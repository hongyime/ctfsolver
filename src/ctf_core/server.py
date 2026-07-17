"""MCP Server entry point for CTF Toolkit."""

# ruff: noqa: E402

import asyncio
import json
import logging
import re
import sys
from pathlib import Path
from typing import Any, Optional
import os


def _bootstrap_env() -> None:
    """Load .env into os.environ (without overriding) before config is read (P6-2)."""
    env_path = Path(__file__).parent.parent.parent / ".env"
    try:
        if env_path.exists():
            for line in env_path.read_text(encoding="utf-8").splitlines():
                line = line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                key, _, val = line.partition("=")
                key = key.strip()
                val = val.strip().strip('"').strip("'")
                if key:
                    os.environ.setdefault(key, val)
    except Exception:
        pass


_bootstrap_env()

from mcp.server.fastmcp import FastMCP

from .db import get_database, close_database, CTFDatabase, init_database, migrate_database, DEFAULT_DB_PATH
from .docker_runner import DockerRunner, WORKSPACE_PATH
from .parsers.nmap_parser import parse_nmap_xml, format_for_database, generate_summary
from .parsers.ferox_parser import parse_feroxbuster_jsonl, generate_summary as ferox_generate_summary
from .parsers.sploit_parser import parse_searchsploit_json, generate_summary as sploit_generate_summary
from .utils.shodan_client import ShodanClient
from .utils.flag_detector import FlagPatternDetector
from .agents.mode_controller import ModeController

# Configure structured JSON logging
class JSONFormatter(logging.Formatter):
    """Custom JSON formatter for structured logging."""
    
    def format(self, record):
        log_data = {
            "timestamp": self.formatTime(record),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }
        
        # Add extra fields if present
        if hasattr(record, 'tool'):
            log_data["tool"] = record.tool
        if hasattr(record, 'target'):
            log_data["target"] = record.target
        if hasattr(record, 'duration'):
            log_data["duration"] = record.duration
        
        # Add exception info if present
        if record.exc_info:
            log_data["exception"] = self.formatException(record.exc_info)
        
        return json.dumps(log_data)


# Setup logging with JSON formatter
log_handler = logging.StreamHandler(sys.stderr)
log_handler.setFormatter(JSONFormatter())

logging.getLogger().addHandler(log_handler)
logging.getLogger().setLevel(logging.INFO)

logger = logging.getLogger(__name__)

# Initialize FastMCP server
mcp = FastMCP("ctfsolver")

# Global instances
db: Optional[CTFDatabase] = None
docker_runner: Optional[DockerRunner] = None
mode_controller: ModeController = ModeController()
_flag_detector: FlagPatternDetector = FlagPatternDetector()  # P4-009: shared singleton (no per-call regex recompile)


def _workspace_root() -> Path:
    from .docker_runner import WORKSPACE_PATH as _WORKSPACE_PATH

    return Path(_WORKSPACE_PATH)


def _scope_block_message(target: str) -> str:
    return (
        f"Target out of scope: {target}\n"
        "Use set_target_scope with the authorized host, URL, IP, or CIDR before "
        "running network-capable tools."
    )


def _is_target_in_scope(target: str) -> bool:
    from .scope import is_target_allowed

    return is_target_allowed(target, workspace=_workspace_root())


def _extract_network_target(tool: str, args: list[str]) -> str:
    """Best-effort target extraction for generic network scan jobs."""
    name = tool.lower()
    if name in {"feroxbuster", "ffuf", "sqlmap", "nuclei", "nikto", "whatweb"}:
        for flag in ("-u", "--url", "-target", "-target-url"):
            if flag in args:
                idx = args.index(flag)
                if idx + 1 < len(args):
                    return args[idx + 1]
    if name in {"gobuster", "wfuzz"} and "-u" in args:
        idx = args.index("-u")
        if idx + 1 < len(args):
            return args[idx + 1]
    if name in {"nmap", "masscan", "httpx", "hydra"} and args:
        for item in reversed(args):
            if item and not item.startswith("-"):
                return item
    return ""


def _split_user_list(value: str) -> list[str]:
    return [item.strip() for item in re.split(r"[\n,]+", value or "") if item.strip()]


def _json_response(payload: Any) -> str:
    return json.dumps(payload, indent=2, sort_keys=True, default=str)


def _resolve_workspace_file(path: str) -> Path:
    """Resolve a user-supplied artifact path with workspace-relative safety."""
    from .execution import resolve_workspace_path

    return resolve_workspace_path(path, _workspace_root(), allow_absolute_host_paths=True)


def _workspace_container_path(path: str) -> str:
    """Return a normalized /workspace container path for a workspace file."""
    from .execution import resolve_workspace_path

    root = _workspace_root().resolve()
    resolved = resolve_workspace_path(path, root)
    relative = resolved.relative_to(root).as_posix()
    return f"/workspace/{relative}" if relative != "." else "/workspace"


def _derived_workspace_dir(path: str, prefix: str) -> str:
    stem = re.sub(r"[^A-Za-z0-9_.-]+", "_", Path(path).stem).strip("._-") or "artifact"
    return f"derived/{prefix}_{stem}"


def validate_environment() -> tuple[bool, list[str]]:
    """
    Validate the CTF Toolkit environment at startup.
    
    Checks:
    - Docker connectivity
    - DB file/writability
    - Workspace existence and writability
    - Docker image availability
    
    Returns:
        tuple: (success: bool, issues: list[str])
    """
    issues = []
    
    # 1. Check Docker connectivity
    try:
        import docker
        client = docker.from_env()
        client.ping()
        logger.info("Docker connectivity: OK")
    except Exception as e:
        issues.append(f"Docker connectivity failed: {e}")
        logger.error(f"Docker connectivity: FAILED - {e}")
    
    # 2. Check DB file and writability
    db_path = DEFAULT_DB_PATH
    if db_path.exists():
        if not db_path.is_file():
            issues.append(f"DB path exists but is not a file: {db_path}")
        elif not db_path.stat().st_mode & 0o200:  # Check write permission
            issues.append(f"DB file is not writable: {db_path}")
        else:
            logger.info("Database file: OK")
    else:
        # DB doesn't exist yet - that's okay, it will be created
        logger.info("Database file: Will be created on first use")
    
    # 3. Check workspace existence and writability
    workspace_path = Path(__file__).parent.parent.parent / "workspace"
    if workspace_path.exists():
        if not workspace_path.is_dir():
            issues.append(f"Workspace path exists but is not a directory: {workspace_path}")
        elif not any(workspace_path.iterdir()):  # Directory is empty or just .gitkeep
            logger.info(f"Workspace directory: OK (empty or just initialized): {workspace_path}")
        else:
            logger.info(f"Workspace directory: OK: {workspace_path}")
    else:
        # Try to create the workspace
        try:
            workspace_path.mkdir(parents=True, exist_ok=True)
            logger.info(f"Workspace directory created: {workspace_path}")
        except Exception as e:
            issues.append(f"Failed to create workspace directory: {e}")
    
    # 4. Check Docker image availability (non-blocking check)
    try:
        if issues:  # Only check images if Docker is connected
            pass
        else:
            runner = DockerRunner()
            images_ok, missing = runner.verify_images()
            if not images_ok:
                # Log warning but don't fail - images can be pulled on demand
                logger.warning(f"Missing Docker images: {missing}")
                issues.append(f"Missing Docker images: {', '.join(missing)}")
            else:
                logger.info("Docker images: OK")
    except Exception as e:
        logger.warning(f"Could not verify Docker images: {e}")
        # Don't fail on image check - they can be pulled on demand
    
    if issues:
        logger.error(f"Environment validation found {len(issues)} issues")
        return False, issues
    else:
        logger.info("Environment validation: PASSED")
        return True, []


@mcp.tool(structured_output=False)
async def run_nmap(target: str, flags: str = "-sV -sC", format: str = "text") -> str:
    """
    Run Nmap network scanner against a target.
    
    Args:
        target: Target IP address or hostname
        flags: Nmap flags (default: -sV -sC for version detection and scripts)
        
    Returns:
        Formatted scan results summary
    """
    global db, docker_runner

    if not _is_target_in_scope(target):
        return _scope_block_message(target)
    
    if docker_runner is None:
        docker_runner = DockerRunner()
    
    args = flags.split() + [target]
    
    try:
        result = await docker_runner.run_tool("nmap", args)
        
        if result.get("error"):
            return f"Error running nmap: {result['stderr']}"
        
        parsed = parse_nmap_xml(result["stdout"])
        summary = generate_summary(parsed)
        
        if db is None:
            db = await get_database()
        
        async with db.transaction():
            for action in format_for_database(parsed):
                if action["type"] == "target":
                    target_id = await db.insert_target(**action["data"])
                    await db.log_action(
                        tool_used="nmap",
                        command_string=f"nmap {' '.join(args)}",
                        reason="Initial reconnaissance",
                        target_id=target_id,
                    )
                elif action["type"] == "service":
                    target_info = await db.get_target_by_ip(action["ip_address"])
                    if target_info:
                        await db.insert_service(
                            target_id=target_info["id"],
                            **action["data"],
                        )
        
        # Flag detection (P1-005)
        combined_output = result.get("stdout", "") + result.get("stderr", "")
        flag_matches = _flag_detector.detect(combined_output)
        if flag_matches and db is not None:
            for match in flag_matches:
                try:
                    await db.insert_flag(flag=match.flag, source="nmap", pattern=match.pattern)
                except Exception as e:
                    logger.warning(f"Failed to store nmap flag: {e}")
            summary += "\n\nFlags detected:\n" + "\n".join(f"  {m.flag}" for m in flag_matches)
        
        # Mode controller (P2-012)
        blocked_state = mode_controller.detect_blocked_state(summary)
        if blocked_state:
            summary += f"\n\n[User Input Required]\n{blocked_state.suggested_action}"
        
        return json.dumps(parsed) if format == "json" else summary
    except Exception as e:
        logger.error(f"Error in run_nmap: {e}")
        return f"Error: {str(e)}"


@mcp.tool(structured_output=False)
async def run_searchsploit(query: str, format: str = "text") -> str:
    """
    Search for exploits using SearchSploit.
    
    Args:
        query: Search query (e.g., service name, CVE, version)
        
    Returns:
        Formatted exploit search results
    """
    global db, docker_runner

    if docker_runner is None:
        docker_runner = DockerRunner()
    
    args = [query, "--json"]
    
    try:
        result = await docker_runner.run_tool("searchsploit", args)
        
        if result.get("error"):
            return f"Error running searchsploit: {result['stderr']}"
        
        parsed = parse_searchsploit_json(result["stdout"])
        summary = sploit_generate_summary(parsed)
        
        # Flag detection (P1-005)
        combined_output = result.get("stdout", "") + result.get("stderr", "")
        flag_matches = _flag_detector.detect(combined_output)
        if flag_matches and db is not None:
            for match in flag_matches:
                try:
                    await db.insert_flag(flag=match.flag, source="searchsploit", pattern=match.pattern)
                except Exception as e:
                    logger.warning(f"Failed to store searchsploit flag: {e}")
            summary += "\n\nFlags detected:\n" + "\n".join(f"  {m.flag}" for m in flag_matches)
        
        # Mode controller (P2-012)
        blocked_state = mode_controller.detect_blocked_state(summary)
        if blocked_state:
            summary += f"\n\n[User Input Required]\n{blocked_state.suggested_action}"
        
        return json.dumps(parsed) if format == "json" else summary
        
    except Exception as e:
        logger.error(f"Error in run_searchsploit: {e}")
        return f"Error: {str(e)}"


@mcp.tool(structured_output=False)
async def run_feroxbuster(url: str, wordlist: str = "/usr/share/wordlists/dirb/common.txt", format: str = "text") -> str:
    """
    Run Feroxbuster web directory brute-forcer.
    
    Args:
        url: Target URL
        wordlist: Path to wordlist file
        
    Returns:
        Formatted directory discovery results
    """
    global db, docker_runner
    
    if docker_runner is None:
        docker_runner = DockerRunner()
    
    # Unique output filename per run avoids the concurrent-overwrite race when two
    # feroxbuster scans run at once (both previously wrote /workspace/ferox_results.json).
    import uuid as _uuid
    _ferox_name = f"ferox_{_uuid.uuid4().hex[:12]}.json"
    args = ["-u", url, "-w", wordlist, "--json", "-o", f"/workspace/{_ferox_name}"]
    
    try:
        result = await docker_runner.run_tool("feroxbuster", args, timeout=600)
        
        if result.get("error"):
            return f"Error running feroxbuster: {result['stderr']}"
        
        results_file = WORKSPACE_PATH / _ferox_name
        if not results_file.exists():
            return "Error: feroxbuster output file not found. The scan may have failed or produced no output."

        try:
            with open(results_file) as f:
                content = f.read().strip()
            if content:
                parsed = parse_feroxbuster_jsonl(content)
                summary = ferox_generate_summary(parsed)
            else:
                parsed = {"directories": []}
                summary = f"Feroxbuster completed. Output: {result['stdout'][:500]}"
        finally:
            # Clean up this run's unique output file (best-effort).
            try:
                results_file.unlink()
            except OSError:
                pass
        
        # Flag detection (P1-005)
        combined_output = result.get("stdout", "") + result.get("stderr", "")
        flag_matches = _flag_detector.detect(combined_output)
        if flag_matches and db is not None:
            for match in flag_matches:
                try:
                    await db.insert_flag(flag=match.flag, source="feroxbuster", pattern=match.pattern)
                except Exception as e:
                    logger.warning(f"Failed to store feroxbuster flag: {e}")
            summary += "\n\nFlags detected:\n" + "\n".join(f"  {m.flag}" for m in flag_matches)
        
        # Mode controller (P2-012)
        blocked_state = mode_controller.detect_blocked_state(summary)
        if blocked_state:
            summary += f"\n\n[User Input Required]\n{blocked_state.suggested_action}"
        
        return json.dumps(parsed) if format == "json" else summary
        
    except Exception as e:
        logger.error(f"Error in run_feroxbuster: {e}")
        return f"Error: {str(e)}"


@mcp.tool(structured_output=False)
async def run_sqlmap(url: str, options: str = "--batch --dbs", format: str = "text") -> str:
    """
    Run SQLMap for SQL injection testing.
    
    Args:
        url: Target URL with parameter
        options: SQLMap options (default: --batch --dbs)
        
    Returns:
        Formatted SQL injection results
    """
    global docker_runner

    if not _is_target_in_scope(url):
        return _scope_block_message(url)
    
    if docker_runner is None:
        docker_runner = DockerRunner()
    
    args = ["-u", url] + options.split()
    
    try:
        result = await docker_runner.run_tool("sqlmap", args, timeout=600)
        
        if result.get("error"):
            return f"Error running sqlmap: {result['stderr']}"
        
        output = result["stdout"][:2000]
        from .parsers.sqlmap_parser import parse_sqlmap_output
        parsed = parse_sqlmap_output(result["stdout"])
        
        # Flag detection (P1-005)
        combined_output = result.get("stdout", "") + result.get("stderr", "")
        flag_matches = _flag_detector.detect(combined_output)
        if flag_matches and db is not None:
            for match in flag_matches:
                try:
                    await db.insert_flag(flag=match.flag, source="sqlmap", pattern=match.pattern)
                except Exception as e:
                    logger.warning(f"Failed to store sqlmap flag: {e}")
            output += "\n\nFlags detected:\n" + "\n".join(f"  {m.flag}" for m in flag_matches)
        
        # Mode controller (P2-012)
        blocked_state = mode_controller.detect_blocked_state(output)
        if blocked_state:
            output += f"\n\n[User Input Required]\n{blocked_state.suggested_action}"
        
        return json.dumps(parsed) if format == "json" else output
        
    except Exception as e:
        logger.error(f"Error in run_sqlmap: {e}")
        return f"Error: {str(e)}"


@mcp.tool(structured_output=False)
async def query_targets(limit: int = 10) -> str:
    """
    Query stored targets from the database.
    
    Args:
        limit: Maximum number of results to return
        
    Returns:
        Formatted list of targets
    """
    global db
    
    if db is None:
        db = await get_database()
    
    targets = await db.get_targets(limit=limit)
    
    if not targets:
        return "No targets found in database."
    
    lines = ["Stored Targets:", ""]
    for t in targets:
        lines.append(f"- {t['ip_address']} ({t.get('hostname', 'N/A')}) - {t.get('os_type', 'Unknown')}")
    
    return "\n".join(lines)


@mcp.tool(structured_output=False)
async def query_services(target_ip: Optional[str] = None, limit: int = 50) -> str:
    """
    Query services from the database.
    
    Args:
        target_ip: Optional target IP to filter by
        limit: Maximum number of results
        
    Returns:
        Formatted list of services
    """
    global db
    
    if db is None:
        db = await get_database()
    
    target_id = None
    if target_ip:
        target = await db.get_target_by_ip(target_ip)
        if target:
            target_id = target["id"]
    
    services = await db.get_services(target_id=target_id, limit=limit)
    
    if not services:
        return "No services found."
    
    lines = ["Discovered Services:", ""]
    for s in services:
        banner = s.get("banner", "")
        service_str = f"- {s['ip_address']}:{s['port']}/{s['protocol']} - {s.get('service_name', 'unknown')}"
        if banner:
            service_str += f" ({banner})"
        lines.append(service_str)
    
    return "\n".join(lines)


@mcp.tool(structured_output=False)
async def get_recent_actions(limit: int = 20) -> str:
    """
    Get recent actions from the audit log.
    
    Args:
        limit: Maximum number of actions to return
        
    Returns:
        Formatted list of recent actions
    """
    global db
    
    if db is None:
        db = await get_database()
    
    actions = await db.get_recent_actions(limit=limit)
    
    if not actions:
        return "No actions in audit log."
    
    lines = ["Recent Actions:", ""]
    for a in actions:
        timestamp = a.get("timestamp", "")[:19]
        lines.append(f"[{timestamp}] {a['tool_used']}: {a['command_string'][:80]}")
        if a.get("reason"):
            lines.append(f"    Reason: {a['reason']}")
    
    return "\n".join(lines)


@mcp.tool(structured_output=False)
async def analyze_challenge(user_input: str) -> str:
    """
    Analyze a CTF challenge description and identify category.
    
    Args:
        user_input: User's description of the challenge
        
    Returns:
        Analysis results with category and extracted information
    """
    from .agents.auto_prompter import AutoPrompter
    
    prompter = AutoPrompter()
    analysis = prompter.analyze_input(user_input)
    
    lines = ["Challenge Analysis:", ""]
    lines.append(f"Category: {analysis['category']}")
    lines.append(f"Confidence: {analysis['confidence']:.0%}")
    
    if analysis.get("challenge_name"):
        lines.append(f"Challenge Name: {analysis['challenge_name']}")
    if analysis.get("target_ip"):
        lines.append(f"Target IP: {analysis['target_ip']}")
    if analysis.get("target_url"):
        lines.append(f"Target URL: {analysis['target_url']}")
    if analysis.get("suspected_vuln"):
        lines.append(f"Suspected Vulnerability: {analysis['suspected_vuln']}")
    if analysis.get("file_paths"):
        lines.append(f"File Paths: {', '.join(analysis['file_paths'])}")
    
    # Generate clarifying questions
    questions = prompter.generate_questions(analysis)
    if questions:
        lines.append("")
        lines.append("Clarifying Questions:")
        for q in questions:
            lines.append(f"- {q}")
    
    return "\n".join(lines)


@mcp.tool(structured_output=False)
async def health_check() -> str:
    """
    Check the health status of the CTF Toolkit system.
    
    Returns:
        System health status with component states
    """
    global db, docker_runner
    
    status = {
        "status": "healthy",
        "components": {},
        "timestamp": None,
    }
    
    from datetime import datetime
    status["timestamp"] = datetime.now().isoformat()
    
    # Check database
    try:
        if db is None:
            db = await get_database()
        status["components"]["database"] = {
            "status": "healthy",
            "message": "Database connection active",
        }
    except Exception as e:
        status["components"]["database"] = {
            "status": "unhealthy",
            "message": str(e),
        }
        status["status"] = "degraded"
    
    # Check Docker runner
    try:
        if docker_runner is None:
            docker_runner = DockerRunner()
        status["components"]["docker"] = {
            "status": "healthy",
            "message": "Docker runner initialized",
        }
    except Exception as e:
        status["components"]["docker"] = {
            "status": "unhealthy",
            "message": str(e),
        }
        status["status"] = "degraded"
    
    # Check workspace
    try:
        from .docker_runner import WORKSPACE_PATH
        if WORKSPACE_PATH.exists():
            status["components"]["workspace"] = {
                "status": "healthy",
                "path": str(WORKSPACE_PATH),
            }
        else:
            status["components"]["workspace"] = {
                "status": "warning",
                "message": "Workspace directory missing, will create on first use",
            }
    except Exception as e:
        status["components"]["workspace"] = {
            "status": "warning",
            "message": str(e),
        }
    
    # Format response
    lines = ["CTF Toolkit Health Check:", ""]
    lines.append(f"Overall Status: {status['status'].upper()}")
    lines.append(f"Timestamp: {status['timestamp']}")
    lines.append("")
    lines.append("Components:")
    
    for component, info in status["components"].items():
        comp_status = info.get("status", "unknown").upper()
        lines.append(f"  [{comp_status}] {component}: {info.get('message', info.get('path', 'N/A'))}")
    
    return "\n".join(lines)


@mcp.tool(structured_output=False)
async def check_environment() -> str:
    """
    Validate the CTF Toolkit environment at startup.
    
    Checks:
    - Docker connectivity
    - DB file/writability
    - Workspace existence and writability
    - Docker image availability
    
    Returns:
        Environment validation status with any issues found
    """
    success, issues = validate_environment()
    
    if success:
        return "Environment validation: PASSED\n\nAll systems are properly configured and ready to use."
    else:
        lines = ["Environment validation: FAILED", "", "Issues found:"]
        for i, issue in enumerate(issues, 1):
            lines.append(f"  {i}. {issue}")
        lines.append("")
        lines.append("Please fix these issues before running CTF challenges.")
        return "\n".join(lines)


@mcp.tool(structured_output=False)
async def run_backend_smoke(format: str = "text") -> str:
    """Run lightweight non-Docker backend smoke checks for MCP mode."""
    from .smoke import run_smoke

    report = await run_smoke()
    if format.lower() == "json":
        return json.dumps(report.to_dict(), indent=2, sort_keys=True)
    return report.to_text()


@mcp.tool(structured_output=False)
async def set_target_scope(targets: str, notes: str = "") -> str:
    """Set authorized network targets for non-CTFd backend tools.

    Pass targets as comma-separated or newline-separated hosts, URLs, IPs, or CIDRs.
    Network-capable tools refuse targets not covered by this scope.
    """
    from .scope import save_allowed_targets

    raw_targets = [
        item.strip()
        for item in re.split(r"[\n,]+", targets or "")
        if item.strip()
    ]
    if not raw_targets:
        return "Error: provide at least one authorized target."
    state = save_allowed_targets(
        _workspace_root(),
        raw_targets,
        metadata={"notes": notes} if notes else {},
    )
    return json.dumps(state, indent=2, sort_keys=True)


@mcp.tool(structured_output=False)
async def get_target_scope() -> str:
    """Return the current authorized network target scope."""
    from .scope import load_scope

    return json.dumps(load_scope(_workspace_root()), indent=2, sort_keys=True)


@mcp.tool(structured_output=False)
async def check_target_scope(target: str) -> str:
    """Check whether a target is covered by the current network scope."""
    from .scope import normalize_target

    allowed = _is_target_in_scope(target)
    return json.dumps(
        {
            "target": target,
            "normalized_target": normalize_target(target),
            "allowed": allowed,
            "message": "target is in scope" if allowed else _scope_block_message(target),
        },
        indent=2,
        sort_keys=True,
    )


@mcp.tool(structured_output=False)
async def suggest_next_tools(
    description: str = "",
    category: str = "",
    target: str = "",
    files: str = "",
    findings: str = "",
    limit: int = 10,
) -> str:
    """Recommend ranked next MCP tools for a CTF challenge state."""
    from .workflows import suggest_next_tools as _suggest

    recommendations = _suggest(
        description=description,
        category=category,
        target=target,
        files=_split_user_list(files),
        findings=_split_user_list(findings),
        limit=limit,
    )
    return json.dumps(recommendations, indent=2, sort_keys=True)


@mcp.tool(structured_output=False)
async def triage_artifact(path: str, challenge_id: str = "") -> str:
    """Safely hash and summarize an artifact, then recommend next tools."""
    from .artifact_triage import triage_artifact as _triage
    from .evidence import append_evidence_event

    try:
        resolved = _resolve_workspace_file(path)
        result = _triage(resolved)
    except Exception as exc:
        return f"Error: {exc}"

    append_evidence_event(
        _workspace_root(),
        "artifact_triaged",
        challenge_id=challenge_id or None,
        files=[resolved],
        file_hashes=[
            {
                "path": result["path"],
                "sha256": result["sha256"],
                "size": result["size"],
            }
        ],
        artifacts=[result["path"]],
        metadata={
            "category_hint": result.get("category_hint"),
            "type_hints": result.get("type_hints", []),
            "recommended_tools": [
                item.get("tool") for item in result.get("recommended_next_tools", [])
            ],
        },
    )
    return json.dumps(result, indent=2, sort_keys=True)


@mcp.tool(structured_output=False)
async def list_cases() -> str:
    """List persistent non-CTFd/CTFd case workspaces."""
    from .cases import list_cases as _list_cases

    return json.dumps(_list_cases(_workspace_root()), indent=2, sort_keys=True)


@mcp.tool(structured_output=False)
async def set_active_case(selector: str) -> str:
    """Set the active case by id, slug, name, category, or substring."""
    from .cases import set_active_case as _set_active_case

    try:
        return json.dumps(_set_active_case(selector, _workspace_root()), indent=2, sort_keys=True)
    except Exception as exc:
        return f"Error: {exc}"


@mcp.tool(structured_output=False)
async def get_active_case() -> str:
    """Return the currently active case, if one is set."""
    from .cases import get_active_case as _get_active_case

    try:
        return json.dumps(_get_active_case(_workspace_root()), indent=2, sort_keys=True)
    except Exception as exc:
        return f"Error: {exc}"


@mcp.tool(structured_output=False)
async def attach_case_artifact(selector: str, src_path: str, dest_name: str = "") -> str:
    """Attach a host artifact to a case's artifacts directory with path safety."""
    from .cases import attach_artifact as _attach_artifact

    try:
        result = _attach_artifact(
            selector,
            src_path,
            workspace=_workspace_root(),
            dest_name=dest_name or None,
        )
        return json.dumps(result, indent=2, sort_keys=True)
    except Exception as exc:
        return f"Error: {exc}"


@mcp.tool(structured_output=False)
async def add_case_note(selector: str, note: str) -> str:
    """Append a note to a case WRITEUP.md."""
    from .cases import add_case_note as _add_case_note

    try:
        return json.dumps(_add_case_note(selector, note, _workspace_root()), indent=2, sort_keys=True)
    except Exception as exc:
        return f"Error: {exc}"


@mcp.tool(structured_output=False)
async def mark_case_solved(selector: str, flag: str = "") -> str:
    """Mark a case solved and optionally record its final flag."""
    from .cases import mark_case_solved as _mark_case_solved

    try:
        result = _mark_case_solved(selector, flag or None, _workspace_root())
        return json.dumps(result, indent=2, sort_keys=True)
    except Exception as exc:
        return f"Error: {exc}"


@mcp.tool(structured_output=False)
async def export_case(selector: str, output_dir: str = "") -> str:
    """Export a case into a deterministic folder with writeup and manifest."""
    from .cases import export_case as _export_case

    try:
        result = _export_case(selector, output_dir or (_workspace_root() / "exports"), _workspace_root())
        return json.dumps(result, indent=2, sort_keys=True)
    except Exception as exc:
        return f"Error: {exc}"


@mcp.tool(structured_output=False)
async def summarize_case_memory(selector: str, limit: int = 50) -> str:
    """Summarize reusable agent memory for a case."""
    from .writeups import summarize_agent_memory as _summarize_agent_memory

    try:
        result = _summarize_agent_memory(selector, _workspace_root(), limit=limit)
        return json.dumps(result, indent=2, sort_keys=True)
    except Exception as exc:
        return f"Error: {exc}"


@mcp.tool(structured_output=False)
async def generate_case_writeup(selector: str, output_path: str = "", final_flag: str = "") -> str:
    """Generate or write a deterministic final case writeup."""
    from .writeups import generate_final_writeup as _generate_final_writeup
    from .writeups import write_final_writeup as _write_final_writeup

    try:
        if output_path:
            result = _write_final_writeup(
                selector,
                _workspace_root(),
                output_path=output_path,
                final_flag=final_flag or None,
            )
            return json.dumps(result, indent=2, sort_keys=True)
        return _generate_final_writeup(selector, _workspace_root(), final_flag=final_flag or None)
    except Exception as exc:
        return f"Error: {exc}"


@mcp.tool(structured_output=False)
async def get_docker_image_status(inspect_local: bool = True) -> str:
    """Return Docker image matrix with build/missing/stale state and expected binaries."""
    from .docker_status import build_status_matrix

    matrix = build_status_matrix(inspect_local=inspect_local)
    return json.dumps(matrix.to_dict(), indent=2, sort_keys=True)


@mcp.tool(structured_output=False)
async def plan_binary_probes(image: str = "", run: bool = False) -> str:
    """Plan or explicitly run expected-binary probes for Docker images."""
    from .docker_status import run_binary_probes

    probes = run_binary_probes(image=image or None, run=run)
    return json.dumps([probe.to_dict() for probe in probes], indent=2, sort_keys=True)


@mcp.tool(structured_output=False)
async def get_tool_execution_policy() -> str:
    """Return timeout, truncation, cancellation, and artifact preservation policy."""
    from .tool_policy import load_policy

    return json.dumps(load_policy().to_dict(), indent=2, sort_keys=True)


@mcp.tool(structured_output=False)
async def list_workflow_chains() -> str:
    """List declarative workflow chains for common CTF paths."""
    from .workflow_chains import list_workflow_chains as _list_workflow_chains

    return json.dumps(_list_workflow_chains(), indent=2, sort_keys=True)


@mcp.tool(structured_output=False)
async def get_workflow_chain(chain_id: str) -> str:
    """Return one declarative workflow chain by id."""
    from .workflow_chains import get_workflow_chain as _get_workflow_chain

    try:
        return json.dumps(_get_workflow_chain(chain_id), indent=2, sort_keys=True)
    except Exception as exc:
        return f"Error: {exc}"


@mcp.tool(structured_output=False)
async def select_workflow_chains(
    description: str = "",
    category: str = "",
    target: str = "",
    files: str = "",
    limit: int = 5,
) -> str:
    """Select ranked declarative workflow chains for a challenge state."""
    from .workflow_chains import select_workflow_chains as _select_workflow_chains

    result = _select_workflow_chains(
        description=description,
        category=category,
        target=target,
        files=_split_user_list(files),
        limit=limit,
    )
    return json.dumps(result, indent=2, sort_keys=True)


@mcp.tool(structured_output=False)
async def list_tool_packs() -> str:
    """List optional, disabled-by-default tool packs."""
    from .tool_packs import list_tool_packs as _list_tool_packs

    return json.dumps(_list_tool_packs(), indent=2, sort_keys=True)


@mcp.tool(structured_output=False)
async def get_tool_pack(pack_id: str) -> str:
    """Return one optional tool pack by id."""
    from .tool_packs import get_tool_pack as _get_tool_pack

    try:
        return json.dumps(_get_tool_pack(pack_id), indent=2, sort_keys=True)
    except Exception as exc:
        return f"Error: {exc}"


@mcp.tool(structured_output=False)
async def build_images() -> str:
    """
    Build (or rebuild) every Docker image required by the CTF Toolkit.

    Useful as a one-time pre-warm so the first real tool invocation does not
    pay the build cost. Each image is built from its Dockerfile under
    ``docker/<short-name>/Dockerfile``. Existing images are skipped unless
    they are missing.

    Returns:
        A per-image status report.
    """
    global docker_runner
    if docker_runner is None:
        docker_runner = DockerRunner()

    results = await docker_runner.ensure_all_images()
    lines = ["Docker image build report:", ""]
    ok = sum(1 for v in results.values() if v)
    for image, built in results.items():
        mark = "OK   " if built else "FAIL "
        lines.append(f"  [{mark}] {image}")
    lines.append("")
    lines.append(f"{ok}/{len(results)} images available.")
    if ok != len(results):
        lines.append(
            "Some builds failed. Check server logs for details, or run:\n"
            "  python scripts/build_images.py <short-name>"
        )
    return "\n".join(lines)


# Phase 4: background image builds (heavy images blow the tool timeout - build as a job).
_build_tasks: dict = {}


async def _run_build_job(job_id: str, image: str) -> None:
    global db, docker_runner
    if docker_runner is None:
        docker_runner = DockerRunner()
    try:
        ok = await docker_runner._ensure_image(image)
        if db is None:
            db = await get_database()
        await db.finish_scan_job(job_id, status="completed" if ok else "failed",
                                 exit_code=0 if ok else 1,
                                 output=f"build {'succeeded' if ok else 'failed'}: {image}",
                                 error=None if ok else "build failed")
    except Exception as e:
        try:
            if db is not None:
                await db.finish_scan_job(job_id, status="failed", exit_code=-1, output="", error=str(e))
        except Exception:
            pass
    finally:
        _build_tasks.pop(job_id, None)


@mcp.tool(structured_output=False)
async def build_image(category: str) -> str:
    """Build one image (e.g. 'ctf-re', 'ctf-sage') in the BACKGROUND and return a job_id.

    Heavy images (Ghidra ~5GB, Sage ~2.5GB) take many minutes and would exceed the
    tool-call timeout if built inline. Poll with get_build_status(job_id)."""
    global db, docker_runner
    import uuid
    if docker_runner is None:
        docker_runner = DockerRunner()
    if db is None:
        db = await get_database()
    short = category.strip().split("/")[-1]
    image = short if short.startswith("ctftoolkit/") else f"ctftoolkit/{short}"
    job_id = uuid.uuid4().hex[:12]
    await db.create_scan_job(job_id, f"build:{short}", image, job_type="build", image_name=image)
    _build_tasks[job_id] = asyncio.create_task(_run_build_job(job_id, image))
    return f'Building {image} in background. Poll with get_build_status("{job_id}").'


@mcp.tool(structured_output=False)
async def get_build_status(job_id: str) -> str:
    """Check the status of a background build_image job."""
    global db
    if db is None:
        db = await get_database()
    job = await db.get_scan_job(job_id)
    if job is None:
        return f"No build job {job_id}"
    return (f"Build {job_id} ({job['tool']}): status={job['status']} "
            f"{job.get('error') or job.get('output') or ''}")


@mcp.tool(structured_output=False)
async def prebuild_all_images() -> str:
    """Build all core images now (excludes lazy-only Sage). Same as `docker compose build`."""
    global docker_runner
    if docker_runner is None:
        docker_runner = DockerRunner()
    results = await docker_runner.ensure_all_images()
    ok = sum(1 for v in results.values() if v)
    lines = [f"{ok}/{len(results)} core images available:"]
    for image, built in results.items():
        lines.append(f"  [{'OK' if built else 'FAIL'}] {image}")
    return "\n".join(lines)


@mcp.tool(structured_output=False)
async def prune_images(ttl_days: int = 0, apply: bool = False) -> str:
    """Two-gate idle-TTL prune of ctftoolkit/* images (never removes in-use images).

    Default is a DRY RUN (lists candidates). Set apply=true to actually remove.
    ttl_days=0 uses CTFTOOLKIT_IMAGE_TTL_DAYS (default 7). Never force-removes;
    vetoes any image referenced by a container or a running/durable job."""
    from .prune import prune_images as _prune
    import json as _json
    rep = await _prune(ttl_days=ttl_days or None, dry_run=not apply)
    return _json.dumps(rep, indent=2)


@mcp.tool(structured_output=False)
async def disk_usage() -> str:
    """Report disk used by ctftoolkit images and dangling layers."""
    from .prune import disk_usage as _du
    import json as _json
    return _json.dumps(await _du(), indent=2)


@mcp.tool(structured_output=False)
async def check_workspace_permissions() -> str:
    """Verify the workspace is writable by the container user (uid 1000) and the host."""
    from .docker_runner import WORKSPACE_PATH
    import os as _os
    ws = WORKSPACE_PATH
    info = {"workspace": str(ws), "exists": ws.exists(),
            "host_writable": _os.access(ws, _os.W_OK) if ws.exists() else False}
    # Container-side check: can uid 1000 write a file in the mount?
    global docker_runner
    if docker_runner is None:
        docker_runner = DockerRunner()
    try:
        res = await docker_runner.run_tool(
            "file", ["/workspace"], timeout=30, image="ctftoolkit/ctf-re")
        info["container_mount_ok"] = res.get("error") != "image_not_found"
    except Exception as e:
        info["container_mount_ok"] = f"check failed: {e}"
    import json as _json
    return _json.dumps(info, indent=2)

@mcp.tool(structured_output=False)
async def run_shodan(query: str, limit: int = 10) -> str:
    """
    Query Shodan for information about IP addresses, services, and vulnerabilities.
    
    Requires SHODAN_API_KEY environment variable to be set.
    
    Args:
        query: Search query (can be IP address or search terms)
        limit: Maximum number of results (default: 10, max: 100)
        
    Returns:
        Formatted Shodan results
    """
    client = ShodanClient()
    
    if not client.is_configured():
        return "Error: Shodan API key not configured. Set SHODAN_API_KEY environment variable."
    
    try:
        # Try as IP lookup first
        import re
        ip_pattern = re.compile(r'^(\d{1,3}\.){3}\d{1,3}$')
        
        if ip_pattern.match(query):
            # It's an IP address, do lookup
            result = client.lookup_ip(query)
            
            lines = [f"Shodan results for IP: {query}", ""]
            lines.append(f"ISP: {result.get('ISP', 'Unknown')}")
            lines.append(f"Organization: {result.get('org', 'Unknown')}")
            lines.append(f"Operating System: {result.get('os', 'Unknown')}")
            lines.append(f"Last Update: {result.get('last_update', 'Unknown')}")
            lines.append("")
            lines.append("Open Ports/Services:")
            
            for service in result.get('data', [])[:10]:
                port = service.get('port', '?')
                product = service.get('product', 'Unknown')
                version = service.get('version', '')
                banner = service.get('data', '')[:100]
                lines.append(f"  - Port {port}: {product} {version}")
                if banner:
                    lines.append(f"    Banner: {banner}...")
            
            return "\n".join(lines)
        else:
            # It's a search query
            result = client.search(query, limit=limit)
            
            lines = [f"Shodan search results for: {query}", ""]
            total = result.get('total', 0)
            lines.append(f"Total results: {total}")
            lines.append("")
            
            for match in result.get('matches', [])[:limit]:
                ip = match.get('ip_str', '?')
                port = match.get('port', '?')
                product = match.get('product', 'Unknown')
                org = match.get('org', 'Unknown')
                lines.append(f"  - {ip}:{port} ({product}) - {org}")
            
            return "\n".join(lines)
            
    except Exception as e:
        return f"Error querying Shodan: {str(e)}"


@mcp.tool(structured_output=False)
async def run_spiderfoot(target: str) -> str:
    """
    Run SpiderFoot OSINT scan against a target.

    Args:
        target: Target IP, domain, or username

    Returns:
        Formatted OSINT scan results
    """
    global docker_runner
    if not _is_target_in_scope(target):
        return _scope_block_message(target)
    if docker_runner is None:
        docker_runner = DockerRunner()
    from .utils.osint_tools import SpiderFootClient
    client = SpiderFootClient(workspace_path=WORKSPACE_PATH, docker_runner=docker_runner)
    result = await client.scan_target(target)
    return client.get_summary(result)


@mcp.tool(structured_output=False)
async def run_harvester(domain: str) -> str:
    """
    Run theHarvester email and subdomain enumeration against a domain.

    Args:
        domain: Target domain to enumerate

    Returns:
        Formatted enumeration results
    """
    global docker_runner
    if not _is_target_in_scope(domain):
        return _scope_block_message(domain)
    if docker_runner is None:
        docker_runner = DockerRunner()
    from .utils.osint_tools import TheHarvesterClient
    client = TheHarvesterClient(workspace_path=WORKSPACE_PATH, docker_runner=docker_runner)
    result = await client.enumerate_domain(domain)
    return client.get_summary(result)


@mcp.tool(structured_output=False)
async def run_challenge_analysis(challenge_description: str) -> str:
    """
    Run the full autonomous agent pipeline to analyze a CTF challenge.

    Pipeline: AutoPrompter → Planner → Executor (runs all tasks) → structured response.

    Args:
        challenge_description: Description of the CTF challenge

    Returns:
        Structured analysis with real tool findings across all six sections
    """
    global db, docker_runner

    from .agents.auto_prompter import AutoPrompter
    from .agents.planner import Planner
    from .agents.executor import Executor

    # Step 1: Categorise and extract target metadata
    analysis = AutoPrompter().analyze_input(challenge_description)

    # Phase 3: build a /goal triage->route->solve->verify prompt for the agent.
    from .agents.goal_template import build_goal_prompt, verify_flag
    goal = build_goal_prompt(
        challenge_name=analysis.get("challenge_name") or "challenge",
        category=analysis.get("category") or "misc",
        description=challenge_description,
        target=analysis.get("target_ip") or analysis.get("target_url"),
        files=analysis.get("file_paths"),
    )
    # Phase 5: match a codified solver playbook and inject it as context.
    from .playbooks import match_playbook, render_playbook
    _pb = match_playbook(challenge_description, analysis.get("category"))
    playbook_block = ("\n\n" + render_playbook(_pb)) if _pb else ""

    if db is None:
        db = await get_database()

    # Step 2: Planner selects strategy and produces next_tasks
    planner = Planner(db=db)
    try:
        decision = await planner.analyze_state(analysis, {})
    except Exception as e:
        logger.info(f"Planner.analyze_state raised: {e}")
        return f"Error: challenge analysis failed — {e}"

    # Step 3: Short-circuit if no tasks to run
    next_tasks = decision.get("next_tasks", [])
    if not next_tasks:
        return planner.format_response(decision)

    # Step 4: Executor loop — run every task, collect findings
    if docker_runner is None:
        docker_runner = DockerRunner()

    executor = Executor(docker_runner=docker_runner, db=db)
    findings = []
    from .utils.resilience import _SHUTDOWN

    for task in next_tasks:
        if _SHUTDOWN.is_set():
            findings.append("[INTERRUPTED] Shutdown requested - returning partial results.")
            break
        tool = task.get("tool", "unknown")
        logger.info(f"run_challenge_analysis: executing task '{tool}'")
        try:
            result = await executor.execute_task(task, context=analysis)
            if result.get("success"):
                try:
                    await executor.store_results(result, target_id=None)
                except Exception as store_err:
                    logger.warning(f"store_results failed for '{tool}': {store_err}")
                output = (result.get("output") or "").strip()
                findings.append(output[:500] if output else f"[OK] {tool}: completed")
            else:
                output = (result.get("output") or "no output").strip()
                findings.append(f"[FAILED] {tool}: {output[:200]}")
        except Exception as e:
            logger.info(f"run_challenge_analysis: task '{tool}' raised: {e}")
            findings.append(f"[FAILED] {tool}: {e}")

    # Step 5: verify any captured flags, then return the structured response prefixed
    # with the /goal template (triage->route->solve->verify).
    verified = []
    for m in _flag_detector.detect("\n".join(findings)):
        if verify_flag(m.flag):
            verified.append(m.flag)
    body = planner.format_response(decision, findings=findings)
    if verified:
        body += "\n\nVerified flag(s): " + ", ".join(sorted(set(verified)))
    return goal + playbook_block + "\n\n" + body


@mcp.tool(structured_output=False)
async def record_finding(kind: str, value: str, notes: str = "", target_ip: str = "") -> str:
    """
    Record an agent-discovered finding into the CTF database (F7 write API).

    Args:
        kind: one of "flag", "credential" (value "user:pass"), or "note"
        value: the finding (flag string, "user:pass", or note text)
        notes: optional context for the finding
        target_ip: optional IP to attach the finding to (created if unknown)

    Returns:
        Confirmation string with the stored row id
    """
    global db
    if db is None:
        db = await get_database()

    target_id = None
    if target_ip:
        existing = await db.get_target_by_ip(target_ip)
        target_id = existing["id"] if existing else await db.insert_target(ip_address=target_ip)

    k = kind.strip().lower()
    try:
        if k == "flag":
            fid = await db.insert_flag(flag=value, source="agent", pattern="manual", target_id=target_id)
            return f"Recorded flag (id={fid}): {value}"
        if k in ("credential", "cred", "creds"):
            if target_id is None:
                return "Error: credentials require target_ip (credentials.target_id is NOT NULL)."
            user, sep, pw = value.partition(":")
            cid = await db.insert_credential(target_id=target_id, username=user, cleartext=(pw if sep else None))
            return f"Recorded credential (id={cid}) for target {target_ip}: {user}"
        if k == "note":
            await db.log_action(tool_used="agent_note", command_string=value,
                                reason=(notes or "agent finding"), target_id=target_id)
            return f"Recorded note: {value}"
        return f"Unknown finding kind '{kind}'. Use 'flag', 'credential', or 'note'."
    except Exception as e:
        logger.error(f"record_finding failed: {e}")
        return f"Error recording finding: {e}"


# F3: async scan handles - run tools in background tasks; state lives in scan_jobs.
_scan_tasks: dict = {}


async def _run_scan_job(job_id: str, tool: str, args: list, timeout: int) -> None:
    """Background worker: run the tool, then persist result to scan_jobs (F3)."""
    global db, docker_runner
    if docker_runner is None:
        docker_runner = DockerRunner()
    try:
        result = await docker_runner.run_tool(tool, args, timeout=timeout)
        output = (result.get("stdout", "") + result.get("stderr", ""))
        status = "failed" if result.get("error") else "completed"
        if db is None:
            db = await get_database()
        await db.finish_scan_job(job_id, status=status, exit_code=result.get("exit_code"),
                                 output=output[:20000], error=result.get("error"))
    except Exception as e:
        logger.error(f"scan job {job_id} crashed: {e}")
        try:
            if db is not None:
                await db.finish_scan_job(job_id, status="failed", exit_code=-1, output="", error=str(e))
        except Exception:
            pass
    finally:
        _scan_tasks.pop(job_id, None)


@mcp.tool(structured_output=False)
async def start_scan(tool: str, args: str = "", timeout: int = 600, durable: bool = False) -> str:
    """
    Start a tool scan in the background and return a job_id immediately (F3).

    Survives the caller's session: poll with poll_scan(job_id) and fetch the
    final output with get_scan_result(job_id). Use for long scans that would
    otherwise exceed a single request's time budget.

    Args:
        tool: tool name (e.g. nmap, feroxbuster, sqlmap)
        args: space-separated arguments
        timeout: per-tool timeout in seconds
        durable: if True, run in a DETACHED container that survives an IDE/server
                 close (Phase 2 tiered durability). Re-attached on restart. Subject
                 to CTFTOOLKIT_MAX_DURABLE_JOBS and a 24h hard cap.

    Returns:
        A job_id string.
    """
    global db, docker_runner
    import uuid
    job_id = uuid.uuid4().hex[:12]
    arglist = args.split()
    network_tools = {
        "feroxbuster", "ffuf", "gobuster", "httpx", "hydra", "masscan",
        "nikto", "nmap", "nuclei", "sqlmap", "whatweb", "wfuzz",
    }
    if tool.lower() in network_tools:
        target = _extract_network_target(tool, arglist)
        if not target:
            return (
                f"Error: could not infer target for network tool '{tool}'. "
                "Use a dedicated wrapper or include a clear target argument."
            )
        if not _is_target_in_scope(target):
            return _scope_block_message(target)

    if docker_runner is None:
        docker_runner = DockerRunner()
    if db is None:
        db = await get_database()

    if durable:
        from .docker_runner import TOOL_IMAGES
        from .jobs import start_durable_job
        image = TOOL_IMAGES.get(tool, "")
        await db.create_scan_job(job_id, tool, args, job_type="durable",
                                 durable=True, image_name=image)
        res = await start_durable_job(job_id, tool, arglist, image, timeout)
        if res.get("error"):
            await db.finish_scan_job(job_id, status="failed", exit_code=-1,
                                     output="", error=res["error"])
            return f"Error starting durable job: {res['error']}"
        return (f'Started DURABLE scan job {job_id} ({tool}) in container '
                f'{res["container_id"][:12]}. Poll with poll_scan("{job_id}").')

    await db.create_scan_job(job_id, tool, args)
    _scan_tasks[job_id] = asyncio.create_task(_run_scan_job(job_id, tool, arglist, timeout))
    return f'Started scan job {job_id} ({tool}). Poll with poll_scan("{job_id}").'


@mcp.tool(structured_output=False)
async def poll_scan(job_id: str) -> str:
    """Return the status of a background scan job (F3)."""
    global db
    if db is None:
        db = await get_database()
    job = await db.get_scan_job(job_id)
    if job is None:
        return f"No scan job with id {job_id}"
    return (f"Job {job_id} ({job['tool']}): status={job['status']} "
            f"started={job['started_at']} finished={job.get('finished_at') or '-'}")


@mcp.tool(structured_output=False)
async def get_scan_result(job_id: str) -> str:
    """Return the full output of a completed background scan job (F3)."""
    global db
    if db is None:
        db = await get_database()
    job = await db.get_scan_job(job_id)
    if job is None:
        return f"No scan job with id {job_id}"
    if job["status"] == "running":
        return f"Job {job_id} still running. Poll again shortly."
    header = f"Job {job_id} ({job['tool']}) status={job['status']} exit={job.get('exit_code')}"
    if job.get("error"):
        return f"{header}\nError: {job['error']}\n\n{job.get('output') or ''}"
    return f"{header}\n\n{job.get('output') or ''}"


@mcp.tool(structured_output=False)
async def run_binary_analysis(path: str) -> str:
    """
    Static analysis of a local binary/artifact in the workspace (F1).

    Runs file, readelf -h, nm -C, and strings (in the ctf-re container) on the
    given workspace-relative path and returns the combined output.

    Args:
        path: workspace-relative path to the file (e.g. "challenge.bin")

    Returns:
        Combined static-analysis output
    """
    global db, docker_runner
    if docker_runner is None:
        docker_runner = DockerRunner()
    try:
        target = _workspace_container_path(path)
    except ValueError as exc:
        return f"Error: {exc}"
    steps = [
        ("file", [target]),
        ("readelf", ["-h", target]),
        ("nm", ["-C", target]),
        ("strings", ["-n", "8", target]),
    ]
    sections = [f"# Binary analysis: {path}", ""]
    for tool, args in steps:
        try:
            result = await docker_runner.run_tool(tool, args, timeout=120)
            out = (result.get("stdout", "") or result.get("stderr", "")).strip()
            sections.append(f"=== {tool} {' '.join(a for a in args if a != target)} ===")
            sections.append(out[:3000] if out else "(no output)")
            sections.append("")
        except Exception as e:
            sections.append(f"=== {tool} (error: {e}) ===")
    combined = "\n".join(sections)
    if db is None:
        db = await get_database()
    for m in _flag_detector.detect(combined):
        try:
            await db.insert_flag(flag=m.flag, source="binary_analysis", pattern=m.pattern)
        except Exception as e:
            logger.warning(f"binary_analysis flag insert failed: {e}")
    return combined[:8000]


def _write_workspace_script(content: str, suffix: str) -> tuple[str, str]:
    """Write a script to the workspace; return (host_path, container_path) (F1)."""
    import uuid
    name = f"_f1_{uuid.uuid4().hex[:8]}{suffix}"
    host = WORKSPACE_PATH / name
    host.write_text(content, encoding="utf-8")
    return str(host), f"/workspace/{name}"


async def _run_workspace_script(content: str, suffix: str, runner_tool: str,
                                image: str, extra_args: Optional[list] = None, timeout: int = 120) -> str:
    """Write an agent-supplied script to the (sandboxed) workspace and execute it (F1)."""
    global docker_runner
    if docker_runner is None:
        docker_runner = DockerRunner()
    host, cpath = _write_workspace_script(content, suffix)
    args = (extra_args or []) + [cpath]
    try:
        result = await docker_runner.run_tool(runner_tool, args, timeout=timeout, image=image)
        out = (result.get("stdout", "") + result.get("stderr", "")).strip()
    finally:
        try:
            Path(host).unlink()
        except Exception:
            pass
    return out[:8000] or "(no output)"


@mcp.tool(structured_output=False)
async def run_z3(script: str, timeout: int = 120) -> str:
    """Run a Z3 (python z3 module) solver script in the sandboxed ctf-crypto container (F1)."""
    return await _run_workspace_script(script, ".py", "python3", "ctftoolkit/ctf-crypto", timeout=timeout)


@mcp.tool(structured_output=False)
async def run_pwntools(script: str, timeout: int = 120) -> str:
    """Run a pwntools (python) exploit script in the ctf-pwn container (F1)."""
    return await _run_workspace_script(script, ".py", "python3", "ctftoolkit/ctf-pwn", timeout=timeout)


@mcp.tool(structured_output=False)
async def run_gdb_script(binary_path: str, commands: str, timeout: int = 120) -> str:
    """Run batch GDB commands against a workspace binary in the ctf-pwn container (F1)."""
    try:
        target = _workspace_container_path(binary_path)
    except ValueError as exc:
        return f"Error: {exc}"
    return await _run_gdb(target, commands, timeout)


async def _run_gdb(target: str, commands: str, timeout: int) -> str:
    global docker_runner
    if docker_runner is None:
        docker_runner = DockerRunner()
    host, cpath = _write_workspace_script(commands, ".gdb")
    try:
        result = await docker_runner.run_tool(
            "gdb", ["-batch", "-nx", "-x", cpath, target], timeout=timeout, image="ctftoolkit/ctf-pwn")
        out = (result.get("stdout", "") + result.get("stderr", "")).strip()
    finally:
        try:
            Path(host).unlink()
        except Exception:
            pass
    return out[:8000] or "(no output)"


@mcp.tool(structured_output=False)
async def decode_stego(path: str, passphrase: str = "", timeout: int = 120) -> str:
    """Run stego/forensics tools (exiftool, strings, steghide) on a workspace file (F1)."""
    global docker_runner
    if docker_runner is None:
        docker_runner = DockerRunner()
    try:
        target = _workspace_container_path(path)
    except ValueError as exc:
        return f"Error: {exc}"
    steghide_args = ["info", "-sf", target] + (["-p", passphrase] if passphrase else [])
    steps = [("exiftool", [target]), ("strings", ["-n", "8", target]), ("steghide", steghide_args)]
    sections = [f"# Stego analysis: {path}", ""]
    for tool, args in steps:
        try:
            result = await docker_runner.run_tool(tool, args, timeout=timeout)
            out = (result.get("stdout", "") or result.get("stderr", "")).strip()
            sections.append(f"=== {tool} ===")
            sections.append(out[:2000] if out else "(no output)")
        except Exception as e:
            sections.append(f"=== {tool} (error: {e}) ===")
    return "\n".join(sections)[:8000]


@mcp.tool(structured_output=False)
async def run_sage(script: str, timeout: int = 120) -> str:
    """Run a SageMath script in the sandboxed ctf-sage container (F1).

    The ctf-sage image (docker/ctf-sage/Dockerfile, ~2.5GB) is lazy-built on first
    use and prunable when idle. For pure SMT/constraint problems, run_z3 is lighter.
    """
    return await _run_workspace_script(script, ".sage", "sage", "ctftoolkit/ctf-sage", timeout=timeout)


# ============================================================================
# Phase 1: category-coverage MCP tools
# ============================================================================

async def _run_target_tool(tool: str, path: str, extra: Optional[list] = None,
                           image: Optional[str] = None, timeout: int = 180,
                           pre_args: Optional[list] = None,
                           parser=None, fmt: str = "text") -> str:
    """Run a binary against a workspace-relative file and return combined output.

    If `parser` is given it is called as parser(raw_output) and its result is
    returned, unless fmt=='json' in which case the raw output is returned verbatim.
    """
    global db, docker_runner
    if docker_runner is None:
        docker_runner = DockerRunner()
    try:
        target = _workspace_container_path(path)
    except ValueError as exc:
        return f"Error: {exc}"
    args = (pre_args or []) + [target] + (extra or [])
    try:
        result = await docker_runner.run_tool(tool, args, timeout=timeout, image=image)
    except Exception as e:
        return f"Error running {tool}: {e}"
    if result.get("error") == "image_not_found":
        return f"Error: image for {tool} not built yet. {result.get('stderr','')}"
    out = (result.get("stdout", "") + result.get("stderr", "")).strip()
    # Opportunistic flag capture
    if db is None:
        db = await get_database()
    for m in _flag_detector.detect(out):
        try:
            await db.insert_flag(flag=m.flag, source=tool, pattern=m.pattern)
        except Exception:
            pass
    if parser is not None and fmt != "json":
        try:
            return parser(out)[:8000] or "(no output)"
        except Exception as e:
            logger.warning(f"{tool} parser failed, returning raw: {e}")
    return out[:8000] or "(no output)"


# ---- Reverse engineering ----
@mcp.tool(structured_output=False)
async def run_rizin(path: str, commands: str = "aaa; afl; iI", timeout: int = 180) -> str:
    """Analyze a binary with rizin (batch mode). `commands` is a ';'-separated rizin script."""
    return await _run_target_tool("rizin", path, pre_args=["-A", "-q", "-c", commands],
                                  image="ctftoolkit/ctf-re", timeout=timeout)


@mcp.tool(structured_output=False)
async def run_capa(path: str, timeout: int = 300, format: str = "text") -> str:
    """Identify capabilities (ATT&CK/MBC) in a binary with capa.

    Returns a condensed capability summary (grouped by namespace + ATT&CK IDs).
    Pass format='json' for the raw capa JSON."""
    from .parsers.capa_parser import parse_capa_json, generate_summary
    return await _run_target_tool(
        "capa", path, pre_args=["-j", "-r", "/opt/capa-rules"],
        image="ctftoolkit/ctf-re", timeout=timeout,
        parser=lambda raw: generate_summary(parse_capa_json(raw)), fmt=format)


@mcp.tool(structured_output=False)
async def run_floss(path: str, timeout: int = 300, format: str = "text") -> str:
    """Extract obfuscated/stack/decoded strings with FLOSS.

    Returns strings grouped by type (decoded/stack/tight/static). Pass format='json'
    for the raw FLOSS JSON."""
    from .parsers.floss_parser import parse_floss_json, generate_summary
    return await _run_target_tool(
        "floss", path, pre_args=["-j"], image="ctftoolkit/ctf-re", timeout=timeout,
        parser=lambda raw: generate_summary(parse_floss_json(raw)), fmt=format)


@mcp.tool(structured_output=False)
async def run_wasm2wat(path: str, timeout: int = 120) -> str:
    """Disassemble a WebAssembly .wasm to readable .wat text."""
    return await _run_target_tool("wasm2wat", path, image="ctftoolkit/ctf-re", timeout=timeout)


@mcp.tool(structured_output=False)
async def run_apktool(path: str, output_dir: str = "", timeout: int = 300) -> str:
    """Decode an Android APK into workspace-derived resources and smali."""
    output = output_dir or _derived_workspace_dir(path, "apktool")
    try:
        out_path = _workspace_container_path(output)
    except ValueError as exc:
        return f"Error: {exc}"
    return await _run_target_tool(
        "apktool",
        path,
        pre_args=["d", "-f", "-o", out_path],
        image="ctftoolkit/ctf-mobile",
        timeout=timeout,
    )


@mcp.tool(structured_output=False)
async def run_jadx(path: str, output_dir: str = "", timeout: int = 300) -> str:
    """Decompile an APK/DEX/JAR into Java source using JADX."""
    output = output_dir or _derived_workspace_dir(path, "jadx")
    try:
        out_path = _workspace_container_path(output)
    except ValueError as exc:
        return f"Error: {exc}"
    return await _run_target_tool(
        "jadx",
        path,
        pre_args=["-d", out_path],
        image="ctftoolkit/ctf-mobile",
        timeout=timeout,
    )


@mcp.tool(structured_output=False)
async def run_ilspycmd(path: str, output_dir: str = "", timeout: int = 300) -> str:
    """Decompile a .NET assembly into a workspace-derived C# project."""
    output = output_dir or _derived_workspace_dir(path, "ilspy")
    try:
        out_path = _workspace_container_path(output)
    except ValueError as exc:
        return f"Error: {exc}"
    return await _run_target_tool(
        "ilspycmd",
        path,
        pre_args=["-p", "-o", out_path],
        image="ctftoolkit/ctf-mobile",
        timeout=timeout,
    )


@mcp.tool(structured_output=False)
async def run_pyinstxtractor(path: str, timeout: int = 300) -> str:
    """Extract a PyInstaller executable bundle inside the mobile/managed-code image."""
    return await _run_target_tool(
        "pyinstxtractor",
        path,
        image="ctftoolkit/ctf-mobile",
        timeout=timeout,
    )


# ---- Pwn ----
@mcp.tool(structured_output=False)
async def run_ropgadget(path: str, options: str = "", timeout: int = 180) -> str:
    """Find ROP gadgets in a binary with ROPgadget."""
    extra = options.split() if options else []
    return await _run_target_tool("ROPgadget", path, pre_args=["--binary"], extra=extra,
                                  image="ctftoolkit/ctf-pwn", timeout=timeout)


@mcp.tool(structured_output=False)
async def run_one_gadget(libc_path: str, timeout: int = 120) -> str:
    """Find one-gadget RCE offsets in a libc with one_gadget."""
    return await _run_target_tool("one_gadget", libc_path, image="ctftoolkit/ctf-pwn", timeout=timeout)


@mcp.tool(structured_output=False)
async def run_seccomp_tools(path: str, timeout: int = 120) -> str:
    """Dump the seccomp BPF filter of a binary with seccomp-tools."""
    return await _run_target_tool("seccomp-tools", path, pre_args=["dump"],
                                  image="ctftoolkit/ctf-pwn", timeout=timeout)


@mcp.tool(structured_output=False)
async def run_patchelf(path: str, set_interpreter: str = "", set_rpath: str = "",
                       timeout: int = 60) -> str:
    """Inspect or patch an ELF's interpreter/rpath with patchelf (operates in /workspace)."""
    extra: list[str] = []
    pre: list[str] = []
    if set_interpreter:
        pre = ["--set-interpreter", set_interpreter]
    elif set_rpath:
        pre = ["--set-rpath", set_rpath]
    else:
        pre = ["--print-interpreter"]
    return await _run_target_tool("patchelf", path, pre_args=pre, extra=extra,
                                  image="ctftoolkit/ctf-pwn", timeout=timeout)


@mcp.tool(structured_output=False)
async def run_angr(script: str, timeout: int = 300) -> str:
    """Run an angr symbolic-execution Python script in the ctf-pwn container (F1)."""
    return await _run_workspace_script(script, ".py", "python3", "ctftoolkit/ctf-pwn", timeout=timeout)


@mcp.tool(structured_output=False)
async def run_libc_lookup(symbols: str, timeout: int = 60) -> str:
    """Identify a libc from leaked symbol offsets via the libc.rip API.

    `symbols` is space- or comma-separated `name=hexoffset` pairs
    (e.g. \"puts=0x...,system=0x...\"). Runs inside ctf-pwn (network kept)."""
    import json as _json
    pairs = {}
    for tok in symbols.replace(",", " ").split():
        if "=" in tok:
            k, _, v = tok.partition("=")
            pairs[k.strip()] = v.strip()
    if not pairs:
        return "Provide symbols as name=hexoffset pairs, e.g. puts=0x5f0c0 system=0x453a0"
    payload = _json.dumps({"symbols": pairs})
    script = (
        "import json,urllib.request\n"
        f"req=urllib.request.Request('https://libc.rip/api/find',"
        f"data={payload!r}.encode(),headers={{'Content-Type':'application/json'}})\n"
        "try:\n"
        "    r=urllib.request.urlopen(req,timeout=30); data=json.load(r)\n"
        "    for m in data[:10]:\n"
        "        print(m.get('id'), m.get('buildid',''))\n"
        "    print('TOTAL', len(data))\n"
        "except Exception as e:\n"
        "    print('libc.rip error:', e)\n"
    )
    return await _run_workspace_script(script, ".py", "python3", "ctftoolkit/ctf-pwn", timeout=timeout)


# ---- Crypto ----
@mcp.tool(structured_output=False)
async def run_lll(script: str, timeout: int = 180) -> str:
    """Run a Python lattice-reduction script (fpylll available) in ctf-crypto (F1).

    Use for LLL/BKZ/CVP problems. `import fpylll` is available; flatter is installed
    as a system binary if you shell out. For SMT use run_z3; for algebra use run_sage."""
    return await _run_workspace_script(script, ".py", "python3", "ctftoolkit/ctf-crypto", timeout=timeout)


@mcp.tool(structured_output=False)
async def run_rsactftool(args: str, timeout: int = 300) -> str:
    """Run RsaCtfTool with the given argument string (e.g. '--publickey /workspace/key.pem --uncipher 0x..')."""
    global docker_runner
    if docker_runner is None:
        docker_runner = DockerRunner()
    arglist = args.split()
    try:
        result = await docker_runner.run_tool("RsaCtfTool", arglist, timeout=timeout,
                                              image="ctftoolkit/ctf-crypto")
    except Exception as e:
        return f"Error running RsaCtfTool: {e}"
    out = (result.get("stdout", "") + result.get("stderr", "")).strip()
    return out[:8000] or "(no output)"


# ---- Forensics ----
@mcp.tool(structured_output=False)
async def run_zsteg(path: str, options: str = "-a", timeout: int = 120) -> str:
    """Run zsteg LSB steganalysis on a PNG/BMP (default -a = try all)."""
    extra = options.split() if options else []
    return await _run_target_tool("zsteg", path, pre_args=extra,
                                  image="ctftoolkit/ctf-forensics", timeout=timeout)


@mcp.tool(structured_output=False)
async def run_stegseek(path: str, wordlist: str = "/usr/share/wordlists/rockyou.txt",
                       timeout: int = 300) -> str:
    """Bruteforce a steghide passphrase with stegseek using the given wordlist."""
    return await _run_target_tool("stegseek", path, pre_args=["-sf"], extra=["-wl", wordlist],
                                  image="ctftoolkit/ctf-forensics", timeout=timeout)


@mcp.tool(structured_output=False)
async def extract_usb_hid_pcap(path: str, mode: str = "auto", timeout: int = 180) -> str:
    """Recover keystrokes/mouse movements from a USB-capture pcap (e.g. Grey Yuumi).

    mode: auto | keyboard | mouse. Returns JSON with keystrokes and/or mouse_path."""
    return await _run_target_tool("usb_hid_extract", path, extra=["--mode", mode],
                                  image="ctftoolkit/ctf-forensics", timeout=timeout)


@mcp.tool(structured_output=False)
async def run_capinfos(path: str, options: str = "-a -c -d -e -H", timeout: int = 120) -> str:
    """Summarize PCAP metadata with capinfos."""
    extra = options.split() if options else []
    return await _run_target_tool(
        "capinfos",
        path,
        pre_args=extra,
        image="ctftoolkit/ctf-forensics",
        timeout=timeout,
    )


@mcp.tool(structured_output=False)
async def run_sox_spectrogram(path: str, out_name: str = "spectrogram.png",
                              timeout: int = 120) -> str:
    """Generate a spectrogram PNG from an audio file with sox (for SSTV/audio stego)."""
    global docker_runner
    if docker_runner is None:
        docker_runner = DockerRunner()
    try:
        target = _workspace_container_path(path)
        out = _workspace_container_path(out_name)
    except ValueError as exc:
        return f"Error: {exc}"
    try:
        result = await docker_runner.run_tool(
            "sox", [target, "-n", "spectrogram", "-o", out],
            timeout=timeout, image="ctftoolkit/ctf-forensics")
    except Exception as e:
        return f"Error running sox: {e}"
    combined = (result.get("stdout", "") + result.get("stderr", "")).strip()
    if result.get("exit_code") == 0:
        return f"Spectrogram written to workspace/{out_name}\n{combined}"[:4000]
    return f"sox failed: {combined}"[:4000]


@mcp.tool(structured_output=False)
async def run_volatility(path: str, plugin: str = "windows.info", timeout: int = 600) -> str:
    """Run a Volatility 3 plugin against a memory image in the workspace."""
    return await _run_target_tool("volatility", path, pre_args=["-f"], extra=[plugin],
                                  image="ctftoolkit/ctf-forensics", timeout=timeout)


# ---- Web ----
@mcp.tool(structured_output=False)
async def run_ffuf(url: str, wordlist: str = "/usr/share/wordlists/dirb/common.txt",
                   options: str = "", timeout: int = 300, format: str = "text") -> str:
    """Run ffuf web fuzzer. URL must contain FUZZ (e.g. http://host/FUZZ).

    Returns status-grouped hits. Pass format='json' for raw ffuf JSON."""
    global docker_runner
    if not _is_target_in_scope(url):
        return _scope_block_message(url)
    if docker_runner is None:
        docker_runner = DockerRunner()
    opt = options.split() if options else []
    # Emit JSON to stdout for parsing unless the caller already set an output mode.
    if not any(o in ("-json", "-of", "-o") for o in opt):
        opt += ["-json"]
    args = ["-u", url, "-w", wordlist] + opt
    try:
        result = await docker_runner.run_tool("ffuf", args, timeout=timeout)
    except Exception as e:
        return f"Error running ffuf: {e}"
    out = (result.get("stdout", "") + result.get("stderr", "")).strip()
    if format == "json":
        return out[:8000] or "(no output)"
    try:
        from .parsers.ffuf_parser import parse_ffuf_json, generate_summary
        return generate_summary(parse_ffuf_json(out))[:8000] or "(no output)"
    except Exception as e:
        logger.warning(f"ffuf parser failed, returning raw: {e}")
        return out[:8000] or "(no output)"


@mcp.tool(structured_output=False)
async def run_nuclei(url: str, options: str = "-silent", timeout: int = 600,
                     format: str = "text") -> str:
    """Scan a URL with nuclei templates.

    Returns severity-grouped findings. Pass format='json' for raw nuclei JSONL."""
    global docker_runner
    if not _is_target_in_scope(url):
        return _scope_block_message(url)
    if docker_runner is None:
        docker_runner = DockerRunner()
    opt = options.split() if options else []
    if not any(o in ("-jsonl", "-json", "-j") for o in opt):
        opt += ["-jsonl"]
    # nuclei doesn't auto-discover the baked templates dir without its config entry;
    # point it explicitly (the image clones templates to /home/ctf/nuclei-templates).
    if not any(o in ("-t", "-templates") for o in opt):
        opt += ["-t", "/home/ctf/nuclei-templates"]
    args = ["-u", url] + opt
    try:
        result = await docker_runner.run_tool("nuclei", args, timeout=timeout)
    except Exception as e:
        return f"Error running nuclei: {e}"
    out = (result.get("stdout", "") + result.get("stderr", "")).strip()
    if format == "json":
        return out[:8000] or "(no output)"
    try:
        from .parsers.nuclei_parser import parse_nuclei_jsonl, generate_summary
        return generate_summary(parse_nuclei_jsonl(out))[:8000] or "(no output)"
    except Exception as e:
        logger.warning(f"nuclei parser failed, returning raw: {e}")
        return out[:8000] or "(no output)"


@mcp.tool(structured_output=False)
async def run_jwt_tool(token: str, options: str = "", timeout: int = 120) -> str:
    """Analyze/attack a JWT with jwt_tool. `options` e.g. '-T' (tamper) or '-C -d wl.txt' (crack)."""
    global docker_runner
    if docker_runner is None:
        docker_runner = DockerRunner()
    args = [token] + (options.split() if options else [])
    try:
        result = await docker_runner.run_tool("jwt_tool", args, timeout=timeout)
    except Exception as e:
        return f"Error running jwt_tool: {e}"
    out = (result.get("stdout", "") + result.get("stderr", "")).strip()
    return out[:8000] or "(no output)"


@mcp.tool(structured_output=False)
async def run_katana(url: str, options: str = "-silent -json", timeout: int = 300) -> str:
    """Crawl a scoped web target with Katana for endpoint discovery."""
    global docker_runner
    if not _is_target_in_scope(url):
        return _scope_block_message(url)
    if docker_runner is None:
        docker_runner = DockerRunner()
    args = ["-u", url] + (options.split() if options else [])
    try:
        result = await docker_runner.run_tool("katana", args, timeout=timeout)
    except Exception as e:
        return f"Error running katana: {e}"
    out = (result.get("stdout", "") + result.get("stderr", "")).strip()
    return out[:8000] or "(no output)"


@mcp.tool(structured_output=False)
async def run_arjun(url: str, options: str = "-oJ -", timeout: int = 300) -> str:
    """Discover hidden HTTP parameters on a scoped URL with Arjun."""
    global docker_runner
    if not _is_target_in_scope(url):
        return _scope_block_message(url)
    if docker_runner is None:
        docker_runner = DockerRunner()
    args = ["-u", url] + (options.split() if options else [])
    try:
        result = await docker_runner.run_tool("arjun", args, timeout=timeout)
    except Exception as e:
        return f"Error running arjun: {e}"
    out = (result.get("stdout", "") + result.get("stderr", "")).strip()
    return out[:8000] or "(no output)"


@mcp.tool(structured_output=False)
async def run_linkfinder(input_path_or_url: str, options: str = "-o cli", timeout: int = 180) -> str:
    """Extract endpoints from JavaScript by URL or workspace file using LinkFinder."""
    global docker_runner
    target = input_path_or_url
    if input_path_or_url.startswith(("http://", "https://")):
        if not _is_target_in_scope(input_path_or_url):
            return _scope_block_message(input_path_or_url)
    else:
        try:
            target = _workspace_container_path(input_path_or_url)
        except ValueError as exc:
            return f"Error: {exc}"
    if docker_runner is None:
        docker_runner = DockerRunner()
    args = ["-i", target] + (options.split() if options else [])
    try:
        result = await docker_runner.run_tool("linkfinder", args, timeout=timeout)
    except Exception as e:
        return f"Error running linkfinder: {e}"
    out = (result.get("stdout", "") + result.get("stderr", "")).strip()
    return out[:8000] or "(no output)"


@mcp.tool(structured_output=False)
async def run_git_dumper(url: str, output_dir: str = "", timeout: int = 300) -> str:
    """Download an exposed .git directory from a scoped CTF URL."""
    global docker_runner
    if not _is_target_in_scope(url):
        return _scope_block_message(url)
    output = output_dir or "derived/git-dumper"
    try:
        out_path = _workspace_container_path(output)
    except ValueError as exc:
        return f"Error: {exc}"
    if docker_runner is None:
        docker_runner = DockerRunner()
    try:
        result = await docker_runner.run_tool("git-dumper", [url, out_path], timeout=timeout)
    except Exception as e:
        return f"Error running git-dumper: {e}"
    out = (result.get("stdout", "") + result.get("stderr", "")).strip()
    return out[:8000] or "(no output)"


@mcp.tool(structured_output=False)
async def run_gitleaks(path: str, options: str = "--no-git --redact", timeout: int = 300) -> str:
    """Scan a workspace source tree or extracted repo for secret leaks with Gitleaks."""
    extra = options.split() if options else []
    return await _run_target_tool(
        "gitleaks",
        path,
        pre_args=["detect", "--source"],
        extra=extra,
        image="ctftoolkit/ctf-tools",
        timeout=timeout,
    )


@mcp.tool(structured_output=False)
async def run_schemathesis(schema: str, base_url: str = "", options: str = "", timeout: int = 600) -> str:
    """Run bounded OpenAPI contract checks with Schemathesis."""
    global docker_runner
    schema_arg = schema
    if schema.startswith(("http://", "https://")):
        if not _is_target_in_scope(schema):
            return _scope_block_message(schema)
    else:
        try:
            schema_arg = _workspace_container_path(schema)
        except ValueError as exc:
            return f"Error: {exc}"
    if base_url and not _is_target_in_scope(base_url):
        return _scope_block_message(base_url)
    if docker_runner is None:
        docker_runner = DockerRunner()
    args = ["run", schema_arg]
    if base_url:
        args += ["--base-url", base_url]
    args += options.split() if options else []
    try:
        result = await docker_runner.run_tool("schemathesis", args, timeout=timeout)
    except Exception as e:
        return f"Error running schemathesis: {e}"
    out = (result.get("stdout", "") + result.get("stderr", "")).strip()
    return out[:8000] or "(no output)"


@mcp.tool(structured_output=False)
async def run_graphql_cop(url: str, options: str = "--json", timeout: int = 300) -> str:
    """Run scoped GraphQL endpoint checks with GraphQL Cop."""
    global docker_runner
    if not _is_target_in_scope(url):
        return _scope_block_message(url)
    if docker_runner is None:
        docker_runner = DockerRunner()
    args = ["-t", url] + (options.split() if options else [])
    try:
        result = await docker_runner.run_tool("graphql-cop", args, timeout=timeout)
    except Exception as e:
        return f"Error running graphql-cop: {e}"
    out = (result.get("stdout", "") + result.get("stderr", "")).strip()
    return out[:8000] or "(no output)"


# ---- Ghidra (headless analyzeHeadless; §6a stable path, warm-JVM swap deferred) ----
@mcp.tool(structured_output=False)
async def run_ghidra(path: str, timeout: int = 600) -> str:
    """Decompile a binary with Ghidra (headless) and return decompiled functions.

    Runs analyzeHeadless + a bundled dump script in the ctf-re image (lazy-built;
    the Ghidra layer is large). For big binaries increase timeout. Tool signature is
    stable so a future warm-JVM PyGhidra backend can replace this internally (§6a)."""
    return await _run_target_tool("ghidra", path, image="ctftoolkit/ctf-re", timeout=timeout)


# ---- Ghidra warm-JVM interactive session (PyGhidra broker; Oracle-reviewed) ----
# Boots the JVM + analyzes the binary ONCE, then reuses the warm program across
# decompile/strings/xref calls. Much faster than run_ghidra (which re-analyzes each
# call via analyzeHeadless). run_ghidra remains as the one-shot fallback.
@mcp.tool(structured_output=False)
async def ghidra_start(binary: str) -> str:
    """Start a warm Ghidra session on /workspace/<binary> (EXPERIMENTAL).

    Boots a persistent JVM and analyzes the binary once, then ghidra_decompile /
    ghidra_list_functions / ghidra_strings / ghidra_xrefs / ghidra_imports /
    ghidra_exports reuse that warm program; ghidra_stop ends it.

    NOTE: pyghidra's in-process JVM launch (pyghidra.start()) is unstable headless
    (UPGRADE_PLAN §6a) — it can hang on first start. This warm path is therefore
    OPT-IN: set CTFTOOLKIT_GHIDRA_WARM=1 to enable it. The default, always-working
    path is run_ghidra (Ghidra analyzeHeadless), which has an identical purpose."""
    import os as _os
    if _os.environ.get("CTFTOOLKIT_GHIDRA_WARM", "0").lower() not in ("1", "true", "yes"):
        return ("Warm Ghidra sessions are experimental and disabled by default "
                "(pyghidra in-process JVM launch is unstable headless per §6a). "
                "Use run_ghidra(path) for headless decompilation, or set "
                "CTFTOOLKIT_GHIDRA_WARM=1 to try the warm session.")
    from .ghidra_session import ghidra_start as _start
    res = await _start(binary)
    if res.get("error"):
        return f"Error: {res['error']}"
    return f"session_id={res['session_id']} program={res.get('program')}"


@mcp.tool(structured_output=False)
async def ghidra_decompile(session_id: str, name: str = "", address: str = "") -> str:
    """Decompile a function (by name or hex address) in a warm Ghidra session."""
    from .ghidra_session import ghidra_decompile as _d
    res = await _d(session_id, name=name, address=address)
    if res.get("error"):
        return f"Error: {res['error']}"
    d = res["data"]
    return f"// {d['name']} @ {d['entry']}\n{d['c']}"[:8000]


@mcp.tool(structured_output=False)
async def ghidra_list_functions(session_id: str) -> str:
    """List all functions (name, entry, size) in a warm Ghidra session."""
    from .ghidra_session import ghidra_list_functions as _l
    res = await _l(session_id)
    if res.get("error"):
        return f"Error: {res['error']}"
    import json as _json
    return _json.dumps(res["data"], indent=1)[:8000]


@mcp.tool(structured_output=False)
async def ghidra_strings(session_id: str, min_length: int = 4, filter: str = "") -> str:
    """List defined strings in a warm Ghidra session (optionally filtered)."""
    from .ghidra_session import ghidra_strings as _s
    res = await _s(session_id, min_length=min_length, filter=filter)
    if res.get("error"):
        return f"Error: {res['error']}"
    import json as _json
    return _json.dumps(res["data"], indent=1)[:8000]


@mcp.tool(structured_output=False)
async def ghidra_xrefs(session_id: str, name: str = "", address: str = "") -> str:
    """List cross-references TO a function in a warm Ghidra session."""
    from .ghidra_session import ghidra_xrefs as _x
    res = await _x(session_id, name=name, address=address)
    if res.get("error"):
        return f"Error: {res['error']}"
    import json as _json
    return _json.dumps(res["data"], indent=1)[:8000]


@mcp.tool(structured_output=False)
async def ghidra_imports(session_id: str) -> str:
    """List imported symbols in a warm Ghidra session."""
    from .ghidra_session import ghidra_imports as _i
    res = await _i(session_id)
    if res.get("error"):
        return f"Error: {res['error']}"
    import json as _json
    return _json.dumps(res["data"], indent=1)[:8000]


@mcp.tool(structured_output=False)
async def ghidra_exports(session_id: str) -> str:
    """List exported symbols / entry points in a warm Ghidra session."""
    from .ghidra_session import ghidra_exports as _e
    res = await _e(session_id)
    if res.get("error"):
        return f"Error: {res['error']}"
    import json as _json
    return _json.dumps(res["data"], indent=1)[:8000]


@mcp.tool(structured_output=False)
async def ghidra_stop(session_id: str) -> str:
    """Stop a warm Ghidra session and remove its container."""
    from .ghidra_session import ghidra_stop as _stop
    res = await _stop(session_id)
    return f"stopped {res['stopped']}" if res.get("stopped") else f"Error: {res.get('error')}"
# ---- GDB/MI interactive live-debug session (Oracle-reviewed design) ----
@mcp.tool(structured_output=False)
async def gdb_start(binary: str) -> str:
    """Start an interactive GDB/MI debug session on /workspace/<binary>.

    Returns a session_id. Drive it with gdb_send (MI commands like '-break-insert main',
    '-exec-run', '-stack-list-frames'), poll async stops with gdb_read, end with gdb_stop.
    State (breakpoints, the running inferior) persists across gdb_send calls."""
    from .gdb_session import gdb_start as _start
    res = await _start(binary)
    if res.get("error"):
        return f"Error: {res['error']}"
    return f"session_id={res['session_id']}\n{res.get('startup','')}"


@mcp.tool(structured_output=False)
async def gdb_send(session_id: str, mi_command: str, timeout: int = 30) -> str:
    """Send a GDB/MI command to a live session (e.g. '-exec-run', '-break-insert *0x401234')."""
    from .gdb_session import gdb_send as _send
    res = await _send(session_id, mi_command, timeout=float(timeout))
    return res.get("output") or f"Error: {res.get('error','no output')}"


@mcp.tool(structured_output=False)
async def gdb_read(session_id: str, timeout: int = 2) -> str:
    """Drain asynchronous GDB output (e.g. a ^stopped after -exec-continue)."""
    from .gdb_session import gdb_read as _read
    res = await _read(session_id, timeout=float(timeout))
    return res.get("output") or f"Error: {res.get('error','no output')}"


@mcp.tool(structured_output=False)
async def gdb_stop(session_id: str) -> str:
    """Stop and remove a GDB/MI live-debug session."""
    from .gdb_session import gdb_stop as _stop
    res = await _stop(session_id)
    return f"stopped {res['stopped']}" if res.get("stopped") else f"Error: {res.get('error')}"


# ---- Phase 2: per-challenge persistent workspace + memory ----
@mcp.tool(structured_output=False)
async def create_challenge(name: str, category: str = "", description: str = "") -> str:
    """Create a persistent per-challenge workspace (files/, .agent-home/, WRITEUP.md).

    Returns the challenge_id (slug) and container path. Files placed under the
    challenge's files/ dir are reachable at /workspace/challenges/<slug>/files/ in tools."""
    from .challenge import create_challenge as _create
    res = await _create(name, category=category or None, description=description or None)
    return (f"challenge_id={res['challenge_id']}\nworkspace={res['container_path']}\n"
            f"files={res['container_path']}/files\nwriteup={res['writeup']}")


@mcp.tool(structured_output=False)
async def ingest_challenge_file(challenge_id: str, src_path: str) -> str:
    """Copy a host file into a challenge's files/ dir (records hash in DB)."""
    from .challenge import ingest_file as _ingest
    from .evidence import append_evidence_event

    res = await _ingest(challenge_id, src_path)
    if res.get("error"):
        return f"Error: {res['error']}"
    append_evidence_event(
        _workspace_root(),
        "artifact_ingested",
        challenge_id=challenge_id,
        files=[src_path],
        file_hashes=[{"path": res["container_path"], "sha256": res["sha256"]}],
        artifacts=[res["container_path"]],
        metadata={"source": src_path},
    )
    return f"ingested {res['ingested']} (sha256 {res['sha256'][:16]}...) -> {res['container_path']}"


@mcp.tool(structured_output=False)
async def record_challenge_finding(challenge_id: str, kind: str, value: str, notes: str = "") -> str:
    """Record a finding (flag/credential/note) against a challenge + append to its WRITEUP.md."""
    from .challenge import record_finding as _record
    from .evidence import append_evidence_event

    res = await _record(challenge_id, kind, value, notes=notes)
    if res.get("error"):
        return f"Error: {res['error']}"
    append_evidence_event(
        _workspace_root(),
        "finding_recorded",
        challenge_id=challenge_id,
        artifacts=[{"kind": kind, "value": value}],
        metadata={"notes": notes} if notes else {},
    )
    return f"recorded {res['recorded']} for {res['challenge_id']}: {res['value']}"


@mcp.tool(structured_output=False)
async def challenge_status(challenge_id: str) -> str:
    """Show a challenge's status, files on disk, and metadata."""
    from .challenge import challenge_status as _status
    res = await _status(challenge_id)
    if res.get("error"):
        return f"Error: {res['error']}"
    import json as _json
    return _json.dumps(res, indent=2, default=str)


@mcp.tool(structured_output=False)
async def download_ctfd_challenge(base_url: str, challenge_id: int,
                                  session_cookie: str = "", token: str = "") -> str:
    """Download a CTFd challenge (metadata+files+hints+connection) into a workspace.

    Provide the CTFd base URL and the numeric challenge id, plus auth: either the
    `session` cookie value or an API `token`. Lays files under the per-challenge
    workspace and writes PROMPT.md. Optional feature (UPGRADE_PLAN §6)."""
    from .scrapers.ctfd_downloader import CTFdDownloader
    dl = CTFdDownloader(base_url, token=token or None, session_cookie=session_cookie or None)
    try:
        res = await dl.download_challenge(int(challenge_id))
    except Exception as e:
        return f"Error downloading challenge: {e}"
    if res.get("error"):
        return f"Error: {res['error']}"
    return (f"Downloaded '{res['name']}' ({res['category']}) -> {res['workspace']}\n"
            f"files: {', '.join(res['files']) or '(none)'}\n"
            f"connection: {res['connection'] or '(none)'}\nprompt: {res['prompt']}")


@mcp.tool(structured_output=False)
async def list_playbooks() -> str:
    """List the codified solver playbooks (Phase 5) and their trigger keywords."""
    from .playbooks import list_playbooks as _list
    import json as _json
    return _json.dumps(_list(), indent=2)


@mcp.tool(structured_output=False)
async def get_playbook(query: str, category: str = "") -> str:
    """Return the best-matching solver playbook (workflow + solve skeleton) for a challenge."""
    from .playbooks import match_playbook, render_playbook
    pb = match_playbook(query, category or None)
    if pb is None:
        return "No matching playbook. Use list_playbooks to see all, or proceed with the category route."
    return render_playbook(pb)


@mcp.tool(structured_output=False)
async def list_solver_templates(category: str = "", limit: int = 100) -> str:
    """List metadata-only solver templates for reverse, pwn, crypto, and forensics work."""
    from .solver_templates import list_solver_templates as _list_solver_templates

    templates = _list_solver_templates()
    if category:
        wanted = category.strip().lower().replace("_", "-")
        templates = [
            template
            for template in templates
            if str(template.get("category", "")).lower().replace("_", "-") == wanted
        ]
    return _json_response(templates[: max(0, limit)])


@mcp.tool(structured_output=False)
async def get_solver_template(template_id: str) -> str:
    """Return one solver template by id."""
    from .solver_templates import get_solver_template as _get_solver_template

    try:
        return _json_response(_get_solver_template(template_id))
    except KeyError:
        return f"Error: unknown solver template id: {template_id}"


@mcp.tool(structured_output=False)
async def select_solver_templates(
    description: str = "",
    category: str = "",
    files: str = "",
    findings: str = "",
    limit: int = 10,
) -> str:
    """Rank solver templates from challenge description, category, files, and findings."""
    from .solver_templates import select_solver_templates as _select_solver_templates

    return _json_response(
        _select_solver_templates(
            description=description,
            category=category,
            files=_split_user_list(files),
            findings=_split_user_list(findings),
            limit=limit,
        )
    )


@mcp.tool(structured_output=False)
async def score_playbooks(
    description: str = "",
    category: str = "",
    target: str = "",
    files: str = "",
    findings: str = "",
    failures: str = "",
    limit: int = 10,
) -> str:
    """Rank playbooks/workflow chains with prerequisites, artifacts, failures, and next actions."""
    from .playbook_scoring import select_scored_playbooks

    return _json_response(
        select_scored_playbooks(
            description=description,
            category=category,
            target=target,
            files=_split_user_list(files),
            findings=_split_user_list(findings),
            failures=_split_user_list(failures),
            limit=limit,
        )
    )


@mcp.tool(structured_output=False)
async def get_best_playbook(
    description: str = "",
    category: str = "",
    target: str = "",
    files: str = "",
    findings: str = "",
    failures: str = "",
) -> str:
    """Return the highest-scoring playbook or workflow-chain candidate."""
    from .playbook_scoring import select_best_playbook

    result = select_best_playbook(
        description=description,
        category=category,
        target=target,
        files=_split_user_list(files),
        findings=_split_user_list(findings),
        failures=_split_user_list(failures),
    )
    return _json_response(result or {})


@mcp.tool(structured_output=False)
async def list_playbook_failure_branches() -> str:
    """List common failure branches used by scored playbook routing."""
    from .playbook_scoring import common_failure_branches

    return _json_response(common_failure_branches())


@mcp.tool(structured_output=False)
async def get_case_resource_context(selector: str = "") -> str:
    """Return files, notes, findings, evidence logs, playbooks, and writeups for cases."""
    from .resources import build_resource_context

    return _json_response(build_resource_context(selector or None, _workspace_root()))


@mcp.tool(structured_output=False)
async def simulate_structured_tool_result(
    tool: str = "file",
    args: str = "",
    stdout: str = "simulated structured result",
    challenge_id: str = "",
    target: str = "",
    record_evidence: bool = False,
) -> str:
    """Return a structured ToolResult without invoking Docker; optionally record evidence."""
    from .execution import log_execution_result, simulate_read_only_tool_call

    arglist = _split_user_list(args) if args else []
    result = simulate_read_only_tool_call(
        tool,
        arglist,
        stdout=stdout,
        target=target or None,
        challenge_id=challenge_id or None,
    )
    payload: dict[str, Any] = {"result": result.to_dict()}
    if record_evidence:
        payload["evidence"] = log_execution_result(
            _workspace_root(),
            result,
            challenge_id=challenge_id or None,
            target=target or None,
        )
    return _json_response(payload)


@mcp.resource("ctfsolver://inventory", mime_type="application/json")
def resource_inventory() -> str:
    """Read-only backend inventory for MCP clients."""
    from .manifest import build_manifest

    return json.dumps(build_manifest(), indent=2, sort_keys=True)


@mcp.resource("ctfsolver://playbooks", mime_type="application/json")
def resource_playbooks() -> str:
    """Read-only list of built-in solver playbooks."""
    from .playbooks import list_playbooks as _list

    return json.dumps(_list(), indent=2, sort_keys=True)


@mcp.resource("ctfsolver://skills", mime_type="application/json")
def resource_skills() -> str:
    """Read-only list of bundled skill Markdown documents."""
    root = Path(__file__).resolve().parents[2]
    skills_root = root / "skills"
    paths = sorted(path.relative_to(root).as_posix() for path in skills_root.rglob("*.md"))
    return json.dumps({"count": len(paths), "paths": paths}, indent=2, sort_keys=True)


@mcp.resource("ctfsolver://cases", mime_type="application/json")
def resource_cases() -> str:
    """Read-only list of known case workspaces."""
    from .cases import list_cases as _list_cases

    return json.dumps(_list_cases(_workspace_root()), indent=2, sort_keys=True)


@mcp.resource("ctfsolver://challenge-files", mime_type="application/json")
def resource_challenge_files() -> str:
    """Read-only challenge files and attached artifacts."""
    from .resources import build_challenge_files_resource

    return _json_response(build_challenge_files_resource(workspace=_workspace_root()))


@mcp.resource("ctfsolver://notes", mime_type="application/json")
def resource_notes() -> str:
    """Read-only case notes and hypotheses."""
    from .resources import build_notes_resource

    return _json_response(build_notes_resource(workspace=_workspace_root()))


@mcp.resource("ctfsolver://findings", mime_type="application/json")
def resource_findings() -> str:
    """Read-only case findings."""
    from .resources import build_findings_resource

    return _json_response(build_findings_resource(workspace=_workspace_root()))


@mcp.resource("ctfsolver://evidence-logs", mime_type="application/json")
def resource_evidence_logs() -> str:
    """Read-only JSONL evidence event summaries."""
    from .resources import build_evidence_logs_resource

    return _json_response(build_evidence_logs_resource(workspace=_workspace_root()))


@mcp.resource("ctfsolver://writeups", mime_type="application/json")
def resource_writeups() -> str:
    """Read-only current and generated writeup context."""
    from .resources import build_writeups_resource

    return _json_response(build_writeups_resource(workspace=_workspace_root()))


@mcp.resource("ctfsolver://context", mime_type="application/json")
def resource_context() -> str:
    """Read-only full backend context for MCP clients."""
    from .resources import build_resource_context

    return _json_response(build_resource_context(workspace=_workspace_root()))


@mcp.resource("ctfsolver://workflow-chains", mime_type="application/json")
def resource_workflow_chains() -> str:
    """Read-only declarative workflow chain metadata."""
    from .workflow_chains import list_workflow_chains as _list_workflow_chains

    return json.dumps(_list_workflow_chains(), indent=2, sort_keys=True)


@mcp.resource("ctfsolver://tool-packs", mime_type="application/json")
def resource_tool_packs() -> str:
    """Read-only optional tool-pack metadata."""
    from .tool_packs import list_tool_packs as _list_tool_packs

    return json.dumps(_list_tool_packs(), indent=2, sort_keys=True)


def _category_prompt(category: str, challenge: str, target: str = "", files: str = "") -> str:
    parts = [
        f"Solve this {category} CTF challenge using ctfsolver non-CTFd MCP mode.",
        "create or select a challenge workspace, record findings as you go, and prefer safe offline triage before network scans.",
    ]
    if challenge:
        parts.append(f"Challenge: {challenge}")
    if target:
        parts.append(f"Target: {target}")
    if files:
        parts.append(f"Files: {files}")
    parts.append("Use get_playbook or suggest_next_tools when unsure, then run the narrowest relevant tools.")
    parts.append("When a flag is found, record it with record_challenge_finding and generate a concise writeup.")
    return "\n\n".join(parts)


@mcp.prompt(name="ctf_web_workflow")
def prompt_web(challenge: str, target: str = "", files: str = "") -> str:
    """Reusable web challenge workflow prompt."""
    return _category_prompt("web", challenge, target, files)


@mcp.prompt(name="ctf_pwn_workflow")
def prompt_pwn(challenge: str, target: str = "", files: str = "") -> str:
    """Reusable pwn challenge workflow prompt."""
    return _category_prompt("pwn", challenge, target, files)


@mcp.prompt(name="ctf_rev_workflow")
def prompt_rev(challenge: str, target: str = "", files: str = "") -> str:
    """Reusable reverse engineering challenge workflow prompt."""
    return _category_prompt("reverse engineering", challenge, target, files)


@mcp.prompt(name="ctf_crypto_workflow")
def prompt_crypto(challenge: str, target: str = "", files: str = "") -> str:
    """Reusable crypto challenge workflow prompt."""
    return _category_prompt("crypto", challenge, target, files)


@mcp.prompt(name="ctf_forensics_workflow")
def prompt_forensics(challenge: str, target: str = "", files: str = "") -> str:
    """Reusable forensics challenge workflow prompt."""
    return _category_prompt("forensics", challenge, target, files)


@mcp.prompt(name="ctf_osint_workflow")
def prompt_osint(challenge: str, target: str = "", files: str = "") -> str:
    """Reusable OSINT challenge workflow prompt."""
    return _category_prompt("OSINT", challenge, target, files)


@mcp.prompt(name="ctf_mobile_workflow")
def prompt_mobile(challenge: str, target: str = "", files: str = "") -> str:
    """Reusable mobile challenge workflow prompt."""
    return _category_prompt("mobile", challenge, target, files)


@mcp.prompt(name="ctf_cloud_workflow")
def prompt_cloud(challenge: str, target: str = "", files: str = "") -> str:
    """Reusable cloud challenge workflow prompt."""
    return _category_prompt("cloud", challenge, target, files)


def main():
    """Main entry point for the MCP server."""
    logger.info("Starting CTF Toolkit MCP Server...")

    # P0-002: set _SHUTDOWN on SIGINT/SIGTERM even when launched directly as the
    # MCP server (the normal `python -m ctf_core.server` path bypasses main.py).
    import signal as _signal
    import atexit as _atexit
    from .utils.resilience import _SHUTDOWN

    def _handle_shutdown(signum, frame):
        _SHUTDOWN.set()
        logger.info("Shutdown requested (signal %s) - finishing in-flight work...", signum)

    try:
        _signal.signal(_signal.SIGINT, _handle_shutdown)
        _signal.signal(_signal.SIGTERM, _handle_shutdown)
    except (ValueError, OSError):
        pass  # signal handlers must be set in the main thread

    # P0-003: close the shared DB connection on process exit.
    def _close_db_on_exit():
        try:
            asyncio.run(close_database())
        except Exception:
            pass

    _atexit.register(_close_db_on_exit)
    
    # Add file log handler inside main() (P3-004)
    log_dir = Path(__file__).parent.parent.parent / "logs"
    if log_dir.exists():
        file_handler = logging.FileHandler(log_dir / "ctfsolver.log")
        file_handler.setFormatter(JSONFormatter())
        logging.getLogger().addHandler(file_handler)
    
    # Auto-initialize database if missing (P2-008)
    db_path = DEFAULT_DB_PATH
    if not db_path.exists():
        logger.info("Database not found, initializing...")
        success = asyncio.run(init_database(db_path))
        if success:
            logger.info("Database initialized successfully")
        else:
            logger.warning("Database initialization failed - some features may not work")
    else:
        # P2-005: apply pending schema migrations to an existing database
        try:
            asyncio.run(migrate_database(db_path))
        except Exception as e:
            logger.warning(f"Migration check failed: {e}")

    # Phase 1: remove orphan GDB/MI session containers from a prior server process
    # (interactive sessions can't be recovered; kill-on-startup is correct here).
    try:
        from .gdb_session import reconcile_orphan_gdb_sessions
        asyncio.run(reconcile_orphan_gdb_sessions())
    except Exception as e:
        logger.warning(f"GDB orphan reconciliation skipped: {e}")

    # Phase: remove orphan warm-Ghidra session containers from a prior process.
    try:
        from .ghidra_session import reconcile_orphan_ghidra_sessions
        asyncio.run(reconcile_orphan_ghidra_sessions())
    except Exception as e:
        logger.warning(f"Ghidra orphan reconciliation skipped: {e}")

    # Phase 2: reconcile stale scan jobs (resolve every `running` row against Docker:
    # NotFound->failed, exited->collect+complete, running->re-attach, orphans->remove).
    try:
        from .jobs import reconcile_stale_jobs
        asyncio.run(reconcile_stale_jobs())
    except Exception as e:
        logger.warning(f"Scan-job reconciliation skipped: {e}")

    # Phase 4: opt-in idle-image prune at startup (safe two-gate; never mid-solve).
    # Disabled unless CTFTOOLKIT_PRUNE_ON_START is truthy, to avoid surprising removals.
    if os.environ.get("CTFTOOLKIT_PRUNE_ON_START", "0").lower() in ("1", "true", "yes"):
        try:
            from .prune import prune_images as _prune
            asyncio.run(_prune(dry_run=False))
        except Exception as e:
            logger.warning(f"Startup prune skipped: {e}")

    mcp.run(transport="stdio")


if __name__ == "__main__":
    main()
