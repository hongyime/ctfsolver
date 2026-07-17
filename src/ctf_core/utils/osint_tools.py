"""OSINT tools integration — SpiderFoot and theHarvester via Docker (Phase 0).

Phase 0 change: these tools previously ran as HOST subprocesses (subprocess.run),
which meant they were absent on virtually every machine and broke the hardened,
container-isolated execution model. They now run inside the ctf-tools image through
the shared DockerRunner, exactly like every other tool. No host binaries required.
"""

import json
import logging
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)


async def _run_osint_tool(tool_name: str, args: list[str], timeout: int = 600,
                          docker_runner=None) -> dict:
    """Run an OSINT tool inside the ctf-tools container via the shared DockerRunner.

    Returns a dict shaped like the rest of the toolkit: stdout/stderr/returncode/tool.
    """
    from ..docker_runner import DockerRunner
    if docker_runner is None:
        docker_runner = DockerRunner()
    try:
        result = await docker_runner.run_tool(tool_name, args, timeout=timeout)
    except Exception as e:  # pragma: no cover — defensive
        return {"stdout": "", "stderr": str(e), "returncode": -1,
                "tool": tool_name, "error": str(e)}
    return {
        "stdout": result.get("stdout", ""),
        "stderr": result.get("stderr", ""),
        "returncode": result.get("exit_code", -1),
        "tool": tool_name,
        "error": result.get("error"),
    }


class SpiderFootClient:
    """SpiderFoot OSINT client — runs `sf` inside the ctf-tools container."""

    def __init__(self, workspace_path: Optional[Path] = None, docker_runner=None):
        if workspace_path is None:
            from ..docker_runner import WORKSPACE_PATH
            workspace_path = WORKSPACE_PATH
        self.workspace_path = Path(workspace_path)
        self.workspace_path.mkdir(parents=True, exist_ok=True)
        self._docker_runner = docker_runner

    async def scan_target(self, target: str, scan_name: str = "auto_scan") -> dict:
        """Run a SpiderFoot scan on a target inside the container.

        SpiderFoot CLI (`sf` / sfcli) usage: -s <target> -m <modules> -F json (stdout).
        Output is captured from stdout (no host file dependency).
        """
        args = ["-s", target, "-m", "sfp_dnsresolve,sfp_whois,sfp_portscan_tcp", "-F", "json"]
        result = await _run_osint_tool("spiderfoot", args, timeout=600,
                                       docker_runner=self._docker_runner)
        if not result.get("error"):
            raw = (result.get("stdout") or "").strip()
            if raw:
                try:
                    result["parsed"] = json.loads(raw)
                except json.JSONDecodeError:
                    # SpiderFoot may emit CSV/line JSON; keep raw for the summary.
                    logger.debug("SpiderFoot output was not a single JSON document")
        return result

    def get_summary(self, result: dict) -> str:
        """Generate a summary from SpiderFoot results."""
        if result.get("error"):
            return f"SpiderFoot error: {result.get('stderr', 'Unknown error')}"

        lines = ["SpiderFoot OSINT Results:", ""]
        parsed = result.get("parsed", {})
        if isinstance(parsed, list):
            lines.append(f"Total findings: {len(parsed)}")
            lines.append("")
            by_module: dict[str, list] = {}
            for item in parsed[:50]:
                module = item.get("module") or item.get("MODULE", "unknown")
                by_module.setdefault(module, []).append(
                    item.get("data") or item.get("DATA", "N/A"))
            for module, items in by_module.items():
                lines.append(f"[{module}] ({len(items)} findings)")
                for item in items[:3]:
                    lines.append(f"  - {item}")
        else:
            lines.append("No structured results available.")
            lines.append(f"Raw output: {result.get('stdout', '')[:500]}")
        return "\n".join(lines)


class TheHarvesterClient:
    """theHarvester client — runs `theHarvester` inside the ctf-tools container."""

    def __init__(self, workspace_path: Optional[Path] = None, docker_runner=None):
        if workspace_path is None:
            from ..docker_runner import WORKSPACE_PATH
            workspace_path = WORKSPACE_PATH
        self.workspace_path = Path(workspace_path)
        self.workspace_path.mkdir(parents=True, exist_ok=True)
        self._docker_runner = docker_runner

    async def enumerate_domain(self, domain: str, sources: list[str] | None = None) -> dict:
        """Enumerate subdomains and emails for a domain inside the container.

        Writes JSON to /workspace and parses it back out (theHarvester appends .json).
        """
        if sources is None:
            sources = ["crtsh", "duckduckgo", "rapiddns", "dnsdumpster"]
        out_stem = f"harvester_{domain.replace('/', '_')}"
        args = ["-d", domain, "-b", ",".join(sources), "-f", f"/workspace/{out_stem}"]
        result = await _run_osint_tool("theHarvester", args, timeout=300,
                                       docker_runner=self._docker_runner)
        if not result.get("error"):
            # theHarvester writes <stem>.json into the mounted workspace.
            for candidate in (self.workspace_path / f"{out_stem}.json",
                              self.workspace_path / out_stem):
                if candidate.exists():
                    try:
                        with open(candidate) as f:
                            result["parsed"] = json.load(f)
                    except (json.JSONDecodeError, OSError) as e:
                        logger.warning(f"Failed to parse theHarvester output: {e}")
                    finally:
                        try:
                            candidate.unlink()
                        except OSError:
                            pass
                    break
        return result

    def get_summary(self, result: dict) -> str:
        """Generate a summary from theHarvester results."""
        if result.get("error"):
            return f"theHarvester error: {result.get('stderr', 'Unknown error')}"

        lines = ["theHarvester OSINT Results:", ""]
        parsed = result.get("parsed", {})
        if not isinstance(parsed, dict):
            parsed = {}

        emails = parsed.get("emails", [])
        if emails:
            lines.append(f"Email addresses found: {len(emails)}")
            for email in emails[:10]:
                lines.append(f"  - {email}")
            if len(emails) > 10:
                lines.append(f"  ... and {len(emails) - 10} more")
        else:
            lines.append("No email addresses found.")

        lines.append("")

        hosts = parsed.get("hosts", [])
        if hosts:
            lines.append(f"Subdomains found: {len(hosts)}")
            for host in hosts[:10]:
                lines.append(f"  - {host}")
            if len(hosts) > 10:
                lines.append(f"  ... and {len(hosts) - 10} more")
        else:
            lines.append("No subdomains found.")

        if not emails and not hosts:
            lines.append("")
            lines.append(f"Raw output: {result.get('stdout', '')[:500]}")
        return "\n".join(lines)


async def run_spiderfoot(target: str) -> str:
    """Run SpiderFoot scan and return formatted results."""
    client = SpiderFootClient()
    result = await client.scan_target(target)
    return client.get_summary(result)


async def run_theharvester(domain: str) -> str:
    """Run theHarvester enumeration and return formatted results."""
    client = TheHarvesterClient()
    result = await client.enumerate_domain(domain)
    return client.get_summary(result)
