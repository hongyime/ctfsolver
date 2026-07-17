"""Executor agent for task execution."""

import logging
import os
import sys
from pathlib import Path
from typing import Any, Optional

from ctf_core.utils.resilience import _SHUTDOWN

logger = logging.getLogger(__name__)


class Executor:
    """Executes specific tasks delegated by the Planner."""
    
    def __init__(self, docker_runner=None, db=None):
        self.docker_runner = docker_runner
        self.db = db
        self.skill_cache = {}
    
    async def execute_task(self, task: dict, context: dict) -> dict:
        """Execute a single task with step-by-step reasoning log and shutdown checks.

        Args:
            task: Task definition from Planner
            context: Execution context (target info, etc.)

        Returns:
            Execution results (partial if shutdown was requested mid-task)
        """
        tool = task.get("tool") or ""
        args = task.get("args", [])
        challenge_id = context.get("challenge_id")
        action_id = context.get("action_id")
        step_number = context.get("_step_counter", 1)

        if _SHUTDOWN.is_set():
            print("[STOPPED] Shutdown requested. Not starting task execution.")
            return {"tool": tool, "success": False, "output": "", "skill_used": False, "duration": 0}

        # Substitute context variables in args
        substituted_args = self._substitute_args(args, context)

        # P1-007: fail fast if a template var (e.g. {target_url}) was left unresolved,
        # rather than passing the literal placeholder string to the tool.
        import re as _re
        unresolved = [a for a in substituted_args if _re.search(r"\{[a-zA-Z_]\w*\}", a)]
        if unresolved:
            msg = f"Unresolved template args for {tool}: {unresolved}"
            logger.warning(msg)
            return {"tool": tool, "success": False, "output": msg, "skill_used": False, "duration": 0}

        # Load skill if available
        skill_content = await self._load_skill(tool)

        # Check shutdown before each tool execution
        if _SHUTDOWN.is_set():
            print("[STOPPED] Shutdown requested. Not starting tool execution.")
            return {"tool": tool, "success": False, "output": "", "skill_used": False, "duration": 0}

        # Log step to database
        step_description = f"[STEP {step_number}] Executing {tool} with args: {substituted_args}"
        if self.db is not None:
            try:
                await self.db.log_reasoning_step(
                    step_number=step_number,
                    step_description=step_description,
                    challenge_id=challenge_id,
                    action_id=action_id,
                )
            except Exception as e:
                logger.warning(f"Failed to write reasoning_log: {e}")

        print(step_description, flush=True)
        sys.stdout.flush()

        # Execute the tool
        result = await self._execute_tool(tool, substituted_args)

        # Truncate output before storing
        full_output = result.get("stdout", "") + result.get("stderr", "")
        max_len = int(os.environ.get("CTFTOOLKIT_SUMMARIZE_THRESHOLD", "1000"))
        truncated_output = full_output[:max_len] if len(full_output) > max_len else full_output

        # Update reasoning_log with output
        if self.db is not None:
            try:
                await self.db.update_reasoning_output(
                    step_output=truncated_output,
                    step_number=step_number,
                    challenge_id=challenge_id,
                )
            except Exception as e:
                logger.warning(f"Failed to update reasoning_log: {e}")

        return {
            "tool": tool,
            "success": result.get("exit_code", 1) == 0,
            "output": full_output,
            "skill_used": skill_content is not None,
            "duration": result.get("duration", 0),
        }
    
    def _substitute_args(self, args: list[str], context: dict) -> list[str]:
        """Substitute context variables in arguments."""
        result = []
        for arg in args:
            for key, value in context.items():
                if value:
                    arg = arg.replace(f"{{{key}}}", str(value))
            result.append(arg)
        return result
    
    async def _load_skill(self, tool_name: str) -> Optional[str]:
        """Load SKILL.md file for the tool."""
        if tool_name in self.skill_cache:
            return self.skill_cache[tool_name]
        
        # Map tool names to skill files
        skill_map = {
            "nmap": "skills/recon/ctf-recon-nmap.md",
            "sqlmap": "skills/web/ctf-web-sqli.md",
            "ffuf": "skills/web/ctf-web-fuzzing.md",
            "feroxbuster": "skills/web/ctf-web-fuzzing.md",
            "searchsploit": "skills/exploitation/ctf-exploit-searchsploit.md",
            "pwntools": "skills/pwn/ctf-pwn-basics.md",
            "gdb": "skills/pwn/ctf-pwn-debugging.md",
            "volatility": "skills/forensics/ctf-forensics-memory.md",
            "exiftool": "skills/forensics/ctf-forensics-metadata.md",
        }
        
        skill_file = skill_map.get(tool_name)
        if not skill_file:
            return None
        
        skill_path = Path(__file__).parent.parent.parent.parent / skill_file
        if skill_path.exists():
            content = skill_path.read_text()
            self.skill_cache[tool_name] = content
            return content
        
        return None
    
    async def _execute_tool(self, tool_name: str, args: list[str]) -> dict:
        """Execute a tool using Docker runner."""
        if self.docker_runner is None:
            return {
                "stdout": "",
                "stderr": "Docker runner not initialized",
                "exit_code": 1,
                "duration": 0,
            }
        
        return await self.docker_runner.run_tool(tool_name, args)
    
    async def store_results(self, task_result: dict, target_id: Optional[int]) -> None:
        """Store task results in database."""
        if self.db is None:
            logger.warning("Database not initialized, skipping result storage")
            return
        
        tool = task_result.get("tool", "unknown")
        output = task_result.get("output", "")
        
        # Log the action
        await self.db.log_action(
            tool_used=tool,
            command_string=output[:500],  # Truncate for storage
            reason=f"Executed as part of task: {tool}",
            target_id=target_id,
        )

        # P0-006: capture flags + persist structured findings (finishes the pipeline)
        try:
            from ..utils.flag_detector import FlagPatternDetector
            for m in FlagPatternDetector().detect(output):
                await self.db.insert_flag(flag=m.flag, source=tool, pattern=m.pattern, target_id=target_id)
        except Exception as e:
            logger.warning(f"store_results: flag capture failed for {tool}: {e}")

        parsed = self._parse_output(tool, task_result)
        if not parsed:
            return
        try:
            async with self.db.transaction():
                await self._persist_parsed(tool, parsed, target_id)
        except Exception as e:
            logger.warning(f"store_results: persist failed for {tool}: {e}")

    def _parse_output(self, tool: str, task_result: dict) -> Optional[dict]:
        """Dispatch the matching parser for a tool's output (P0-006)."""
        output = task_result.get("output", "")
        parsers = {
            "nmap": ("..parsers.nmap_parser", "parse_nmap_xml"),
            "masscan": ("..parsers.masscan_parser", "parse_masscan_xml"),
            "feroxbuster": ("..parsers.ferox_parser", "parse_feroxbuster_jsonl"),
            "searchsploit": ("..parsers.sploit_parser", "parse_searchsploit_json"),
            "sqlmap": ("..parsers.sqlmap_parser", "parse_sqlmap_output"),
            "hydra": ("..parsers.hydra_parser", "parse_hydra_output"),
            "nikto": ("..parsers.nikto_parser", "parse_nikto_output"),
            "hashcat": ("..parsers.hashcat_parser", "parse_hashcat_output"),
        }
        spec = parsers.get(tool)
        if not spec:
            return None
        import importlib
        try:
            mod = importlib.import_module(spec[0], __package__)
            return getattr(mod, spec[1])(output)
        except Exception as e:
            logger.warning(f"store_results: parse failed for {tool}: {e}")
            return None

    async def _persist_parsed(self, tool: str, parsed: dict, target_id: Optional[int]) -> None:
        """Route parsed findings to DB inserts (P0-006)."""
        if self.db is None:
            return
        db = self.db
        # nmap/masscan create targets + services
        if parsed.get("hosts"):
            for host in parsed["hosts"]:
                ip = host.get("ip_address")
                if not ip:
                    continue
                tid = await db.insert_target(ip_address=ip, hostname=host.get("hostname"), os_type=host.get("os_type"))
                for svc in host.get("services", []):
                    await db.insert_service(target_id=tid, port=svc["port"], protocol=svc.get("protocol", "tcp"),
                                            service_name=svc.get("service_name"), banner=svc.get("banner"))
                for p in host.get("ports", []):
                    await db.insert_service(target_id=tid, port=p["port"], protocol=p.get("protocol", "tcp"))
            return
        # remaining tools need an existing target to attach to
        if target_id is None:
            logger.info(f"store_results: no target_id for {tool}; structured findings logged only")
            return
        for d in parsed.get("directories", []):
            await db.insert_web_directory(target_id=target_id, path=d.get("url", ""), status_code=d.get("status"))
        for c in parsed.get("credentials", []):
            await db.insert_credential(target_id=target_id, username=c.get("username", ""), cleartext=c.get("password"))
        for h in parsed.get("password_hashes", []):
            await db.insert_credential(target_id=target_id, username=h.get("username", ""), password_hash=h.get("password_hash"))
        for ex in parsed.get("exploits", []):
            await db.insert_exploit(target_id=target_id, cve_id=ex.get("cve"), exploit_path=(ex.get("path") or "unknown"))
