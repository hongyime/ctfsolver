"""Lightweight backend smoke checks for non-CTFd MCP mode."""

from __future__ import annotations

import asyncio
import os
import re
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


@dataclass
class SmokeCheck:
    name: str
    ok: bool
    message: str
    details: dict[str, Any] = field(default_factory=dict)


@dataclass
class SmokeReport:
    ok: bool
    checks: list[SmokeCheck]

    def to_dict(self) -> dict[str, Any]:
        return {
            "ok": self.ok,
            "checks": [
                {
                    "name": check.name,
                    "ok": check.ok,
                    "message": check.message,
                    "details": check.details,
                }
                for check in self.checks
            ],
        }

    def to_text(self) -> str:
        lines = ["ctfsolver backend smoke check:", ""]
        for check in self.checks:
            mark = "PASS" if check.ok else "FAIL"
            lines.append(f"[{mark}] {check.name}: {check.message}")
        lines.append("")
        lines.append("overall: " + ("PASS" if self.ok else "FAIL"))
        return "\n".join(lines)


def repo_root() -> Path:
    return Path(__file__).resolve().parents[2]


def count_mcp_tool_decorators(server_path: Path | None = None) -> int:
    path = server_path or repo_root() / "src" / "ctf_core" / "server.py"
    text = path.read_text(encoding="utf-8")
    return len(re.findall(r"@mcp\.tool", text))


def registry_count() -> int:
    from .registry import TOOL_REGISTRY

    return len(TOOL_REGISTRY)


async def _challenge_roundtrip(workspace: Path, db_path: Path) -> SmokeCheck:
    os.environ["CTFTOOLKIT_WORKSPACE"] = str(workspace)
    os.environ["CTFTOOLKIT_DB_PATH"] = str(db_path)

    from . import db as db_module
    from . import docker_runner as docker_runner_module
    from .challenge import challenge_status, create_challenge

    db_module.DEFAULT_DB_PATH = db_path
    docker_runner_module.WORKSPACE_PATH = workspace

    try:
        await db_module.close_database()
        await db_module.init_database(db_path)
        await db_module.migrate_database(db_path)
        created = await create_challenge(
            "smoke local challenge",
            category="smoke",
            description="backend smoke test",
        )
        status = await challenge_status(created["challenge_id"])
        ok = not status.get("error") and status.get("challenge_id") == created["challenge_id"]
        return SmokeCheck(
            "challenge_roundtrip",
            ok,
            f"created {created['challenge_id']}" if ok else str(status.get("error")),
            {"challenge_id": created["challenge_id"], "workspace": created["workspace"]},
        )
    except Exception as exc:  # pragma: no cover - exercised by CLI failure path.
        return SmokeCheck("challenge_roundtrip", False, str(exc))
    finally:
        await db_module.close_database()


def _artifact_triage_roundtrip(workspace: Path) -> SmokeCheck:
    from .artifact_triage import triage_artifact

    try:
        artifact = workspace / "smoke-artifact.txt"
        artifact.parent.mkdir(parents=True, exist_ok=True)
        artifact.write_text("CTF smoke artifact\n", encoding="utf-8")
        result = triage_artifact(artifact)
        ok = result["sha256"] and result["size"] == artifact.stat().st_size
        return SmokeCheck(
            "artifact_triage",
            bool(ok),
            f"triaged {artifact.name}" if ok else "artifact triage result was incomplete",
            {"path": str(artifact), "size": result.get("size")},
        )
    except Exception as exc:  # pragma: no cover - exercised by CLI failure path.
        return SmokeCheck("artifact_triage", False, str(exc))


async def run_smoke(
    *,
    min_mcp_tools: int = 71,
    min_registry_tools: int = 60,
    workspace: Path | None = None,
    db_path: Path | None = None,
    challenge_roundtrip: bool = True,
) -> SmokeReport:
    """Run fast backend checks that do not require Docker images."""

    checks: list[SmokeCheck] = []

    try:
        tools = count_mcp_tool_decorators()
        checks.append(
            SmokeCheck(
                "mcp_tool_inventory",
                tools >= min_mcp_tools,
                f"{tools} MCP tool decorators found",
                {"count": tools, "minimum": min_mcp_tools},
            )
        )
    except Exception as exc:
        checks.append(SmokeCheck("mcp_tool_inventory", False, str(exc)))

    try:
        tools = registry_count()
        checks.append(
            SmokeCheck(
                "registry_inventory",
                tools >= min_registry_tools,
                f"{tools} registry tools found",
                {"count": tools, "minimum": min_registry_tools},
            )
        )
    except Exception as exc:
        checks.append(SmokeCheck("registry_inventory", False, str(exc)))

    if challenge_roundtrip:
        if workspace is None or db_path is None:
            with tempfile.TemporaryDirectory(prefix="ctfsolver-smoke-") as tmp:
                root = Path(tmp)
                workspace_path = root / "workspace"
                checks.append(await _challenge_roundtrip(workspace_path, root / "ctf_state.db"))
                checks.append(_artifact_triage_roundtrip(workspace_path))
        else:
            checks.append(await _challenge_roundtrip(workspace, db_path))
            checks.append(_artifact_triage_roundtrip(workspace))

    return SmokeReport(ok=all(check.ok for check in checks), checks=checks)


def run_smoke_sync(**kwargs: Any) -> SmokeReport:
    return asyncio.run(run_smoke(**kwargs))
