from __future__ import annotations

import os
import re
import sys
from pathlib import Path
from typing import Any


def repo_root() -> Path:
    return Path(__file__).resolve().parents[2]


def src_root() -> Path:
    return repo_root() / "src"


def toolkit_workspace() -> Path:
    return Path(os.environ.get("CTFTOOLKIT_WORKSPACE") or repo_root() / "workspace")


def toolkit_db_path() -> Path:
    return Path(os.environ.get("CTFTOOLKIT_DB_PATH") or repo_root() / "ctf_state.db")


def toolkit_downloads() -> Path:
    return Path(os.environ.get("CTFTOOLKIT_DOWNLOADS") or repo_root() / "downloads")


def _abs(raw: str | None, default: Path) -> str:
    """Return an absolute path string: resolve relative values against repo_root()."""
    if not raw:
        return str(default)
    p = Path(raw)
    return str(p if p.is_absolute() else repo_root() / p)


def toolkit_env(base: dict[str, str] | None = None) -> dict[str, str]:
    env = dict(base or os.environ)
    existing_pythonpath = env.get("PYTHONPATH")
    paths = [str(src_root())]
    if existing_pythonpath:
        paths.append(existing_pythonpath)
    env["PYTHONPATH"] = os.pathsep.join(paths)
    env.setdefault("PYTHONUTF8", "1")
    env["CTFTOOLKIT_WORKSPACE"] = _abs(env.get("CTFTOOLKIT_WORKSPACE"), repo_root() / "workspace")
    env["CTFTOOLKIT_DB_PATH"] = _abs(env.get("CTFTOOLKIT_DB_PATH"), repo_root() / "ctf_state.db")
    env["CTFTOOLKIT_DOWNLOADS"] = _abs(env.get("CTFTOOLKIT_DOWNLOADS"), repo_root() / "downloads")
    return env


def ensure_toolkit_runtime_dirs() -> None:
    toolkit_workspace().mkdir(parents=True, exist_ok=True)
    toolkit_downloads().mkdir(parents=True, exist_ok=True)
    (repo_root() / "logs").mkdir(parents=True, exist_ok=True)


def toolkit_status_snapshot() -> dict[str, Any]:
    root = repo_root()
    core_dir = root / "src" / "ctf_core"
    server_file = core_dir / "server.py"
    registry_tools: int | None = None
    registry_error: str | None = None

    if str(src_root()) not in sys.path:
        sys.path.insert(0, str(src_root()))

    try:
        from ctf_core.registry import TOOL_REGISTRY

        registry_tools = len(TOOL_REGISTRY)
    except Exception as exc:  # pragma: no cover - dashboard status should not crash UI.
        registry_error = str(exc)

    server_text = server_file.read_text(encoding="utf-8") if server_file.exists() else ""
    mcp_tools = len(re.findall(r"@mcp\.tool", server_text))
    skill_files = len(list((root / "skills").rglob("*.md"))) if (root / "skills").exists() else 0
    dockerfiles = (
        len(list((root / "docker").rglob("Dockerfile*"))) if (root / "docker").exists() else 0
    )
    schema_files = len([path for path in (root / "schema").rglob("*") if path.is_file()]) if (
        root / "schema"
    ).exists() else 0

    ok = (
        core_dir.exists()
        and server_file.exists()
        and mcp_tools >= 71
        and (registry_tools or 0) >= 60
        and skill_files >= 33
        and dockerfiles >= 6
        and schema_files >= 2
    )
    return {
        "ok": ok,
        "state": "ready" if ok else "incomplete",
        "core_dir": str(core_dir),
        "workspace": str(toolkit_workspace()),
        "db_path": str(toolkit_db_path()),
        "mcp_tools": mcp_tools,
        "registry_tools": registry_tools,
        "registry_error": registry_error,
        "skill_files": skill_files,
        "dockerfiles": dockerfiles,
        "schema_files": schema_files,
    }
