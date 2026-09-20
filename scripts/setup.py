"""ctfsolver setup — generate MCP client config from the repo location.

This script generates a ready-to-paste MCP config pinned to THIS checkout's
absolute path, so clone-and-run works with zero hand-editing.

Usage:
    python scripts/setup.py                 # print MCP config for this clone (auto OS)
    python scripts/setup.py --write          # also write mcp.local.json next to repo
    python scripts/setup.py --auth-check     # print local Claude/Codex auth status
    python scripts/setup.py --check-docker   # verify Docker daemon reachable
    python scripts/setup.py --windows        # force Windows-style backslash paths
    python scripts/setup.py --posix          # force POSIX forward-slash paths
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
SERVER_ID = "ctfsolver"


def _is_windows() -> bool:
    return os.name == "nt" or sys.platform.startswith("win")


def _fmt_path(p: Path, *, windows: bool) -> str:
    """Render an absolute path for the target client OS.

    JSON requires backslashes to be escaped; json.dump handles that, so we pass the
    native string and let the serializer escape it. For POSIX output we force forward
    slashes (useful when generating a WSL/Linux config from a Windows checkout).
    """
    s = str(p.resolve())
    if not windows:
        s = s.replace("\\", "/")
    return s


def build_config(*, windows: bool) -> dict:
    root = _fmt_path(PROJECT_ROOT, windows=windows)
    workspace = _fmt_path(PROJECT_ROOT / "workspace", windows=windows)
    db_path = _fmt_path(PROJECT_ROOT / "ctf_state.db", windows=windows)

    # Resolve CTF_WORKDIR: env var first, then session config fallback
    ctf_workdir = os.environ.get("CTF_WORKDIR", "").strip()
    if not ctf_workdir:
        try:
            import importlib.util as _ilu
            _script = PROJECT_ROOT / "scripts" / "ctfsolver_config.py"
            _spec = _ilu.spec_from_file_location("ctfsolver_config", str(_script))
            if _spec and _spec.loader:
                _mod = _ilu.module_from_spec(_spec)
                _spec.loader.exec_module(_mod)  # type: ignore[union-attr]
                ctf_workdir = _mod.read_session_config().get("workdir", "") or ""
        except Exception:
            pass
    if not ctf_workdir:
        print(
            "WARNING: CTF_WORKDIR is not set. Set it in .env or via the dashboard '--workdir' flag ",
            "before running agents.",
            file=sys.stderr,
        )

    return {
        "mcpServers": {
            SERVER_ID: {
                "command": "uv",
                "args": [
                    "--directory", root,
                    "run", "python", "-m", "ctf_core.server",
                ],
                "env": {
                    "CTF_WORKDIR": ctf_workdir,
                    "CTFTOOLKIT_WORKSPACE": workspace,
                    "CTFTOOLKIT_DB_PATH": db_path,
                },
            }
        }
    }


def auth_status() -> list[tuple[str, bool, str]]:
    """Return Claude/Codex auth status without exposing secret values."""
    claude_env = bool(
        os.environ.get("ANTHROPIC_API_KEY")
        or os.environ.get("ANTHROPIC_AUTH_TOKEN")
        or os.environ.get("CLAUDE_CODE_OAUTH_TOKEN")
    )
    claude_file = Path(os.environ.get("CTF_HARNESS_CLAUDE_CONFIG_DIR") or Path.home() / ".claude") / ".credentials.json"
    codex_env = bool(
        os.environ.get("OPENAI_API_KEY")
        or os.environ.get("CODEX_ACCESS_TOKEN")
        or os.environ.get("OPENAI_OAUTH_TOKEN")
        or os.environ.get("CODEX_OAUTH_TOKEN")
    )
    codex_file = Path(os.environ.get("CTF_HARNESS_CODEX_HOME") or Path.home() / ".codex") / "auth.json"

    return [
        (
            "Claude",
            claude_env or claude_file.exists(),
            "env auth set" if claude_env else (
                f"local CLI auth found at {claude_file}" if claude_file.exists()
                else "missing; sign in with Claude Code or set ANTHROPIC_API_KEY / ANTHROPIC_AUTH_TOKEN in .env"
            ),
        ),
        (
            "Codex",
            codex_env or codex_file.exists(),
            "env auth set" if codex_env else (
                f"local CLI auth found at {codex_file}" if codex_file.exists()
                else "missing; sign in with Codex or set OPENAI_API_KEY / CODEX_ACCESS_TOKEN in .env"
            ),
        ),
    ]


def print_auth_status() -> bool:
    statuses = auth_status()
    print("\nAuth status:")
    for name, ok, detail in statuses:
        label = "OK" if ok else "MISSING"
        print(f"- {name}: {label} ({detail})")
    return all(ok for _, ok, _ in statuses)


def check_docker() -> bool:
    """Return True if the Docker daemon is reachable."""
    try:
        import docker
    except ImportError:
        print("ERROR: docker SDK not installed. Run `uv sync` first.", file=sys.stderr)
        return False
    try:
        client = docker.from_env()
        client.ping()
        ver = client.version().get("Version", "unknown")
        print(f"Docker daemon: OK (server {ver})")
        return True
    except Exception as e:  # noqa: BLE001 — surface any docker connectivity failure
        print(f"Docker daemon: UNREACHABLE — {e}", file=sys.stderr)
        print("       Start Docker Desktop / dockerd and retry.", file=sys.stderr)
        return False


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Generate ctfsolver MCP config from this checkout's path.")
    parser.add_argument("--write", action="store_true",
                        help="write mcp.local.json into the repo root")
    parser.add_argument("--check-docker", action="store_true",
                        help="verify the Docker daemon is reachable")
    parser.add_argument("--auth-check", action="store_true",
                        help="print local Claude/Codex auth status without exposing token values")
    g = parser.add_mutually_exclusive_group()
    g.add_argument("--windows", action="store_true", help="force Windows-style paths")
    g.add_argument("--posix", action="store_true", help="force POSIX-style paths")
    args = parser.parse_args()

    if args.check_docker:
        ok = check_docker()
        if not args.write and not args.windows and not args.posix and not args.auth_check:
            return 0 if ok else 2

    windows = args.windows or (_is_windows() and not args.posix)
    config = build_config(windows=windows)
    rendered = json.dumps(config, indent=2)

    print("# MCP config for this checkout (paste into your AI IDE's MCP settings):")
    print(rendered)

    if args.write:
        out = PROJECT_ROOT / "mcp.local.json"
        out.write_text(rendered + "\n", encoding="utf-8")
        print(f"\nWrote {out}")

    if args.auth_check:
        print_auth_status()

    return 0


if __name__ == "__main__":
    sys.exit(main())
