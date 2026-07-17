"""Thin launcher for the CTF Toolkit MCP server.

Phase 0: a convenience entrypoint so the server can be started without remembering
the module path, and so a `[project.scripts]` console-script (`ctf-toolkit`) exists.

This wrapper deliberately stays minimal — it sets sane default env (workspace/DB
rooted at this checkout if unset) and then hands off to ctf_core.server.main().
The heavy security tooling lives in Docker images, not on the host; the host only
needs Python + the `docker` SDK (installed via `uv sync`).
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent


def main() -> int:
    # Default workspace/DB to this checkout if the caller did not set them, so a bare
    # `ctf-toolkit` / `python scripts/launch.py` works out of the box.
    os.environ.setdefault("CTFTOOLKIT_WORKSPACE", str(PROJECT_ROOT / "workspace"))
    os.environ.setdefault("CTFTOOLKIT_DB_PATH", str(PROJECT_ROOT / "ctf_state.db"))

    # Ensure src/ is importable when launched directly (not via the installed package).
    src = PROJECT_ROOT / "src"
    if src.is_dir() and str(src) not in sys.path:
        sys.path.insert(0, str(src))

    from ctf_core.server import main as server_main
    server_main()
    return 0


if __name__ == "__main__":
    sys.exit(main())
