from __future__ import annotations

from pathlib import Path
import os


DEFAULT_OUTPUT_DIR = "challenges"
DEFAULT_CTF_IMAGE = "ctf-ai-solver:latest"
DEFAULT_DOCKERFILE = "Dockerfile.ctf-tools"
DEFAULT_CODEX_MODEL = "gpt-5.4"
DEFAULT_KIRO_MODEL = ""  # empty = let kiro-cli pick its default (avoids "Method not found" on bad names)
DEFAULT_OPENCODE_MODEL = ""  # let opencode.jsonc drive the model
STATE_FILENAME = "state.json"
HARNESS_STATE_FILENAME = ".harness-state.json"


def load_dotenv(path: Path = Path(".env")) -> None:
    if not path.exists():
        return
    import os

    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        if line.startswith("export "):
            line = line[len("export ") :].strip()
        key, value = line.split("=", 1)
        key = key.strip()
        value = value.strip().strip("'\"")
        if os.environ.get(key) in (None, ""):
            os.environ[key] = value


# ---------------------------------------------------------------------------
# Repo-root constant (config.py lives at src/ctf_harness_app/config.py)
# ---------------------------------------------------------------------------
REPO_ROOT = Path(__file__).resolve().parent.parent.parent


class WorkdirError(Exception):
    """Raised when no valid working directory can be resolved."""


def resolve_workdir(cli_flag: str | None = None) -> Path:
    """Resolve the working directory using a 5-level priority chain.

    Priority:
    1. *cli_flag* argument (if not None and non-empty)
    2. ``CTF_WORKDIR`` environment variable
    3. ``~/.ctfsolver/config.json`` key ``"workdir"`` (via ctfsolver_config)
    4. ``CTFTOOLKIT_WORKSPACE`` environment variable (backwards compat)
    5. Raise :class:`WorkdirError`

    Always returns an absolute :class:`~pathlib.Path` (`.resolve()` applied).
    Raises :class:`WorkdirError` if the resolved path is inside the repo root.
    Never creates the directory.
    """
    raw: str | None = None

    # 1. CLI flag
    if cli_flag is not None and cli_flag.strip():
        raw = cli_flag.strip()

    # 2. CTF_WORKDIR env var
    if raw is None:
        _val = os.environ.get("CTF_WORKDIR", "")
        if _val:
            raw = _val

    # 3. ~/.ctfsolver/config.json — lazy import to avoid circular deps
    if raw is None:
        try:
            import importlib.util as _ilu
            _script = REPO_ROOT / "scripts" / "ctfsolver_config.py"
            _spec = _ilu.spec_from_file_location("ctfsolver_config", _script)
            if _spec and _spec.loader:
                _mod = _ilu.module_from_spec(_spec)
                _spec.loader.exec_module(_mod)  # type: ignore[union-attr]
                _cfg_val = _mod.read_session_config().get("workdir", "")
                if _cfg_val:
                    raw = _cfg_val
        except Exception:
            pass

    # 4. CTFTOOLKIT_WORKSPACE env var (backwards compat)
    if raw is None:
        _val = os.environ.get("CTFTOOLKIT_WORKSPACE", "")
        if _val:
            raw = _val

    # 5. Nothing found — raise
    if raw is None:
        raise WorkdirError(
            "No working directory configured. "
            "Set CTF_WORKDIR, pass --workdir, or configure via the dashboard."
        )

    path = Path(raw).resolve()

    # Must be outside the repo
    try:
        path.relative_to(REPO_ROOT)
        raise WorkdirError(
            f"Working directory must be outside the repo. Got: {path}"
        )
    except ValueError:
        pass  # not a sub-path of REPO_ROOT — good

    return path
