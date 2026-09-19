from __future__ import annotations

from pathlib import Path


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
