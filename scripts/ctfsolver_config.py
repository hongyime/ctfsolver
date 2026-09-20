"""~/.ctfsolver/config.json read/write helpers.

Standalone module — no ctf_harness_app dependency.
Keys: workdir, platform, platform_url, platform_username.
Never stores passwords, tokens, or secrets.
"""
from __future__ import annotations

import json
from pathlib import Path

CONFIG_PATH = Path.home() / ".ctfsolver" / "config.json"

_ALLOWED_KEYS = frozenset({"workdir", "platform", "platform_url", "platform_username"})


def read_session_config() -> dict:
    """Read ~/.ctfsolver/config.json; return {} if missing or malformed."""
    try:
        return json.loads(CONFIG_PATH.read_text(encoding="utf-8"))
    except Exception:
        return {}


def write_session_config(updates: dict) -> None:
    """Merge *updates* into ~/.ctfsolver/config.json, creating it if needed.

    Only keys in ``_ALLOWED_KEYS`` are persisted.  Passwords and tokens are
    silently ignored.  Write is atomic: content is first written to a ``.tmp``
    sibling file, then renamed into place.
    """
    CONFIG_PATH.parent.mkdir(parents=True, exist_ok=True)

    current = read_session_config()

    for key, value in updates.items():
        if key in _ALLOWED_KEYS:
            current[key] = value

    tmp_path = CONFIG_PATH.with_suffix(".tmp")
    tmp_path.write_text(json.dumps(current, indent=2), encoding="utf-8")
    tmp_path.replace(CONFIG_PATH)
