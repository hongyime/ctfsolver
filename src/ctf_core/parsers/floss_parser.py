"""FLOSS JSON output parser — group decoded/stack/static strings."""

import logging
from typing import Any

logger = logging.getLogger(__name__)


def parse_floss_json(content: str) -> dict[str, Any]:
    """Parse `floss -j` output into grouped string lists.

    FLOSS JSON shape: {"strings": {"static_strings": [...], "stack_strings": [...],
    "tight_strings": [...], "decoded_strings": [...]}} (keys vary by version).
    """
    from .capa_parser import _extract_json
    try:
        data = _extract_json(content)
    except Exception as e:
        return {"groups": {}, "error": f"no/invalid JSON in floss output: {e}"}

    strings = data.get("strings", data)
    groups: dict[str, list[str]] = {}
    for key in ("decoded_strings", "stack_strings", "tight_strings", "static_strings"):
        vals = strings.get(key, [])
        out = []
        for v in vals:
            if isinstance(v, dict):
                out.append(v.get("string") or v.get("value") or str(v))
            else:
                out.append(str(v))
        if out:
            groups[key] = out
    return {"groups": groups}


def generate_summary(parsed: dict) -> str:
    if parsed.get("error"):
        return f"floss: {parsed['error']}"
    groups = parsed.get("groups", {})
    if not groups:
        return "floss: no strings extracted."
    lines = ["floss extracted strings:", ""]
    # Prioritise decoded/stack (the interesting obfuscated ones) over static.
    order = ["decoded_strings", "stack_strings", "tight_strings", "static_strings"]
    for key in order:
        vals = groups.get(key)
        if not vals:
            continue
        lines.append(f"[{key}] ({len(vals)})")
        for s in vals[:25]:
            lines.append(f"  {s}")
        if len(vals) > 25:
            lines.append(f"  ... and {len(vals) - 25} more")
        lines.append("")
    return "\n".join(lines).strip()
