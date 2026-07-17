"""capa JSON output parser — condense capabilities into a readable summary."""

import json
import logging
from typing import Any

logger = logging.getLogger(__name__)


def _extract_json(content: str):
    """Parse a JSON object from `content`, tolerating progress/log noise around it.

    Tries a direct load, then raw_decode from the first '{' (stops at the end of the
    object, ignoring any trailing stderr/progress text the container stream merged in).
    """
    try:
        return json.loads(content)
    except json.JSONDecodeError:
        pass
    start = content.find("{")
    if start == -1:
        raise ValueError("no JSON object found")
    obj, _ = json.JSONDecoder().raw_decode(content[start:])
    return obj


def parse_capa_json(content: str) -> dict[str, Any]:
    """Parse `capa -j` output into {capabilities: [{rule, namespace, attack, mbc}], meta}."""
    caps: list[dict] = []
    meta: dict = {}
    try:
        data = _extract_json(content)
    except Exception as e:
        return {"capabilities": [], "meta": {}, "error": f"no/invalid JSON in capa output: {e}"}

    meta = data.get("meta", {})
    rules = data.get("rules", {})
    for name, rule in rules.items():
        rmeta = rule.get("meta", {})
        attack = []
        for a in rmeta.get("attack", []):
            if isinstance(a, dict):
                attack.append(f"{a.get('tactic','')}::{a.get('technique','')}".strip(":"))
            else:
                attack.append(str(a))
        mbc = []
        for m in rmeta.get("mbc", []):
            if isinstance(m, dict):
                mbc.append(f"{m.get('objective','')}::{m.get('behavior','')}".strip(":"))
            else:
                mbc.append(str(m))
        caps.append({
            "rule": rmeta.get("name", name),
            "namespace": rmeta.get("namespace", ""),
            "attack": attack,
            "mbc": mbc,
        })
    return {"capabilities": caps, "meta": meta}


def generate_summary(parsed: dict) -> str:
    if parsed.get("error"):
        return f"capa: {parsed['error']}"
    caps = parsed.get("capabilities", [])
    if not caps:
        return "capa: no capabilities identified."
    lines = [f"capa: {len(caps)} capabilities identified", ""]
    # Group by namespace for signal.
    by_ns: dict[str, list[str]] = {}
    for c in caps:
        by_ns.setdefault(c["namespace"] or "(uncategorized)", []).append(c["rule"])
    for ns in sorted(by_ns):
        lines.append(f"[{ns}]")
        for rule in by_ns[ns][:12]:
            lines.append(f"  - {rule}")
        if len(by_ns[ns]) > 12:
            lines.append(f"  ... and {len(by_ns[ns]) - 12} more")
    # Collect distinct ATT&CK IDs.
    attack = sorted({a for c in caps for a in c["attack"] if a})
    if attack:
        lines += ["", "ATT&CK: " + ", ".join(attack[:20])]
    return "\n".join(lines)
