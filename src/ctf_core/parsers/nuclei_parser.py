"""nuclei JSONL output parser — severity-grouped findings."""

import json
import logging
from typing import Any

logger = logging.getLogger(__name__)

_SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4, "unknown": 5}


def parse_nuclei_jsonl(content: str) -> dict[str, Any]:
    """Parse `nuclei -jsonl` output (one JSON object per line) into findings."""
    findings = []
    for line in content.strip().split("\n"):
        line = line.strip()
        if not line or not line.startswith("{"):
            continue
        try:
            e = json.loads(line)
        except json.JSONDecodeError:
            continue
        info = e.get("info", {})
        findings.append({
            "template": e.get("template-id", e.get("templateID", "")),
            "name": info.get("name", ""),
            "severity": (info.get("severity") or "unknown").lower(),
            "matched": e.get("matched-at", e.get("host", "")),
            "type": e.get("type", ""),
        })
    return {"findings": findings, "total": len(findings)}


def generate_summary(parsed: dict) -> str:
    findings = parsed.get("findings", [])
    if not findings:
        return "nuclei: no findings."
    lines = [f"nuclei: {len(findings)} findings", ""]
    findings.sort(key=lambda f: _SEV_ORDER.get(f["severity"], 5))
    by_sev: dict[str, list[dict]] = {}
    for f in findings:
        by_sev.setdefault(f["severity"], []).append(f)
    for sev in sorted(by_sev, key=lambda s: _SEV_ORDER.get(s, 5)):
        group = by_sev[sev]
        lines.append(f"[{sev.upper()}] ({len(group)})")
        for f in group[:15]:
            lines.append(f"  {f['name'] or f['template']} @ {f['matched']}")
        if len(group) > 15:
            lines.append(f"  ... and {len(group) - 15} more")
    return "\n".join(lines)
