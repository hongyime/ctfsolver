"""ffuf JSON output parser — status-grouped hits."""

import logging
from typing import Any

logger = logging.getLogger(__name__)


def parse_ffuf_json(content: str) -> dict[str, Any]:
    """Parse ffuf JSON into {hits: [{url, status, length, words}], total}.

    ffuf has TWO JSON shapes:
      * aggregate (`-o file -of json`): a single {"results": [...]} object.
      * streaming (`-json`): one JSON object PER matched result (JSONL), each
        {"input": {"FUZZ": <base64>}, "url": ..., "status": ...}.
    This handles both.
    """
    import base64 as _b64
    import json as _json
    from .capa_parser import _extract_json

    def _mk(r: dict) -> dict:
        url = r.get("url", "")
        if not url:
            fuzz = (r.get("input") or {}).get("FUZZ", "")
            try:
                url = _b64.b64decode(fuzz).decode("utf-8", "replace") if fuzz else ""
            except Exception:
                url = fuzz
        return {"url": url, "status": r.get("status"), "length": r.get("length"),
                "words": r.get("words"), "redirect": r.get("redirectlocation", "")}

    hits = []
    # Aggregate form first.
    try:
        data = _extract_json(content)
        if isinstance(data, dict) and "results" in data:
            hits = [_mk(r) for r in data.get("results", [])]
            return {"hits": hits, "total": len(hits)}
    except Exception:
        data = None
    # Streaming JSONL form: one result object per line.
    for line in content.strip().split("\n"):
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            r = _json.loads(line)
        except Exception:
            continue
        if "url" in r or "input" in r:
            hits.append(_mk(r))
    if not hits and data is None:
        return {"hits": [], "error": "no/invalid JSON in ffuf output"}
    return {"hits": hits, "total": len(hits)}


def generate_summary(parsed: dict) -> str:
    if parsed.get("error"):
        return f"ffuf: {parsed['error']}"
    hits = parsed.get("hits", [])
    if not hits:
        return "ffuf: no results."
    lines = [f"ffuf: {len(hits)} hits", ""]
    by_status: dict[Any, list[dict]] = {}
    for h in hits:
        by_status.setdefault(h["status"], []).append(h)
    for status in sorted(by_status, key=lambda s: (s is None, s)):
        group = by_status[status]
        lines.append(f"[{status}] ({len(group)})")
        for h in group[:20]:
            extra = f" -> {h['redirect']}" if h.get("redirect") else ""
            lines.append(f"  {h['url']} (len={h['length']}){extra}")
        if len(group) > 20:
            lines.append(f"  ... and {len(group) - 20} more")
    return "\n".join(lines)
