"""SearchSploit JSON output parser."""

import json
import logging
from typing import Any

logger = logging.getLogger(__name__)


def parse_searchsploit_json(json_content: str) -> dict[str, Any]:
    """
    Parse SearchSploit JSON output.
    
    Args:
        json_content: Raw JSON output from searchsploit --json
        
    Returns:
        Dictionary with exploit information
    """
    try:
        data = json.loads(json_content)
    except json.JSONDecodeError:
        logger.warning("searchsploit output was not valid JSON; returning raw output")
        return {"exploits": [], "raw_output": json_content}
    
    exploits = []
    
    # Handle different JSON structures
    if isinstance(data, dict):
        if "RESULTS" in data:
            results = data["RESULTS"]
            if isinstance(results, dict):
                results = list(results.values())
            exploits.extend(results)
        elif "exploits" in data:
            exploits.extend(data["exploits"])
    elif isinstance(data, list):
        exploits.extend(data)
    
    parsed_exploits = []
    for exploit in exploits:
        parsed_exploits.append({
            "title": exploit.get("title", "Unknown"),
            "cve": exploit.get("CVE", ""),
            "path": exploit.get("file", exploit.get("path", "")),
            "date": exploit.get("date", ""),
            "type": exploit.get("type", ""),
            "port": exploit.get("port", ""),
        })
    
    return {"exploits": parsed_exploits}


def format_for_database(
    parsed_data: dict[str, Any], target_id: int
) -> list[dict[str, Any]]:
    """Format parsed data for database insertion."""
    actions = []
    
    for exploit in parsed_data.get("exploits", []):
        actions.append({
            "type": "exploit",
            "target_id": target_id,
            "data": {
                "cve_id": exploit.get("cve"),
                "exploit_path": exploit.get("path"),
            },
        })
    
    return actions


def generate_summary(parsed_data: dict[str, Any]) -> str:
    """Generate a human-readable summary."""
    exploits = parsed_data.get("exploits", [])
    
    if not exploits:
        return "No exploits found."
    
    summary_lines = [f"SearchSploit Results ({len(exploits)} found):", ""]
    
    for e in exploits[:10]:  # Limit to 10
        title = e.get("title", "Unknown")
        cve = e.get("cve", "")
        
        line = f"- {title}"
        if cve:
            line += f" ({cve})"
        summary_lines.append(line)
    
    if len(exploits) > 10:
        summary_lines.append(f"... and {len(exploits) - 10} more")
    
    return "\n".join(summary_lines)
