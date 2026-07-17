"""Generic output parser for tools without specific parsers."""

import json
import logging
import re
from typing import Any

logger = logging.getLogger(__name__)


# Common patterns to extract from tool output
PATTERNS = {
    "ip_address": r'\b(?:\d{1,3}\.){3}\d{1,3}\b',
    "url": r'https?://[^\s<>"{}|\\^`\[\]]+',
    "email": r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}',
    "flag": r'flag\{[^}]+\}|CTF\{[^}]+\}|FLAG\{[^}]+\}',
    "hash": r"\b[a-fA-F0-9]{32}\b|\b[a-fA-F0-9]{40}\b|\b[a-fA-F0-9]{64}\b",
    "port": r"\bport\s+(\d{1,5})\b",
}


def parse_generic_output(output: str, tool_name: str = "unknown") -> dict[str, Any]:
    """
    Parse generic tool output by extracting common patterns.
    
    Args:
        output: Raw tool output
        tool_name: Name of the tool that produced the output
        
    Returns:
        Dictionary with extracted information
    """
    results = {
        "tool": tool_name,
        "raw_output": output[:10000],  # Limit stored output
        "extracted": {},
    }
    
    # Extract patterns
    for key, pattern in PATTERNS.items():
        matches = re.findall(pattern, output)
        if matches:
            results["extracted"][key] = list(set(matches))
    
    # Try JSON parsing
    try:
        json_data = json.loads(output)
        results["structured"] = json_data
    except (json.JSONDecodeError, ValueError):
        pass
    
    return results


def generate_summary(parsed_data: dict[str, Any]) -> str:
    """Generate a human-readable summary."""
    extracted = parsed_data.get("extracted", {})
    
    if not extracted:
        return "No structured data extracted."
    
    summary_lines = ["Extracted Information:", ""]
    
    for key, values in extracted.items():
        summary_lines.append(f"{key.upper()}:")
        for v in values[:10]:  # Limit per category
            summary_lines.append(f"  - {v}")
    
    return "\n".join(summary_lines)
