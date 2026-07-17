"""Feroxbuster JSONL output parser."""

import json
import logging
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)


def parse_feroxbuster_jsonl(jsonl_content: str) -> dict[str, Any]:
    """
    Parse Feroxbuster JSONL output.
    
    Args:
        jsonl_content: Raw JSONL output from feroxbuster
        
    Returns:
        Dictionary with discovered directories
    """
    directories = []
    dropped = 0
    
    for line in jsonl_content.strip().split("\n"):
        if not line.strip():
            continue
        try:
            entry = json.loads(line)
            directories.append({
                "url": entry.get("url", ""),
                "status": entry.get("status", 0),
                "wordlist": entry.get("wordlist", ""),
                "redirect": entry.get("redirect", ""),
            })
        except json.JSONDecodeError:
            dropped += 1
            continue
    
    if dropped:
        logger.warning(f"feroxbuster parser skipped {dropped} malformed JSONL line(s)")
    return {"directories": directories, "dropped_lines": dropped}


def parse_feroxbuster_file(file_path: Path) -> dict[str, Any]:
    """Parse Feroxbuster output from a file."""
    if not file_path.exists():
        return {"directories": [], "error": f"File not found: {file_path}"}
    
    with open(file_path, "r") as f:
        content = f.read()
    
    return parse_feroxbuster_jsonl(content)


def format_for_database(
    parsed_data: dict[str, Any], target_id: int
) -> list[dict[str, Any]]:
    """Format parsed data for database insertion."""
    actions = []
    
    for d in parsed_data.get("directories", []):
        actions.append({
            "type": "web_directory",
            "target_id": target_id,
            "data": {
                "path": d["url"],
                "status_code": d["status"],
            },
        })
    
    return actions


def generate_summary(parsed_data: dict[str, Any]) -> str:
    """Generate a human-readable summary."""
    directories = parsed_data.get("directories", [])
    
    if not directories:
        return "No directories found."
    
    summary_lines = [f"Feroxbuster Results ({len(directories)} found):", ""]
    
    for d in directories:
        status = d.get("status", "?")
        url = d.get("url", "")
        summary_lines.append(f"  [{status}] {url}")
    
    return "\n".join(summary_lines)
