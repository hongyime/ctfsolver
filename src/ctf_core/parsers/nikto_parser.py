"""Nikto output parser."""

import re
import json
import logging
from typing import Any

logger = logging.getLogger(__name__)


def parse_nikto_output(output: str) -> dict[str, Any]:
    """
    Parse Nikto text or JSON output.
    
    Args:
        output: Raw output from nikto
        
    Returns:
        Dictionary with vulnerability findings
    """
    result: dict[str, Any] = {
        "target": None,
        "port": None,
        "vulnerabilities": [],
        "server_info": {},
        "errors": [],
    }
    
    # Try JSON parsing first
    try:
        json_data = json.loads(output)
        if isinstance(json_data, dict):
            result["target"] = json_data.get("host")
            result["port"] = json_data.get("port")
            
            vulnerabilities = json_data.get("vulnerabilities", [])
            for vuln in vulnerabilities:
                result["vulnerabilities"].append({
                    "id": vuln.get("#"),
                    "method": vuln.get("method"),
                    "url": vuln.get("url"),
                    "message": vuln.get("msg"),
                })
            return result
    except (json.JSONDecodeError, TypeError):
        pass
    
    # Parse text output
    # Extract target info
    target_pattern = r'Starting Host: (.+)'
    target_match = re.search(target_pattern, output)
    if target_match:
        result["target"] = target_match.group(1).strip()
    
    port_pattern = r'Port: (\d+)'
    port_match = re.search(port_pattern, output)
    if port_match:
        result["port"] = int(port_match.group(1))
    
    # Extract server info
    server_pattern = r'Server: (.+)'
    server_match = re.search(server_pattern, output)
    if server_match:
        result["server_info"]["server"] = server_match.group(1).strip()
    
    # Extract vulnerabilities (Nikto findings are "+ <message>"), skipping the
    # informational "+ Target IP / Server / Start Time" header lines (P4-005).
    _info_prefixes = (
        "Target IP", "Target Hostname", "Target Port", "Target:",
        "Start Time", "End Time", "Server:", "Server banner", "Root page",
        "Hostname", "SSL Info", "host(s) tested",
    )
    for match in re.findall(r"\+ (.+)", output):
        msg = match.strip()
        if not msg or msg.startswith(_info_prefixes):
            continue
        result["vulnerabilities"].append({"message": msg})
    
    # Extract errors
    error_pattern = r"ERROR:\s*(.+)"
    error_matches = re.findall(error_pattern, output)
    for match in error_matches:
        result["errors"].append(match.strip())
    
    return result


def format_for_database(parsed_data: dict[str, Any], target_id: int) -> list[dict[str, Any]]:
    """Format parsed Nikto data for database insertion."""
    actions = []
    
    for vuln in parsed_data.get("vulnerabilities", []):
        actions.append({
            "type": "vulnerability",
            "target_id": target_id,
            "data": {
                "description": vuln.get("message", ""),
                "url": vuln.get("url"),
            },
        })
    
    return actions


def generate_summary(parsed_data: dict[str, Any]) -> str:
    """Generate a human-readable summary."""
    lines = ["Nikto Scan Results:", ""]
    
    if parsed_data.get("target"):
        lines.append(f"Target: {parsed_data['target']}")
    if parsed_data.get("port"):
        lines.append(f"Port: {parsed_data['port']}")
    
    server = parsed_data.get("server_info", {}).get("server")
    if server:
        lines.append(f"Server: {server}")
    
    vulnerabilities = parsed_data.get("vulnerabilities", [])
    lines.append(f"\nVulnerabilities Found: {len(vulnerabilities)}")
    
    for i, vuln in enumerate(vulnerabilities[:20], 1):
        message = vuln.get("message", str(vuln))
        lines.append(f"  {i}. {message}")
    
    if len(vulnerabilities) > 20:
        lines.append(f"  ... and {len(vulnerabilities) - 20} more")
    
    return "\n".join(lines)
