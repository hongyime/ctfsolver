"""Hydra output parser."""

import re
import logging
from typing import Any

logger = logging.getLogger(__name__)


def parse_hydra_output(output: str) -> dict[str, Any]:
    """
    Parse Hydra brute-force output.
    
    Args:
        output: Raw text output from hydra
        
    Returns:
        Dictionary with discovered credentials
    """
    result: dict[str, Any] = {
        "target": None,
        "service": None,
        "credentials": [],
        "attempts": 0,
        "success": False,
    }
    
    # Hydra success lines look like:
    #   [22][ssh] host: 10.0.0.1   login: root   password: toor
    success_pattern = re.compile(
        r"\[(\d+)\]\[(\w+)\]\s*host:\s*(\S+)\s+login:\s*(\S+)\s+password:\s*(\S+)"
    )
    for m in success_pattern.finditer(output):
        _port, service, host, username, password = m.groups()
        result["service"] = service
        result["target"] = host
        result["credentials"].append({
            "username": username.strip(),
            "password": password.strip(),
        })
        result["success"] = True

    # Fallback: derive service/target from the '[DATA] attacking ssh://host:port/' line
    if result["service"] is None:
        svc = re.search(r"attacking\s+(\w+)://", output)
        if svc:
            result["service"] = svc.group(1)
    if result["target"] is None:
        host_m = re.search(r"attacking\s+\w+://([\w.\-]+)", output)
        if host_m:
            result["target"] = host_m.group(1)

    # Count total attempts
    attempt_pattern = r"(\d+) of (\d+) \(.*\) login"
    attempt_matches = re.findall(attempt_pattern, output)
    if attempt_matches:
        result["attempts"] = sum(int(match[0]) for match in attempt_matches)

    # Check for completion status
    if "1 of 1 target successfully completed" in output:
        result["success"] = True
    
    return result


def format_for_database(parsed_data: dict[str, Any], target_id: int) -> list[dict[str, Any]]:
    """Format parsed Hydra data for database insertion."""
    actions = []
    
    for cred in parsed_data.get("credentials", []):
        actions.append({
            "type": "credential",
            "target_id": target_id,
            "data": {
                "username": cred["username"],
                "cleartext": cred["password"],
            },
        })
    
    return actions


def generate_summary(parsed_data: dict[str, Any]) -> str:
    """Generate a human-readable summary."""
    lines = ["Hydra Brute-Force Results:", ""]
    
    if parsed_data.get("target"):
        lines.append(f"Target: {parsed_data['target']}")
    if parsed_data.get("service"):
        lines.append(f"Service: {parsed_data['service']}")
    
    lines.append(f"Attempts: {parsed_data.get('attempts', 0)}")
    lines.append(f"Success: {'Yes' if parsed_data.get('success') else 'No'}")
    
    credentials = parsed_data.get("credentials", [])
    if credentials:
        lines.append(f"\nCredentials Found ({len(credentials)}):")
        for cred in credentials:
            lines.append(f"  - {cred['username']}:{cred['password']}")
    
    return "\n".join(lines)
