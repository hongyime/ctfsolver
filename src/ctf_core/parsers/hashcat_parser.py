"""Hashcat output parser."""

import re
import logging
from typing import Any

logger = logging.getLogger(__name__)


def parse_hashcat_output(output: str) -> dict[str, Any]:
    """
    Parse Hashcat output.
    
    Args:
        output: Raw text output from hashcat
        
    Returns:
        Dictionary with cracked passwords
    """
    result = {
        "hash_mode": None,
        "hash_type": None,
        "total_hashes": 0,
        "cracked": 0,
        "progress": 0.0,
        "speed": None,
        "cracked_passwords": [],
        "status": "unknown",
    }
    
    # Extract hash mode
    mode_pattern = r'Hashmode:\s*(\d+)\s*-\s*(.+)'
    mode_match = re.search(mode_pattern, output)
    if mode_match:
        result["hash_mode"] = int(mode_match.group(1))
        result["hash_type"] = mode_match.group(2).strip()
    
    # Extract statistics
    recovered_pattern = r'Recovered........: (\d+) / (\d+)'
    recovered_match = re.search(recovered_pattern, output)
    if recovered_match:
        result["cracked"] = int(recovered_match.group(1))
        result["total_hashes"] = int(recovered_match.group(2))
    
    # Extract progress
    progress_pattern = r'Progress.........: (\d+)/(\d+)'
    progress_match = re.search(progress_pattern, output)
    if progress_match:
        denom = int(progress_match.group(2))
        if denom:
            result["progress"] = (int(progress_match.group(1)) / denom) * 100
    
    # Extract speed
    speed_pattern = r'Speed.#\d+........: (.+)'
    speed_match = re.search(speed_pattern, output)
    if speed_match:
        result["speed"] = speed_match.group(1).strip()
    
    # Extract status
    status_pattern = r'Status...........: (.+)'
    status_match = re.search(status_pattern, output)
    if status_match:
        result["status"] = status_match.group(1).strip()
    
    # Extract cracked passwords (format: hash:plaintext)
    cracked_pattern = r"^([0-9a-fA-F]{8,}|\$[\w$./]+):(.+)$"
    for line in output.split('\n'):
        cracked_match = re.match(cracked_pattern, line.strip())
        if cracked_match:
            result["cracked_passwords"].append({
                "hash": cracked_match.group(1),
                "plaintext": cracked_match.group(2),
            })
    
    return result


def format_for_database(parsed_data: dict[str, Any], target_id: int) -> list[dict[str, Any]]:
    """Format parsed Hashcat data for database insertion."""
    actions = []
    
    for cred in parsed_data.get("cracked_passwords", []):
        actions.append({
            "type": "credential",
            "target_id": target_id,
            "data": {
                "password_hash": cred["hash"],
                "cleartext": cred["plaintext"],
            },
        })
    
    return actions


def generate_summary(parsed_data: dict[str, Any]) -> str:
    """Generate a human-readable summary."""
    lines = ["Hashcat Results:", ""]
    
    if parsed_data.get("hash_type"):
        lines.append(f"Hash Type: {parsed_data['hash_type']}")
    
    lines.append(f"Total Hashes: {parsed_data.get('total_hashes', 0)}")
    lines.append(f"Cracked: {parsed_data.get('cracked', 0)}")
    lines.append(f"Progress: {parsed_data.get('progress', 0):.1f}%")
    lines.append(f"Status: {parsed_data.get('status', 'Unknown')}")
    
    if parsed_data.get("speed"):
        lines.append(f"Speed: {parsed_data['speed']}")
    
    cracked = parsed_data.get("cracked_passwords", [])
    if cracked:
        lines.append(f"\nCracked Passwords ({len(cracked)}):")
        for cred in cracked:
            lines.append(f"  - {cred['hash'][:20]}...: {cred['plaintext']}")
    
    return "\n".join(lines)
