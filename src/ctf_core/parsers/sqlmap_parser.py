"""SQLMap output parser."""

import re
import logging
from typing import Any

logger = logging.getLogger(__name__)


def parse_sqlmap_output(output: str) -> dict[str, Any]:
    """
    Parse SQLMap text output.
    
    Args:
        output: Raw text output from sqlmap
        
    Returns:
        Dictionary with extracted database information
    """
    result: dict[str, Any] = {
        "databases": [],
        "tables": [],
        "columns": [],
        "users": [],
        "password_hashes": [],
        "vulnerable": False,
        "injection_type": None,
        "backend_dbms": None,
    }
    
    # Extract database names line-by-line after the header (avoids ReDoS from
    # the previous nested-quantifier section regex) (P4-003).
    db_header = re.search(r"available databases \[(\d+)\]:", output, re.IGNORECASE)
    if db_header:
        for line in output[db_header.end():].splitlines():
            m = re.match(r"\s*\[\*\]\s+(.+)", line)
            if m:
                result["databases"].append(m.group(1).strip())
            elif line.strip():
                break
    
    # Extract backend DBMS
    dbms_pattern = r'back-end DBMS: (.+)'
    dbms_match = re.search(dbms_pattern, output)
    if dbms_match:
        result["backend_dbms"] = dbms_match.group(1).strip()
    
    # Check for vulnerability indicators
    vulnerable_patterns = [
        r'is vulnerable',
        r'parameter .+ appears to be',
        r'injection found',
        r'SQLMap has identified',
    ]
    
    for pattern in vulnerable_patterns:
        if re.search(pattern, output, re.IGNORECASE):
            result["vulnerable"] = True
            break
    
    # Extract injection type
    injection_pattern = r'(Type: .+)'
    injection_match = re.search(injection_pattern, output)
    if injection_match:
        result["injection_type"] = injection_match.group(1).strip()
    
    # Extract users
    user_pattern = r'\[\*\] (.+) \[(\d+) users\]'
    user_match = re.search(user_pattern, output)
    if user_match:
        db_name = user_match.group(1).strip()
        result["users"].append({"database": db_name})
    
    # Extract password hashes. Require a hash-shaped value (16+ hex chars or a
    # $-crypt hash) so we don't match arbitrary "key: value" log lines (P4-003).
    hash_pattern = r"(?m)^\s*(\S+?)\s*:\s*((?:[a-fA-F0-9]{16,})|(?:\$[\w$./]+))\s*$"
    for username, password_hash in re.findall(hash_pattern, output):
        result["password_hashes"].append({
            "username": username.strip(),
            "password_hash": password_hash.strip(),
        })
    
    return result


def format_for_database(parsed_data: dict[str, Any], target_id: int) -> list[dict[str, Any]]:
    """Format parsed SQLMap data for database insertion."""
    actions = []
    
    # Store discovered databases
    for db_name in parsed_data.get("databases", []):
        actions.append({
            "type": "database",
            "target_id": target_id,
            "data": {"name": db_name},
        })
    
    # Store credentials
    for cred in parsed_data.get("password_hashes", []):
        actions.append({
            "type": "credential",
            "target_id": target_id,
            "data": {
                "username": cred["username"],
                "password_hash": cred["password_hash"],
            },
        })
    
    return actions


def generate_summary(parsed_data: dict[str, Any]) -> str:
    """Generate a human-readable summary."""
    lines = ["SQLMap Results:", ""]
    
    if parsed_data.get("backend_dbms"):
        lines.append(f"Backend DBMS: {parsed_data['backend_dbms']}")
    
    if parsed_data.get("injection_type"):
        lines.append(f"Injection Type: {parsed_data['injection_type']}")
    
    lines.append(f"Vulnerable: {'Yes' if parsed_data.get('vulnerable') else 'No'}")
    
    databases = parsed_data.get("databases", [])
    if databases:
        lines.append(f"\nDatabases Found ({len(databases)}):")
        for db in databases:
            lines.append(f"  - {db}")
    
    password_hashes = parsed_data.get("password_hashes", [])
    if password_hashes:
        lines.append(f"\nCredentials Found ({len(password_hashes)}):")
        for cred in password_hashes:
            lines.append(f"  - {cred['username']}: {cred['password_hash'][:20]}...")
    
    return "\n".join(lines)
