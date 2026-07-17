"""Volatility memory forensics output parser."""

import re
import json
import logging
from typing import Any

logger = logging.getLogger(__name__)


def parse_volatility_output(output: str, plugin: str = "unknown") -> dict[str, Any]:
    """
    Parse Volatility output.
    
    Args:
        output: Raw text output from volatility
        plugin: Name of the volatility plugin used
        
    Returns:
        Dictionary with forensic findings
    """
    result = {
        "plugin": plugin,
        "processes": [],
        "network_connections": [],
        "files": [],
        "dlls": [],
        "users": [],
        "malware_indicators": [],
    }
    
    lines = output.strip().split('\n')
    
    for line in lines:
        line = line.strip()
        if not line or line.startswith('*') or line.startswith('-'):
            continue
        
        # Parse process list (pslist/pstree)
        if plugin in ['pslist', 'pstree']:
            # Volatility2 format: PID (PPID) Name
            proc_pattern = r'(\d+)\s+\((\d+)\)\s+(.+?)(?:\s+(\d{4}-\d{2}-\d{2}))?'
            proc_match = re.match(proc_pattern, line)
            if proc_match:
                result["processes"].append({
                    "pid": int(proc_match.group(1)),
                    "ppid": int(proc_match.group(2)),
                    "name": proc_match.group(3).strip(),
                })
        
        # Parse network connections (netscan/connections)
        elif plugin in ['netscan', 'connections']:
            # Format: Proto PID Local Address Foreign Address State
            net_pattern = r'(\w+)\s+(\d+)\s+([\d.:]+)\s+([\d.:]+)\s+(\w+)?'
            net_match = re.match(net_pattern, line)
            if net_match:
                result["network_connections"].append({
                    "protocol": net_match.group(1),
                    "pid": int(net_match.group(2)),
                    "local_address": net_match.group(3),
                    "foreign_address": net_match.group(4),
                    "state": net_match.group(5) or "UNKNOWN",
                })
        
        # Parse file scan results
        elif plugin == 'filescan':
            # Format: 0xaddress #Ref #Name Path
            file_pattern = r'(0x[0-9a-fA-F]+)\s+\d+\s+(.+)'
            file_match = re.match(file_pattern, line)
            if file_match:
                result["files"].append({
                    "address": file_match.group(1),
                    "path": file_match.group(2).strip(),
                })
        
        # Parse user information
        elif plugin == 'hashdump':
            # Format: Username:RID:LM Hash:NTLM Hash
            user_pattern = r'(.+?):(\d+):([a-f0-9]+):([a-f0-9]+)'
            user_match = re.match(user_pattern, line)
            if user_match:
                result["users"].append({
                    "username": user_match.group(1),
                    "rid": user_match.group(2),
                    "lm_hash": user_match.group(3),
                    "ntlm_hash": user_match.group(4),
                })
    
    return result


def format_for_database(parsed_data: dict[str, Any], target_id: int) -> list[dict[str, Any]]:
    """Format parsed Volatility data for database insertion."""
    actions = []
    
    # Store discovered processes
    for proc in parsed_data.get("processes", []):
        actions.append({
            "type": "process",
            "target_id": target_id,
            "data": {
                "pid": proc["pid"],
                "name": proc["name"],
                "ppid": proc.get("ppid"),
            },
        })
    
    # Store network connections
    for conn in parsed_data.get("network_connections", []):
        actions.append({
            "type": "network_connection",
            "target_id": target_id,
            "data": conn,
        })
    
    # Store user credentials
    for user in parsed_data.get("users", []):
        actions.append({
            "type": "credential",
            "target_id": target_id,
            "data": {
                "username": user["username"],
                "password_hash": user.get("ntlm_hash"),
            },
        })
    
    return actions


def generate_summary(parsed_data: dict[str, Any]) -> str:
    """Generate a human-readable summary."""
    lines = [f"Volatility {parsed_data.get('plugin', 'Analysis')} Results:", ""]
    
    processes = parsed_data.get("processes", [])
    if processes:
        lines.append(f"Processes Found: {len(processes)}")
        for proc in processes[:10]:
            lines.append(f"  - PID {proc['pid']}: {proc['name']}")
        if len(processes) > 10:
            lines.append(f"  ... and {len(processes) - 10} more")
    
    connections = parsed_data.get("network_connections", [])
    if connections:
        lines.append(f"\nNetwork Connections: {len(connections)}")
        for conn in connections[:10]:
            lines.append(f"  - {conn['protocol']} {conn['local_address']} -> {conn['foreign_address']}")
    
    users = parsed_data.get("users", [])
    if users:
        lines.append(f"\nUser Hashes: {len(users)}")
        for user in users:
            lines.append(f"  - {user['username']}: {user.get('ntlm_hash', 'N/A')[:20]}...")
    
    return "\n".join(lines)
