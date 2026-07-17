"""Masscan XML output parser."""

import xmltodict
import logging
from typing import Any

logger = logging.getLogger(__name__)


def parse_masscan_xml(xml_content: str) -> dict[str, Any]:
    """
    Parse Masscan XML output.
    
    Args:
        xml_content: Raw XML output from masscan -oX
        
    Returns:
        Dictionary with parsed host and port information
    """
    if "<!ENTITY" in xml_content or "<!DOCTYPE" in xml_content:
        logger.error("Rejecting Masscan XML containing entity/DTD declarations")
        return {"hosts": [], "error": "rejected: XML entity declarations not allowed"}
    try:
        data = xmltodict.parse(xml_content)
    except Exception as e:
        logger.error(f"Failed to parse Masscan XML: {e}")
        return {"hosts": [], "error": str(e)}
    
    hosts = []
    nmaprun = data.get("nmaprun", {}) or data.get("masscan", {})
    host_data = nmaprun.get("host", [])
    
    if isinstance(host_data, dict):
        host_data = [host_data]
    
    for host in host_data:
        addresses = host.get("address", [])
        if isinstance(addresses, dict):
            addresses = [addresses]
        
        ip_address = None
        for addr in addresses:
            if addr.get("@addrtype") == "ipv4":
                ip_address = addr.get("@addr")
                break
        
        if not ip_address:
            continue
        
        ports = host.get("ports", {}).get("port", [])
        if isinstance(ports, dict):
            ports = [ports]
        
        discovered_ports = []
        for port in ports:
            port_id = port.get("@portid")
            protocol = port.get("@protocol", "tcp")
            state = port.get("state", {}).get("@state", "unknown")
            
            if state == "open" and port_id:
                try:
                    port_num = int(port_id)
                except (TypeError, ValueError):
                    logger.warning(f"Skipping non-numeric masscan portid: {port_id!r}")
                    continue
                discovered_ports.append({
                    "port": port_num,
                    "protocol": protocol,
                })
        
        if discovered_ports:
            hosts.append({
                "ip_address": ip_address,
                "ports": discovered_ports,
            })
    
    return {"hosts": hosts}


def format_for_database(parsed_data: dict[str, Any], target_id: int) -> list[dict[str, Any]]:
    """Format parsed Masscan data for database insertion."""
    actions = []
    
    for host in parsed_data.get("hosts", []):
        for port_info in host.get("ports", []):
            actions.append({
                "type": "service",
                "target_id": target_id,
                "data": {
                    "port": port_info["port"],
                    "protocol": port_info["protocol"],
                },
            })
    
    return actions


def generate_summary(parsed_data: dict[str, Any]) -> str:
    """Generate a human-readable summary."""
    if not parsed_data.get("hosts"):
        return "No hosts found."
    
    lines = ["Masscan Results:", ""]
    
    for host in parsed_data["hosts"]:
        ip = host["ip_address"]
        ports = host.get("ports", [])
        
        lines.append(f"Host: {ip}")
        lines.append(f"  Open Ports: {len(ports)}")
        
        for p in sorted(ports, key=lambda x: x["port"]):
            lines.append(f"    {p['port']}/{p['protocol']}")
        
        lines.append("")
    
    return "\n".join(lines)
