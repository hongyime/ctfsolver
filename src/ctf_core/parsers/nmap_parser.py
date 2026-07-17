"""Nmap XML output parser for CTF state management."""

import xmltodict
import logging
from typing import Any, Optional

logger = logging.getLogger(__name__)


def parse_nmap_xml(xml_content: str) -> dict[str, Any]:
    """
    Parse Nmap XML output into structured data.
    
    Args:
        xml_content: Raw XML output from nmap -oX
        
    Returns:
        Dictionary with parsed host and service information
    """
    # XXE / billion-laughs guard (P4-007): nmap never emits DTD/entity declarations.
    if "<!ENTITY" in xml_content or "<!DOCTYPE" in xml_content:
        logger.error("Rejecting Nmap XML containing entity/DTD declarations")
        return {"hosts": [], "error": "rejected: XML entity declarations not allowed"}
    try:
        data = xmltodict.parse(xml_content)
    except Exception as e:
        logger.error(f"Failed to parse Nmap XML: {e}")
        return {"hosts": [], "error": str(e)}
    
    hosts = []
    nmaprun = data.get("nmaprun", {})
    host_data = nmaprun.get("host", [])
    
    if isinstance(host_data, dict):
        host_data = [host_data]
    
    for host in host_data:
        host_info = parse_host(host)
        if host_info:
            hosts.append(host_info)
    
    return {"hosts": hosts}


def parse_host(host: dict) -> Optional[dict[str, Any]]:
    """Parse a single host entry from Nmap output."""
    addresses = host.get("address", [])
    if isinstance(addresses, dict):
        addresses = [addresses]
    
    ip_address = None
    hostname = None
    
    for addr in addresses:
        addr_type = addr.get("@addrtype", "")
        if addr_type == "ipv4":
            ip_address = addr.get("@addr")
    
    # Extract hostname from hostnames element
    hostnames = host.get("hostnames", {})
    if isinstance(hostnames, dict):
        hostname_entry = hostnames.get("hostname")
        if isinstance(hostname_entry, dict):
            hostname = hostname_entry.get("@name")
        elif isinstance(hostname_entry, list) and hostname_entry:
            hostname = hostname_entry[0].get("@name")
    
    if not ip_address:
        return None
    
    # Get OS information
    os_info = None
    osmatch = host.get("os", {}).get("osmatch", [])
    if isinstance(osmatch, dict):
        osmatch = [osmatch]
    if osmatch:
        os_info = osmatch[0].get("@name")
    
    # Get services/ports
    ports = host.get("ports", {}).get("port", [])
    if isinstance(ports, dict):
        ports = [ports]
    
    services = []
    for port in ports:
        service = parse_port(port)
        if service:
            services.append(service)
    
    return {
        "ip_address": ip_address,
        "hostname": hostname,
        "os_type": os_info,
        "services": services,
    }


def parse_port(port: dict) -> Optional[dict[str, Any]]:
    """Parse a single port entry from Nmap output."""
    port_id = port.get("@portid")
    protocol = port.get("@protocol", "tcp")
    
    if not port_id:
        return None
    
    state = port.get("state", {})
    state_status = state.get("@state", "unknown")
    
    if state_status != "open":
        return None
    
    service_info = port.get("service", {})
    service_name = service_info.get("@name")
    banner = service_info.get("@product", "")
    
    if service_info.get("@version"):
        banner += f" {service_info.get('@version')}"
    if service_info.get("@extrainfo"):
        banner += f" ({service_info.get('@extrainfo')})"
    
    try:
        port_num = int(port_id)
    except (TypeError, ValueError):
        logger.warning(f"Skipping non-numeric portid: {port_id!r}")
        return None

    return {
        "port": port_num,
        "protocol": protocol,
        "service_name": service_name,
        "banner": banner.strip() if banner else None,
    }


def format_for_database(parsed_data: dict[str, Any]) -> list[dict[str, Any]]:
    """Format parsed Nmap data for database insertion."""
    actions = []
    
    for host in parsed_data.get("hosts", []):
        actions.append({
            "type": "target",
            "data": {
                "ip_address": host["ip_address"],
                "hostname": host.get("hostname"),
                "os_type": host.get("os_type"),
            }
        })
        
        for service in host.get("services", []):
            actions.append({
                "type": "service",
                "ip_address": host["ip_address"],
                "data": service,
            })
    
    return actions


def generate_summary(parsed_data: dict[str, Any]) -> str:
    """Generate a human-readable summary of Nmap results."""
    if not parsed_data.get("hosts"):
        return "No hosts found."
    
    summary_lines = ["Nmap Scan Results:", ""]
    
    for host in parsed_data["hosts"]:
        ip = host["ip_address"]
        hostname = host.get("hostname", "")
        os_type = host.get("os_type", "Unknown")
        
        host_str = f"Host: {ip}"
        if hostname:
            host_str += f" ({hostname})"
        summary_lines.append(host_str)
        summary_lines.append(f"  OS: {os_type}")
        summary_lines.append("  Open Ports:")
        
        for service in host.get("services", []):
            port = service["port"]
            proto = service["protocol"]
            name = service.get("service_name", "unknown")
            banner = service.get("banner", "")
            
            service_str = f"    {port}/{proto}: {name}"
            if banner:
                service_str += f" - {banner}"
            summary_lines.append(service_str)
        
        summary_lines.append("")
    
    return "\n".join(summary_lines)
