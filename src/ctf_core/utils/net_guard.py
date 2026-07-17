"""Network failure detection and diagnostics."""

import re
import subprocess
import ipaddress
import platform
from typing import Optional, Tuple


# Patterns indicating network failures
NETWORK_FAILURE_PATTERNS = [
    r'host down',
    r'no route to host',
    r'connection refused',
    r'network unreachable',
    r'name resolution failed',
    r'dns resolution failed',
    r'could not resolve',
    r'failed to connect',
    r'timeout exceeded',
    r'connection timed out',
]

NETWORK_PATTERN_REGEX = re.compile('|'.join(NETWORK_FAILURE_PATTERNS), re.IGNORECASE)

# Restricted network ranges (RFC 1918 private, loopback, link-local)
PRIVATE_RANGES = [
    ("10.0.0.0/8", r'^10\.'),
    ("172.16.0.0/12", r'^172\.(1[6-9]|2[0-9]|3[0-1])\.'),
    ("192.168.0.0/16", r'^192\.168\.'),
    ("127.0.0.0/8", r'^127\.'),
    ("169.254.0.0/16", r'^169\.254\.'),
]


def detect_network_failure(output: str) -> Optional[str]:
    """
    Detect network-related failures in command output.
    
    Args:
        output: Combined stdout/stderr from command
        
    Returns:
        Diagnostic message if failure detected, None otherwise
    """
    if NETWORK_PATTERN_REGEX.search(output):
        return (
            "Network connectivity issue detected. "
            "Possible causes:\n"
            "1. Target host is down or unreachable\n"
            "2. VPN connection required but not active\n"
            "3. Firewall blocking connection\n"
            "4. DNS resolution failure\n\n"
            "Recommended actions:\n"
            "- Verify VPN connection is active\n"
            "- Ping the target to check connectivity\n"
            "- Check if target IP is correct\n"
            "- Try using IP instead of hostname"
        )
    return None


def check_connection_allowed(target: str, allow_private: bool = True) -> Tuple[bool, Optional[str]]:
    """
    Check if a network connection to the target is allowed by security policy.
    
    Args:
        target: Target IP address or hostname
        allow_private: Whether to allow connections to private IP ranges
        
    Returns:
        Tuple of (allowed: bool, reason: Optional[str])
    """
    # Skip check for hostnames (can't determine IP range)
    try:
        ip = ipaddress.ip_address(target)
    except ValueError:
        # It's a hostname, allow it
        return True, None
    
    # Check against restricted ranges
    if not allow_private:
        for range_name, pattern in PRIVATE_RANGES:
            if re.match(pattern, str(ip)):
                return False, f"Connection to private network range ({range_name}) is blocked by security policy"
    
    # Check for loopback
    if ip.is_loopback:
        return False, "Connection to loopback address is not allowed"
    
    return True, None


def is_target_reachable(target: str, timeout: float = 2.0) -> bool:
    """
    Check if a target is reachable via ping.
    
    Args:
        target: Target IP address or hostname
        timeout: Timeout in seconds
        
    Returns:
        True if reachable, False otherwise
    """
    try:
        if platform.system() == "Windows":
            cmd = ["ping", "-n", "1", "-w", str(int(timeout * 1000)), target]
        else:
            cmd = ["ping", "-c", "1", "-W", str(int(timeout)), target]
        
        result = subprocess.run(cmd, capture_output=True, timeout=timeout + 5)
        return result.returncode == 0
    except (subprocess.TimeoutExpired, OSError):
        return False
