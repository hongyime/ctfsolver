"""Command sanitization module for secure tool execution."""

import shlex
import logging
import re
from typing import Optional, List, Tuple

from .command_whitelist import get_command_whitelist, SecurityLevel

logger = logging.getLogger(__name__)

# Whitelist of allowed binaries — DERIVED from the single tool registry (Phase 3).
# registry.py is the one source of truth; this stays in sync automatically.
from ..registry import derived_allowed_binaries as _derived_allowed_binaries
ALLOWED_BINARIES = set(_derived_allowed_binaries())

# Dangerous patterns to reject
DANGEROUS_PATTERNS = [
    ";", "&&", "||", "|", "`", "$(",  # Command chaining
    ">", ">>", "<",                   # Redirection
    "rm -rf", "mkfs",                 # Destructive commands
    "chmod 777",                      # Dangerous permissions
    "crontab", "systemctl",           # System modifications
    "passwd", "useradd", "userdel",   # User management
    "iptables", "ufw",                # Firewall changes
]


def sanitize_command(binary: str, args: list[str], use_quotes: bool = False) -> tuple[bool, str, list[str]]:
    """
    Sanitize a command and its arguments with whitelist validation.
    
    Args:
        binary: The binary/command to execute
        args: List of arguments
        use_quotes: If True, apply shlex.quote() to arguments (for shell=True).
                   If False (default), return raw arguments (for shell=False).
                   Note: shell=False is recommended for security.
        
    Returns:
        Tuple of (is_safe, sanitized_binary, sanitized_args)
        
    Raises:
        ValueError: If command is not allowed or contains dangerous patterns
    """
    # First check against the simple whitelist
    if binary not in ALLOWED_BINARIES:
        raise ValueError(f"Binary '{binary}' is not in the allowed list")
    
    # Then validate against the advanced whitelist system
    whitelist = get_command_whitelist(SecurityLevel.MEDIUM)
    is_valid, error_msg, validated_args = whitelist.validate_command(binary, args)
    
    if not is_valid:
        logger.warning(f"Whitelist validation failed for {binary}: {error_msg}")
        # Convert "forbidden pattern" to "dangerous pattern" for compatibility
        if "forbidden pattern" in error_msg.lower():
            raise ValueError(f"dangerous pattern detected: {error_msg}")
        raise ValueError(f"Command validation failed: {error_msg}")
    
    # Double-check for dangerous patterns (defense in depth)
    sanitized_args = []
    for arg in validated_args:
        # Check for dangerous patterns - these are blocked regardless of shell mode
        for pattern in DANGEROUS_PATTERNS:
            if pattern in arg.lower():
                logger.warning(f"Dangerous pattern '{pattern}' detected in arg: {arg}")
                raise ValueError(f"dangerous pattern detected: {pattern}")
        
        # Only apply shlex.quote when shell=True (shell=False passes raw args to exec)
        if use_quotes:
            sanitized_args.append(shlex.quote(arg))
        else:
            sanitized_args.append(arg)
    
    return True, binary, sanitized_args


def validate_tool_args(tool_name: str, args: dict) -> tuple[bool, str]:
    """
    Validate tool-specific arguments.
    
    Args:
        tool_name: Name of the tool
        args: Dictionary of arguments
        
    Returns:
        Tuple of (is_valid, error_message)
    """
    validators = {
        "nmap": _validate_nmap_args,
        "sqlmap": _validate_sqlmap_args,
        "ffuf": _validate_ffuf_args,
    }
    
    validator = validators.get(tool_name)
    if validator:
        return validator(args)
    
    return True, ""


def _validate_nmap_args(args: dict) -> tuple[bool, str]:
    """Validate nmap-specific arguments."""
    target = args.get("target", "")
    if not target:
        return False, "Target is required for nmap"
    
    # Validate IP/hostname format
    ip_pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
    hostname_pattern = r'^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$'
    
    if not (re.match(ip_pattern, target) or re.match(hostname_pattern, target)):
        return False, f"Invalid target format: {target}"
    
    return True, ""


def _validate_sqlmap_args(args: dict) -> tuple[bool, str]:
    """Validate sqlmap-specific arguments."""
    url = args.get("url", "")
    if not url:
        return False, "URL is required for sqlmap"
    
    if not url.startswith(("http://", "https://")):
        return False, "URL must start with http:// or https://"
    
    return True, ""


def _validate_ffuf_args(args: dict) -> tuple[bool, str]:
    """Validate ffuf-specific arguments."""
    url = args.get("url", "")
    if not url:
        return False, "URL is required for ffuf"
    
    return True, ""
