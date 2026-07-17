"""Command whitelist system for enhanced security."""

import re
import logging
from typing import Dict, List, Optional, Tuple, Set
from dataclasses import dataclass, field
from enum import Enum

logger = logging.getLogger(__name__)


class SecurityLevel(Enum):
    """Security levels for command validation."""
    LOW = "low"          # Minimal restrictions
    MEDIUM = "medium"    # Standard restrictions
    HIGH = "high"        # Strict restrictions
    PARANOID = "paranoid" # Maximum restrictions
    
    def __lt__(self, other):
        """Compare security levels."""
        order = {
            "low": 1,
            "medium": 2,
            "high": 3,
            "paranoid": 4,
        }
        return order[self.value] < order[other.value]
    
    def __le__(self, other):
        """Compare security levels."""
        order = {
            "low": 1,
            "medium": 2,
            "high": 3,
            "paranoid": 4,
        }
        return order[self.value] <= order[other.value]
    
    def __gt__(self, other):
        """Compare security levels."""
        order = {
            "low": 1,
            "medium": 2,
            "high": 3,
            "paranoid": 4,
        }
        return order[self.value] > order[other.value]
    
    def __ge__(self, other):
        """Compare security levels."""
        order = {
            "low": 1,
            "medium": 2,
            "high": 3,
            "paranoid": 4,
        }
        return order[self.value] >= order[other.value]


@dataclass
class ToolDefinition:
    """Definition of an allowed tool."""
    name: str
    description: str
    binary: str
    allowed_flags: List[str] = field(default_factory=list)
    forbidden_flags: List[str] = field(default_factory=list)
    allowed_args_pattern: Optional[str] = None
    max_args: int = 10
    security_level: SecurityLevel = SecurityLevel.MEDIUM
    requires_sandbox: bool = True


class CommandWhitelist:
    """
    Whitelist-based command validation system.
    
    Only explicitly allowed commands and arguments can be executed.
    This provides defense-in-depth against command injection attacks.
    """
    
    def __init__(self, security_level: SecurityLevel = SecurityLevel.MEDIUM):
        """
        Initialize command whitelist.
        
        Args:
            security_level: Default security level for validation
        """
        self.security_level = security_level
        self._tools: Dict[str, ToolDefinition] = {}
        self._flag_patterns: Dict[str, re.Pattern] = {}
        self._arg_patterns: Dict[str, re.Pattern] = {}
        
        # Compile common patterns
        self._ip_pattern = re.compile(
            r'^(\d{1,3}\.){3}\d{1,3}(/[0-9]+)?$|^[0-9a-fA-F:]+$'
        )
        self._url_pattern = re.compile(
            r'^https?://[^\s]+$|^ftp://[^\s]+$'
        )
        self._file_pattern = re.compile(
            r'^[\w./-]+$'
        )
        self._port_pattern = re.compile(
            r'^\d{1,5}$'
        )
        
        self._register_default_tools()
    
    def _register_default_tools(self):
        """Register allowed tools, DERIVED from the single tool registry (Phase 3).

        registry.py is the one source of truth. Each ToolEntry becomes a
        ToolDefinition here; validate_command and all rule logic are unchanged.
        Adding a tool = add one ToolEntry in registry.py (no edits here).
        """
        from ..registry import TOOL_REGISTRY
        # Map the registry IntEnum security level to this module's string Enum by name.
        _sec_by_name = {s.name: s for s in SecurityLevel}
        for e in TOOL_REGISTRY:
            self.register_tool(ToolDefinition(
                name=e.name,
                description=f"{e.name} ({e.binary})",
                binary=e.binary,
                allowed_flags=list(e.allowed_flags),
                forbidden_flags=list(e.forbidden_flags),
                allowed_args_pattern=e.allowed_args_pattern,
                max_args=e.max_args,
                security_level=_sec_by_name.get(e.security_level.name, SecurityLevel.MEDIUM),
            ))
    def register_tool(self, tool: ToolDefinition):
        """
        Register an allowed tool.
        
        Args:
            tool: Tool definition to register
        """
        self._tools[tool.name] = tool
        logger.debug(f"Registered tool: {tool.name}")
    
    def validate_command(
        self,
        tool_name: str,
        args: List[str],
    ) -> Tuple[bool, str, List[str]]:
        """
        Validate a command against the whitelist.
        
        Args:
            tool_name: Name of the tool to execute
            args: List of command-line arguments
            
        Returns:
            Tuple of (is_valid, error_message, sanitized_args)
        """
        # Check if tool is registered
        if tool_name not in self._tools:
            return False, f"Tool '{tool_name}' is not in the whitelist", []
        
        tool = self._tools[tool_name]
        
        # Check security level
        if tool.security_level > self.security_level:
            return False, f"Tool '{tool_name}' requires higher security level", []
        
        # Check argument count
        if len(args) > tool.max_args:
            return False, f"Too many arguments (max {tool.max_args})", []
        
        # Validate each argument
        sanitized_args = []
        for i, arg in enumerate(args):
            is_valid, error = self._validate_argument(tool, arg, i)
            if not is_valid:
                return False, error, []
            sanitized_args.append(arg)
        
        return True, "", sanitized_args
    
    def _validate_argument(
        self,
        tool: ToolDefinition,
        arg: str,
        index: int,
    ) -> Tuple[bool, str]:
        """
        Validate a single argument.
        
        Args:
            tool: Tool definition
            arg: Argument to validate
            index: Argument index
            
        Returns:
            Tuple of (is_valid, error_message)
        """
        # Check for forbidden patterns
        if self._contains_forbidden_pattern(arg):
            return False, f"forbidden pattern detected in argument: {arg}"
        
        # If it's a flag, validate it
        if arg.startswith('-'):
            return self._validate_flag(tool, arg)
        
        # Otherwise validate as a regular argument
        return self._validate_regular_arg(tool, arg, index)
    
    def _contains_forbidden_pattern(self, arg: str) -> bool:
        """Check if argument contains forbidden patterns."""
        forbidden_patterns = [
            r'[;&|`$]',      # Shell metacharacters
            r'\.\.',          # Directory traversal
            r'[<>]',          # Redirection
            r'\n',            # Newlines
            r'\x00',          # Null bytes
            r'\x1b',          # Escape characters
        ]
        
        for pattern in forbidden_patterns:
            if re.search(pattern, arg):
                return True
        
        return False
    
    def _validate_flag(
        self,
        tool: ToolDefinition,
        flag: str,
    ) -> Tuple[bool, str]:
        """Validate a command-line flag."""
        # Extract flag name (without dashes)
        flag_name = flag.lstrip('-').split('=')[0]
        
        # Check if flag is explicitly forbidden
        if flag_name in tool.forbidden_flags or flag in tool.forbidden_flags:
            return False, f"Flag '{flag}' is forbidden for {tool.name}"
        
        # Check if flag is allowed (check both with and without dash)
        # Check if flag is allowed. Compare both the raw flag and the dash-stripped
        # name, against allowed entries normalised the same way, so that
        # `--file=VALUE`, `--file`, and `file` all match an allowed `--file`/`file`.
        allowed_norm = {f.lstrip('-').split('=')[0] for f in tool.allowed_flags}
        if (flag in tool.allowed_flags or flag_name in tool.allowed_flags
                or flag_name in allowed_norm):
            return True, ""
        
        # For combined short flags (e.g., -abc), check each individually
        if len(flag_name) == 1:
            # Single-char flags that are not forbidden are allowed
            return True, ""
        
        # For long flags, be more strict
        if flag_name:
            return False, f"Flag '{flag}' is not allowed for {tool.name}"
        
        return True, ""
    
    def _validate_regular_arg(
        self,
        tool: ToolDefinition,
        arg: str,
        index: int,
    ) -> Tuple[bool, str]:
        """Validate a regular (non-flag) argument."""
        # A tool's forbidden_flags may name dangerous KEYWORDS that also appear inside
        # regular args (e.g. socat EXEC:/SYSTEM: addresses). Reject those substrings in
        # non-flag args too, not just when used as a leading-dash flag.
        low = arg.lower()
        for bad in tool.forbidden_flags:
            if not bad.startswith('-') and bad.lower() in low:
                return False, f"forbidden keyword '{bad}' in argument: {arg}"
        # Check against tool's argument pattern
        if tool.allowed_args_pattern:
            pattern = re.compile(tool.allowed_args_pattern)
            if not pattern.match(arg):
                return False, f"Argument '{arg}' doesn't match allowed pattern"
        
        # Additional context-specific validation
        if index == 0 and tool.name in ['nmap', 'masscan']:
            # First arg for scanners should be target (IP, hostname, or file with spaces)
            # Allow IP addresses, hostnames, CIDR notation, and file paths with spaces
            if not self._ip_pattern.match(arg) and not self._url_pattern.match(arg):
                # Check if it's a valid hostname or file path with spaces
                hostname_pattern = re.compile(
                    r'^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$'
                )
                # Allow file paths with spaces (common in CTF challenges)
                file_path_pattern = re.compile(r'^[\w ./-]+$')
                if not hostname_pattern.match(arg) and not file_path_pattern.match(arg):
                    return False, f"Invalid target format: {arg}"
        
        return True, ""
    
    def get_allowed_tools(self) -> List[Dict]:
        """Get list of allowed tools with their details."""
        return [
            {
                'name': tool.name,
                'description': tool.description,
                'security_level': tool.security_level.value,
                'requires_sandbox': tool.requires_sandbox,
                'max_args': tool.max_args,
            }
            for tool in self._tools.values()
        ]
    
    def set_security_level(self, level: SecurityLevel):
        """Set the security level for validation."""
        self.security_level = level
        logger.info(f"Security level set to: {level.value}")


# Global whitelist instance
_command_whitelist: Optional[CommandWhitelist] = None
_whitelist_security_level: Optional[SecurityLevel] = None


def get_command_whitelist(
    security_level: SecurityLevel = SecurityLevel.MEDIUM,
) -> CommandWhitelist:
    """
    Get or create global command whitelist instance.
    
    Args:
        security_level: Security level for validation
        
    Returns:
        Command whitelist instance
    """
    global _command_whitelist, _whitelist_security_level
    
    # Create new instance if None or if security level changed
    if _command_whitelist is None or _whitelist_security_level != security_level:
        _command_whitelist = CommandWhitelist(security_level)
        _whitelist_security_level = security_level
    
    return _command_whitelist


__all__ = [
    'CommandWhitelist',
    'ToolDefinition',
    'SecurityLevel',
    'get_command_whitelist',
]
