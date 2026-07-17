"""Unit tests for command sanitization."""

import pytest
from src.ctf_core.utils.sanitize import sanitize_command, validate_tool_args


class TestSanitizeCommand:
    """Tests for sanitize_command function."""
    
    def test_allowed_binary_accepted(self):
        """Test that whitelisted binaries are accepted."""
        is_safe, binary, args = sanitize_command("nmap", ["-sV", "10.10.10.10"])
        assert is_safe is True
        assert binary == "nmap"
    
    def test_disallowed_binary_rejected(self):
        """Test that non-whitelisted binaries are rejected."""
        with pytest.raises(ValueError) as exc_info:
            sanitize_command("malicious_binary", [])
        assert "not in the allowed list" in str(exc_info.value)
    
    def test_dangerous_pattern_rejected(self):
        """Test that dangerous patterns are blocked."""
        with pytest.raises(ValueError) as exc_info:
            sanitize_command("nmap", ["10.10.10.10; rm -rf /"])
        assert "dangerous pattern" in str(exc_info.value)
    
    def test_command_chaining_rejected(self):
        """Test that command chaining is blocked."""
        with pytest.raises(ValueError):
            sanitize_command("nmap", ["10.10.10.10 && echo pwned"])
    
    def test_shell_injection_rejected(self):
        """Test that shell injection attempts are blocked."""
        with pytest.raises(ValueError):
            sanitize_command("nmap", ["$(whoami)"])
    
    def test_arguments_are_quoted(self):
        """Test that arguments are properly shell-quoted."""
        is_safe, binary, args = sanitize_command("nmap", ["10.10.10.10"])
        assert args == ["10.10.10.10"]
    
    def test_spaces_in_args_not_quoted_by_default(self):
        """Test that arguments with spaces are NOT quoted when use_quotes=False (shell=False mode)."""
        # Default behavior: use_quotes=False for shell=False
        is_safe, binary, args = sanitize_command("nmap", ["file with spaces.txt"])
        assert len(args) == 1
        # When shell=False (default), args go directly to exec() - quotes not needed
        assert args[0] == "file with spaces.txt"
    
    def test_spaces_in_args_quoted_when_requested(self):
        """Test that arguments with spaces ARE quoted when use_quotes=True (shell=True mode)."""
        # Explicit shell mode: use_quotes=True for shell=True
        is_safe, binary, args = sanitize_command("nmap", ["file with spaces.txt"], use_quotes=True)
        assert len(args) == 1
        # When shell=True, args need quoting for shell safety
        assert ("'" in args[0] or '"' in args[0])


class TestValidateToolArgs:
    """Tests for tool-specific argument validation."""
    
    def test_nmap_requires_target(self):
        """Test that nmap requires a target."""
        is_valid, error = validate_tool_args("nmap", {})
        assert is_valid is False
        assert "required" in error.lower()
    
    def test_nmap_valid_ip(self):
        """Test that nmap accepts valid IP addresses."""
        is_valid, error = validate_tool_args("nmap", {"target": "10.10.10.10"})
        assert is_valid is True
        assert error == ""
    
    def test_sqlmap_requires_url(self):
        """Test that sqlmap requires a URL."""
        is_valid, error = validate_tool_args("sqlmap", {})
        assert is_valid is False
    
    def test_sqlmap_valid_url(self):
        """Test that sqlmap accepts valid URLs."""
        is_valid, error = validate_tool_args("sqlmap", {"url": "http://example.com/page?id=1"})
        assert is_valid is True
    
    def test_sqlmap_invalid_url(self):
        """Test that sqlmap rejects invalid URLs."""
        is_valid, error = validate_tool_args("sqlmap", {"url": "not-a-url"})
        assert is_valid is False
