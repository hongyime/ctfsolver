"""Security tests for command injection resistance.

These tests verify that the CTF toolkit properly defends against command injection
attacks through multiple layers of protection:
1. Whitelist validation
2. Dangerous pattern detection
3. Shell=False in Docker container execution
"""

import pytest
from unittest.mock import patch, MagicMock
import docker.errors

from src.ctf_core.utils.sanitize import sanitize_command, validate_tool_args
from src.ctf_core.docker_runner import DockerRunner
from src.ctf_core.platform import PlatformInfo, PlatformType


class TestCommandInjectionResistance:
    """Test command injection resistance at various attack vectors."""

    # Command chaining attacks
    test_cases_command_chaining = [
        ("nmap", ["-sV", "127.0.0.1; cat /etc/passwd"], "semicolon_chaining"),
        ("nmap", ["-sV", "127.0.0.1 && cat /etc/passwd"], "double_ampersand"),
        ("nmap", ["-sV", "127.0.0.1 || cat /etc/passwd"], "double_pipe"),
        ("sqlmap", ["-u", "http://test.com; ls"], "sqlmap_semicolon"),
        ("gobuster", ["dir", "-u", "http://test.com/", "-w", "wordlist; id"], "gobuster_semicolon"),
    ]

    @pytest.mark.parametrize("tool,args,attack_type", test_cases_command_chaining)
    def test_command_chaining_blocked(self, tool, args, attack_type):
        """Test that command chaining attacks are blocked."""
        with pytest.raises(ValueError, match="dangerous pattern detected"):
            sanitize_command(tool, args)

    # Redirection attacks
    test_cases_redirection = [
        ("nmap", ["-sV", "127.0.0.1 > /tmp/pwned"], "redirection"),
        ("nmap", ["-sV", "127.0.0.1 >> /tmp/pwned"], "append_redirection"),
        ("nmap", ["-sV", "127.0.0.1 < /etc/passwd"], "input_redirection"),
    ]

    @pytest.mark.parametrize("tool,args,attack_type", test_cases_redirection)
    def test_redirection_blocked(self, tool, args, attack_type):
        """Test that redirection attacks are blocked."""
        with pytest.raises(ValueError):
            sanitize_command(tool, args)

    # Pipe attacks
    test_cases_pipe = [
        ("nmap", ["-sV", "127.0.0.1 | ls"], "pipe_chaining"),
        ("sqlmap", ["-u", "http://test.com | whoami"], "pipe_sqlmap"),
        ("gobuster", ["dir", "-u", "http://test.com/", "-x", "php | id"], "pipe_gobuster"),
    ]

    @pytest.mark.parametrize("tool,args,attack_type", test_cases_pipe)
    def test_pipe_blocked(self, tool, args, attack_type):
        """Test that pipe attacks are blocked."""
        with pytest.raises(ValueError):
            sanitize_command(tool, args)

    # Quote bypass attacks
    test_cases_quote_bypass = [
        ("nmap", ["-sV", "127.0.0.1' -e /bin/sh"], "quote_bypass_single"),
        ('nmap', ["-sV", '127.0.0.1" -e /bin/sh'], "quote_bypass_double"),
        ("nmap", ["-sV", "127.0.0.1\\ncat /etc/passwd"], "newline_bypass"),
    ]

    @pytest.mark.parametrize("tool,args,attack_type", test_cases_quote_bypass)
    def test_quote_bypass_blocked(self, tool, args, attack_type):
        """Test that quote bypass attempts are blocked."""
        # These should raise ValueError due to dangerous patterns
        with pytest.raises(ValueError):
            sanitize_command(tool, args)

    # Subshell attacks
    test_cases_subshell = [
        ("nmap", ["-sV", "$(cat /etc/passwd)"], "subshell_dollar"),
        ("nmap", ["-sV", "`cat /etc/passwd`"], "subshell_backtick"),
        ("sqlmap", ["-u", "http://test.com$(id)"], "sqlmap_subshell"),
    ]

    @pytest.mark.parametrize("tool,args,attack_type", test_cases_subshell)
    def test_subshell_blocked(self, tool, args, attack_type):
        """Test that subshell attacks are blocked."""
        with pytest.raises(ValueError):
            sanitize_command(tool, args)

    # Destructive command attacks
    test_cases_destructive = [
        ("nmap", ["-sV", "127.0.0.1; rm -rf /"], "delete_all"),
        ("sqlmap", ["-u", "http://test.com; mkfs.ext4"], "mkfs_attack"),
        ("gobuster", ["dir", "-u", "http://test.com/", "-w", "wordlist; chmod 777 /"], "chmod_attack"),
    ]

    @pytest.mark.parametrize("tool,args,attack_type", test_cases_destructive)
    def test_destructive_commands_blocked(self, tool, args, attack_type):
        """Test that destructive command attempts are blocked."""
        with pytest.raises(ValueError):
            sanitize_command(tool, args)

    # System modification attacks
    test_cases_system_mod = [
        ("nmap", ["-sV", "127.0.0.1; crontab -r"], "crontab_attack"),
        ("sqlmap", ["-u", "http://test.com; systemctl stop firewalld"], "systemctl_attack"),
        ("gobuster", ["dir", "-u", "http://test.com/", "-w", "wordlist; iptables -F"], "iptables_attack"),
    ]

    @pytest.mark.parametrize("tool,args,attack_type", test_cases_system_mod)
    def test_system_modification_blocked(self, tool, args, attack_type):
        """Test that system modification attempts are blocked."""
        with pytest.raises(ValueError):
            sanitize_command(tool, args)


class TestShellFalseSecurity:
    """Test that shell=False is properly configured for Docker execution."""

    @pytest.mark.asyncio
    async def test_docker_runner_uses_shell_false(self):
        """Test that Docker container execution uses shell=False."""
        with patch('src.ctf_core.docker_runner.docker') as mock_docker, \
             patch('src.ctf_core.docker_runner.get_platform') as mock_get_platform:

            # Set up mocks
            mock_platform_info = MagicMock(spec=PlatformInfo)
            mock_platform_info.platform = PlatformType.WINDOWS
            mock_platform_info.wsl_available = False
            mock_platform_info.get_docker_socket.return_value = None
            mock_get_platform.return_value = mock_platform_info

            mock_client = MagicMock()
            mock_docker.from_env.return_value = mock_client
            mock_docker.errors.APIError = docker.errors.APIError
            mock_docker.errors.NotFound = docker.errors.NotFound

            mock_container = MagicMock()
            mock_client.containers.run.return_value = mock_container
            mock_container.wait.return_value = {"StatusCode": 0}

            # Track the container_config passed to containers.run
            captured_config = {}

            def capture_run(**kwargs):
                captured_config.update(kwargs)
                return mock_container

            mock_client.containers.run.side_effect = capture_run

            # Mock logs to return bytes
            mock_container.logs.return_value = b"test output"

            runner = DockerRunner()
            await runner.run_tool("nmap", ["-sV", "10.0.0.1"])

            # Verify shell=False behavior: command is a list (not a string),
            # which means Docker SDK uses exec form (no shell interpretation)
            assert captured_config['command'] == ["nmap", "-sV", "10.0.0.1"], "command should be a list"
            assert isinstance(captured_config['command'], list), "command must be a list for shell=False exec form"
            assert 'shell' not in captured_config or captured_config.get('shell') is False, \
                "shell must not be True"


class TestValidCommandsAccepted:
    """Test that valid, non-malicious commands are accepted."""

    def test_valid_nmap_command(self):
        """Test that a valid nmap command is accepted."""
        is_safe, binary, args = sanitize_command("nmap", ["-sV", "127.0.0.1"])
        assert is_safe is True
        assert binary == "nmap"
        assert args == ["-sV", "127.0.0.1"]

    def test_valid_sqlmap_command(self):
        """Test that a valid sqlmap command is accepted."""
        is_safe, binary, args = sanitize_command("sqlmap", ["-u", "http://example.com/login.php"])
        assert is_safe is True
        assert binary == "sqlmap"
        assert args == ["-u", "http://example.com/login.php"]

    def test_valid_gobuster_command(self):
        """Test that a valid gobuster command is accepted."""
        is_safe, binary, args = sanitize_command(
            "gobuster", ["dir", "-u", "http://example.com/", "-w", "/usr/share/wordlists/dirb/common.txt"]
        )
        assert is_safe is True
        assert binary == "gobuster"

    def test_valid_searchsploit_command(self):
        """Test that a valid searchsploit command is accepted."""
        is_safe, binary, args = sanitize_command("searchsploit", ["nginx", "1.4.0"])
        assert is_safe is True
        assert binary == "searchsploit"

    def test_command_with_dashes_in_target(self):
        """Test that targets with dashes are accepted."""
        is_safe, binary, args = sanitize_command("nmap", ["-sV", "10-10-10-10.example.com"])
        assert is_safe is True

    def test_command_with_port(self):
        """Test that port numbers in targets are accepted."""
        is_safe, binary, args = sanitize_command("nmap", ["-p", "22", "10.10.10.10"])
        assert is_safe is True


class TestInjectionDefenseInDepth:
    """Test defense-in-depth approach for injection prevention."""

    def test_whitelist_validation_first(self):
        """Test that whitelist validation catches bad binaries first."""
        with pytest.raises(ValueError, match="not in the allowed list"):
            sanitize_command("malicious_binary", ["--help"])

    def test_dangerous_pattern_second(self):
        """Test that dangerous pattern check catches remaining threats."""
        # Even if a binary is in the whitelist, dangerous patterns should be blocked
        # This is defense-in-depth - pattern check catches injection attempts
        assert sanitize_command("nmap", ["-sV", "127.0.0.1"])[0] is True  # nmap is allowed
        with pytest.raises(ValueError):
            sanitize_command("nmap", ["-sV", "127.0.0.1; rm -rf /"])  # blocked by pattern check

    def test_no_quoting_by_default_shell_false(self):
        """Test that args are not quoted when use_quotes=False (shell=False mode)."""
        is_safe, binary, args = sanitize_command("nmap", ["-sV", "127.0.0.1"])
        # Args should be raw, not quoted - shell=False passes them directly to exec()
        assert args == ["-sV", "127.0.0.1"]
        assert "'" not in args[0] and '"' not in args[1]

    def test_quoting_available_for_shell_mode(self):
        """Test that quoting is available when use_quotes=True (for shell=True mode)."""
        # With use_quotes=True, args with spaces should be quoted for shell safety
        # Note: shell=True is NOT recommended for security reasons
        is_safe, binary, args = sanitize_command("nmap", ["-sV", "my target"], use_quotes=True)
        # The argument "my target" should be quoted since it has a space
        assert "'" in args[1] or '"' in args[1]
