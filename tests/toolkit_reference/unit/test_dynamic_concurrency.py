"""Tests for dynamic container concurrency functionality."""

import pytest
from unittest.mock import patch, MagicMock
from src.ctf_core.utils.command_whitelist import SecurityLevel


class TestDynamicConcurrency:
    """Test dynamic container concurrency based on security level."""

    @pytest.mark.asyncio
    async def test_initial_security_level(self):
        """Test that initial security level is MEDIUM."""
        from src.ctf_core.docker_runner import DockerRunner
        
        with patch('src.ctf_core.docker_runner.get_platform') as mock_platform, \
             patch('src.ctf_core.docker_runner.docker') as mock_docker:
            
            # Set up mocks
            mock_platform_info = MagicMock()
            mock_platform_info.platform = MagicMock()
            mock_platform_info.platform.value = "windows"
            mock_platform_info.wsl_available = False
            mock_platform_info.get_docker_socket.return_value = None
            mock_platform.return_value = mock_platform_info
            
            mock_docker_client = MagicMock()
            mock_docker.from_env.return_value = mock_docker_client
            mock_docker.errors.APIError = Exception
            mock_docker.errors.NotFound = Exception
            
            runner = DockerRunner()
            
            assert runner.get_security_level() == SecurityLevel.MEDIUM

    @pytest.mark.asyncio
    async def test_set_security_level_low(self):
        """Test setting security level to LOW."""
        from src.ctf_core.docker_runner import DockerRunner, SECURITY_CONCURRENCY_MAP
        
        with patch('src.ctf_core.docker_runner.get_platform') as mock_platform, \
             patch('src.ctf_core.docker_runner.docker') as mock_docker:
            
            mock_platform_info = MagicMock()
            mock_platform_info.platform.value = "windows"
            mock_platform_info.wsl_available = False
            mock_platform_info.get_docker_socket.return_value = None
            mock_platform.return_value = mock_platform_info
            
            mock_docker_client = MagicMock()
            mock_docker.from_env.return_value = mock_docker_client
            mock_docker.errors.APIError = Exception
            mock_docker.errors.NotFound = Exception
            
            runner = DockerRunner()
            runner.set_security_level(SecurityLevel.LOW)
            
            assert runner.get_security_level() == SecurityLevel.LOW
            assert runner.get_concurrency_limit() == 10

    @pytest.mark.asyncio
    async def test_set_security_level_high(self):
        """Test setting security level to HIGH."""
        from src.ctf_core.docker_runner import DockerRunner
        
        with patch('src.ctf_core.docker_runner.get_platform') as mock_platform, \
             patch('src.ctf_core.docker_runner.docker') as mock_docker:
            
            mock_platform_info = MagicMock()
            mock_platform_info.platform.value = "windows"
            mock_platform_info.wsl_available = False
            mock_platform_info.get_docker_socket.return_value = None
            mock_platform.return_value = mock_platform_info
            
            mock_docker_client = MagicMock()
            mock_docker.from_env.return_value = mock_docker_client
            mock_docker.errors.APIError = Exception
            mock_docker.errors.NotFound = Exception
            
            runner = DockerRunner()
            runner.set_security_level(SecurityLevel.HIGH)
            
            assert runner.get_security_level() == SecurityLevel.HIGH
            assert runner.get_concurrency_limit() == 3

    @pytest.mark.asyncio
    async def test_set_security_level_paranoid(self):
        """Test setting security level to PARANOID."""
        from src.ctf_core.docker_runner import DockerRunner
        
        with patch('src.ctf_core.docker_runner.get_platform') as mock_platform, \
             patch('src.ctf_core.docker_runner.docker') as mock_docker:
            
            mock_platform_info = MagicMock()
            mock_platform_info.platform.value = "windows"
            mock_platform_info.wsl_available = False
            mock_platform_info.get_docker_socket.return_value = None
            mock_platform.return_value = mock_platform_info
            
            mock_docker_client = MagicMock()
            mock_docker.from_env.return_value = mock_docker_client
            mock_docker.errors.APIError = Exception
            mock_docker.errors.NotFound = Exception
            
            runner = DockerRunner()
            runner.set_security_level(SecurityLevel.PARANOID)
            
            assert runner.get_security_level() == SecurityLevel.PARANOID
            assert runner.get_concurrency_limit() == 1


class TestSecurityConcurrencyMap:
    """Test the security concurrency mapping."""

    def test_concurrency_map_values(self):
        """Test that concurrency map has correct values."""
        from src.ctf_core.docker_runner import SECURITY_CONCURRENCY_MAP
        
        assert SECURITY_CONCURRENCY_MAP[SecurityLevel.LOW] == 10
        assert SECURITY_CONCURRENCY_MAP[SecurityLevel.MEDIUM] == 5
        assert SECURITY_CONCURRENCY_MAP[SecurityLevel.HIGH] == 3
        assert SECURITY_CONCURRENCY_MAP[SecurityLevel.PARANOID] == 1

    def test_higher_security_less_concurrency(self):
        """Test that higher security levels have less concurrency."""
        from src.ctf_core.docker_runner import SECURITY_CONCURRENCY_MAP
        
        # LOW > MEDIUM > HIGH > PARANOID in terms of concurrency
        assert SECURITY_CONCURRENCY_MAP[SecurityLevel.LOW] > SECURITY_CONCURRENCY_MAP[SecurityLevel.MEDIUM]
        assert SECURITY_CONCURRENCY_MAP[SecurityLevel.MEDIUM] > SECURITY_CONCURRENCY_MAP[SecurityLevel.HIGH]
        assert SECURITY_CONCURRENCY_MAP[SecurityLevel.HIGH] > SECURITY_CONCURRENCY_MAP[SecurityLevel.PARANOID]
