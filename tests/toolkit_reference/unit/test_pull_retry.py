"""Tests for pull retry functionality with exponential backoff."""

import pytest
from unittest.mock import patch, MagicMock
from src.ctf_core.docker_runner import (
    DockerRunner,
    MAX_PULL_RETRIES,
    INITIAL_PULL_DELAY,
    PULL_BACKOFF_MULTIPLIER
)


class TestPullRetry:
    """Test pull retry with exponential backoff."""

    @pytest.mark.asyncio
    async def test_pull_image_success_first_try(self):
        """Test that pull succeeds on first try without retry."""
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
            
            # Mock pull to succeed
            runner.client.images.pull = MagicMock()
            
            result = runner.pull_image("test/image")
            
            assert result is True
            runner.client.images.pull.assert_called_once_with("test/image")

    @pytest.mark.asyncio
    async def test_pull_image_retry_on_failure(self):
        """Test that pull retries on failure."""
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
            
            # Mock pull to fail twice then succeed
            runner.client.images.pull = MagicMock(side_effect=[
                Exception("Connection reset"),
                Exception("Timeout"),
                None  # Success on third try
            ])
            
            with patch('time.sleep') as mock_sleep:
                result = runner.pull_image("test/image")
            
            assert result is True
            assert runner.client.images.pull.call_count == 3

    @pytest.mark.asyncio
    async def test_pull_image_max_retries_exceeded(self):
        """Test that pull fails after max retries."""
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
            
            # Mock pull to always fail
            runner.client.images.pull = MagicMock(side_effect=Exception("Always fails"))
            
            with patch('time.sleep') as mock_sleep:
                result = runner.pull_image("test/image")
            
            assert result is False
            assert runner.client.images.pull.call_count == MAX_PULL_RETRIES

    @pytest.mark.asyncio
    async def test_pull_image_exponential_backoff_delays(self):
        """Test that exponential backoff delays are correct."""
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

            # Mock pull to always fail
            runner.client.images.pull = MagicMock(side_effect=Exception("Always fails"))

            # Patch _interruptible_sleep (replaces time.sleep since TASK 12 refactor)
            with patch('src.ctf_core.docker_runner._interruptible_sleep') as mock_sleep:
                result = runner.pull_image("test/image")

            # Check exponential backoff delays: 1s, 2s
            expected_delays = [
                INITIAL_PULL_DELAY * (PULL_BACKOFF_MULTIPLIER ** i)
                for i in range(MAX_PULL_RETRIES - 1)
            ]

            # _interruptible_sleep should be called MAX_PULL_RETRIES - 1 times
            assert mock_sleep.call_count == MAX_PULL_RETRIES - 1

            # Check delay values
            actual_delays = [call.args[0] for call in mock_sleep.call_args_list]
            assert actual_delays == expected_delays


class TestPullRetryConstants:
    """Test pull retry constants."""

    def test_max_pull_retries_value(self):
        """Test that MAX_PULL_RETRIES is set correctly."""
        assert MAX_PULL_RETRIES == 3

    def test_initial_pull_delay_value(self):
        """Test that INITIAL_PULL_DELAY is set correctly."""
        assert INITIAL_PULL_DELAY == 1

    def test_pull_backoff_multiplier_value(self):
        """Test that PULL_BACKOFF_MULTIPLIER is set correctly."""
        assert PULL_BACKOFF_MULTIPLIER == 2
