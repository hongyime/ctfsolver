"""Tests for startup validation functionality."""

import pytest
from unittest.mock import patch, MagicMock
import docker.errors


class TestValidateEnvironment:
    """Test the validate_environment function."""

    def test_validate_environment_import(self):
        """Test that validate_environment can be imported."""
        from src.ctf_core.server import validate_environment
        assert callable(validate_environment)

    @patch('docker.from_env')
    @patch('src.ctf_core.docker_runner.docker')
    @patch('src.ctf_core.server.DockerRunner')
    def test_validate_environment_all_ok(self, mock_runner_class, mock_docker_runner, mock_from_env):
        """Test validate_environment when all checks pass."""
        from src.ctf_core.server import validate_environment
        
        # Mock Docker client
        mock_client = MagicMock()
        mock_from_env.return_value = mock_client
        mock_client.ping.return_value = True
        
        # Mock DockerRunner
        mock_runner = MagicMock()
        mock_runner.verify_images.return_value = (True, [])
        mock_runner_class.return_value = mock_runner
        
        success, issues = validate_environment()
        
        # Should pass because all checks pass
        assert success is True
        assert len(issues) == 0

    @patch('docker.from_env')
    def test_validate_environment_docker_disconnected(self, mock_from_env):
        """Test validate_environment when Docker is disconnected."""
        from src.ctf_core.server import validate_environment
        
        # Mock Docker client to raise an error
        mock_from_env.side_effect = docker.errors.APIError("Connection refused")
        
        success, issues = validate_environment()
        
        # Should fail because Docker is not connected
        assert success is False
        assert len(issues) > 0
        assert any("Docker connectivity failed" in issue for issue in issues)

    @patch('docker.from_env')
    @patch('src.ctf_core.server.DockerRunner')
    def test_validate_environment_missing_images(self, mock_runner_class, mock_from_env):
        """Test validate_environment when Docker images are missing."""
        from src.ctf_core.server import validate_environment
        
        # Mock Docker client
        mock_client = MagicMock()
        mock_from_env.return_value = mock_client
        mock_client.ping.return_value = True
        
        # Mock DockerRunner to return missing images
        mock_runner = MagicMock()
        mock_runner.verify_images.return_value = (False, ["ctftoolkit/ctf-tools", "ctftoolkit/ctf-pwn"])
        mock_runner_class.return_value = mock_runner
        
        success, issues = validate_environment()
        
        # Should fail because images are missing
        assert success is False
        assert any("Missing Docker images" in issue for issue in issues)

    @patch('docker.from_env')
    @patch('src.ctf_core.server.DockerRunner')
    def test_validate_environment_workspace_check(self, mock_runner_class, mock_from_env):
        """Test validate_environment workspace checks."""
        from src.ctf_core.server import validate_environment
        
        # Mock Docker client
        mock_client = MagicMock()
        mock_from_env.return_value = mock_client
        mock_client.ping.return_value = True
        
        # Mock DockerRunner
        mock_runner = MagicMock()
        mock_runner.verify_images.return_value = (True, [])
        mock_runner_class.return_value = mock_runner
        
        success, issues = validate_environment()
        
        # Should pass (workspace is created if it doesn't exist)
        assert success is True


class TestCheckEnvironmentTool:
    """Test the check_environment MCP tool."""

    @pytest.mark.asyncio
    async def test_check_environment_tool_import(self):
        """Test that check_environment tool can be imported."""
        from src.ctf_core.server import check_environment
        assert callable(check_environment)

    @pytest.mark.asyncio
    @patch('src.ctf_core.server.validate_environment')
    async def test_check_environment_tool_success(self, mock_validate):
        """Test check_environment tool when validation passes."""
        from src.ctf_core.server import check_environment
        
        mock_validate.return_value = (True, [])
        
        result = await check_environment()
        
        assert "PASSED" in result
        assert "FAILED" not in result

    @pytest.mark.asyncio
    @patch('src.ctf_core.server.validate_environment')
    async def test_check_environment_tool_failure(self, mock_validate):
        """Test check_environment tool when validation fails."""
        from src.ctf_core.server import check_environment
        
        mock_validate.return_value = (False, ["Docker connectivity failed", "Missing images"])
        
        result = await check_environment()
        
        assert "FAILED" in result
        assert "Docker connectivity failed" in result
        assert "Missing images" in result
