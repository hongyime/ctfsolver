"""Unit tests for Windows platform adapter."""

import pytest
from pathlib import Path
from unittest.mock import patch, MagicMock

from ctf_core.platform.windows import WindowsAdapter, get_windows_adapter


class TestWindowsAdapterInit:
    """Test WindowsAdapter initialization."""
    
    def test_init_without_wsl(self):
        """Test initialization without WSL."""
        adapter = WindowsAdapter(is_wsl=False)
        assert adapter.is_wsl is False
    
    def test_init_with_wsl(self):
        """Test initialization with WSL."""
        adapter = WindowsAdapter(is_wsl=True)
        assert adapter.is_wsl is True


class TestWindowsPathConversion:
    """Test Windows path conversion methods."""
    
    def test_convert_to_docker_path_wsl(self):
        """Test path conversion in WSL mode."""
        adapter = WindowsAdapter(is_wsl=True)
        # In WSL, paths should be returned as-is
        path = '/home/user/workspace'
        result = adapter.convert_to_docker_path(path)
        assert result == path
    
    def test_convert_to_docker_path_native(self):
        """Test path conversion in native Windows mode."""
        adapter = WindowsAdapter(is_wsl=False)
        # Test C:\path conversion
        path = 'C:\\Users\\test\\workspace'
        result = adapter.convert_to_docker_path(path)
        # Should convert to /c/Users/test/workspace
        assert result.startswith('/c/')
        assert 'Users' in result
        assert 'workspace' in result
    
    def test_convert_from_docker_path_wsl(self):
        """Test reverse path conversion in WSL mode."""
        adapter = WindowsAdapter(is_wsl=True)
        path = '/home/user/workspace'
        result = adapter.convert_from_docker_path(path)
        assert result == path
    
    def test_convert_from_docker_path_native(self):
        """Test reverse path conversion in native Windows mode."""
        adapter = WindowsAdapter(is_wsl=False)
        # Test /c/path conversion
        path = '/c/Users/test'
        result = adapter.convert_from_docker_path(path)
        assert result.startswith('C:\\')
        assert 'Users' in result
    
    def test_convert_from_docker_path_non_unix(self):
        """Test reverse conversion with non-Unix path."""
        adapter = WindowsAdapter(is_wsl=False)
        path = 'regular_windows_path'
        result = adapter.convert_from_docker_path(path)
        # Should return as-is or handle gracefully
        assert isinstance(result, str)


class TestWindowsDockerVolumeMount:
    """Test Docker volume mount configuration."""
    
    def test_get_docker_volume_mount_wsl(self):
        """Test volume mount configuration in WSL mode."""
        adapter = WindowsAdapter(is_wsl=True)
        host_path = '/home/user/workspace'
        container_path = '/workspace'
        
        result = adapter.get_docker_volume_mount(host_path, container_path, 'rw')
        
        assert isinstance(result, dict)
        assert host_path in result
        assert result[host_path]['bind'] == container_path
        assert result[host_path]['mode'] == 'rw'
    
    def test_get_docker_volume_mount_native(self):
        """Test volume mount configuration in native Windows mode."""
        adapter = WindowsAdapter(is_wsl=False)
        host_path = 'C:\\Users\\test\\workspace'
        container_path = '/workspace'
        
        result = adapter.get_docker_volume_mount(host_path, container_path, 'rw')
        
        assert isinstance(result, dict)
        # Should have converted path as key
        assert len(result) == 1


class TestWindowsWorkspace:
    """Test Windows workspace path handling."""
    
    def test_get_default_workspace_wsl(self):
        """Test default workspace path in WSL mode."""
        adapter = WindowsAdapter(is_wsl=True)
        path = adapter.get_default_workspace()
        
        assert isinstance(path, str)
        assert 'workspace' in path.lower()
    
    def test_get_default_workspace_native(self):
        """Test default workspace path in native Windows mode."""
        adapter = WindowsAdapter(is_wsl=False)
        path = adapter.get_default_workspace()
        
        assert isinstance(path, str)
        assert 'workspace' in path.lower() or 'ctftoolkit' in path.lower()


class TestWindowsValidation:
    """Test Windows environment validation."""
    
    def test_validate_environment(self):
        """Test environment validation."""
        adapter = WindowsAdapter(is_wsl=False)
        is_valid, issues = adapter.validate_environment()
        
        assert isinstance(is_valid, bool)
        assert isinstance(issues, list)
    
    def test_validate_environment_issues_are_strings(self):
        """Test that validation issues are strings."""
        adapter = WindowsAdapter(is_wsl=False)
        _, issues = adapter.validate_environment()
        
        for issue in issues:
            assert isinstance(issue, str)


class TestWindowsSetupInstructions:
    """Test Windows setup instructions."""
    
    def test_get_setup_instructions_wsl(self):
        """Test setup instructions for WSL."""
        adapter = WindowsAdapter(is_wsl=True)
        instructions = adapter.get_setup_instructions()
        
        assert isinstance(instructions, str)
        assert len(instructions) > 0
        assert 'WSL' in instructions or 'wsl' in instructions.lower()
    
    def test_get_setup_instructions_native(self):
        """Test setup instructions for native Windows."""
        adapter = WindowsAdapter(is_wsl=False)
        instructions = adapter.get_setup_instructions()
        
        assert isinstance(instructions, str)
        assert len(instructions) > 0


class TestWindowsCommandConversion:
    """Test Windows command conversion."""
    
    def test_convert_command_wsl(self):
        """Test command conversion in WSL mode."""
        adapter = WindowsAdapter(is_wsl=True)
        command = 'ls -la'
        result = adapter.convert_command(command)
        
        # In WSL, commands should be unchanged
        assert result == command
    
    def test_convert_command_native_ls(self):
        """Test ls command conversion."""
        adapter = WindowsAdapter(is_wsl=False)
        result = adapter.convert_command('ls')
        assert result == 'dir'
    
    def test_convert_command_native_cat(self):
        """Test cat command conversion."""
        adapter = WindowsAdapter(is_wsl=False)
        result = adapter.convert_command('cat file.txt')
        assert result.startswith('type')
    
    def test_convert_command_native_grep(self):
        """Test grep command conversion."""
        adapter = WindowsAdapter(is_wsl=False)
        result = adapter.convert_command('grep pattern file.txt')
        assert result.startswith('findstr')
    
    def test_convert_command_native_unknown(self):
        """Test unknown command conversion."""
        adapter = WindowsAdapter(is_wsl=False)
        command = 'custom_command'
        result = adapter.convert_command(command)
        assert result == command


class TestWindowsEnvironmentVariables:
    """Test Windows environment variables."""
    
    def test_get_environment_variables_wsl(self):
        """Test environment variables for WSL."""
        adapter = WindowsAdapter(is_wsl=True)
        env_vars = adapter.get_environment_variables()
        
        assert isinstance(env_vars, dict)
        assert 'CTFTOOLKIT_PLATFORM' in env_vars
        assert env_vars['CTFTOOLKIT_PLATFORM'] == 'windows'
        assert 'CTFTOOLKIT_IS_WSL' in env_vars
        assert env_vars['CTFTOOLKIT_IS_WSL'] == 'true'
    
    def test_get_environment_variables_native(self):
        """Test environment variables for native Windows."""
        adapter = WindowsAdapter(is_wsl=False)
        env_vars = adapter.get_environment_variables()
        
        assert isinstance(env_vars, dict)
        assert 'CTFTOOLKIT_PLATFORM' in env_vars
        assert env_vars['CTFTOOLKIT_PLATFORM'] == 'windows'
        assert 'CTFTOOLKIT_IS_WSL' in env_vars
        assert env_vars['CTFTOOLKIT_IS_WSL'] == 'false'
        assert 'CTFTOOLKIT_SHELL' in env_vars
        assert env_vars['CTFTOOLKIT_SHELL'] == 'powershell'


class TestWindowsToolRecommendations:
    """Test Windows tool recommendations."""
    
    def test_get_tool_recommendations(self):
        """Test tool recommendations."""
        adapter = WindowsAdapter(is_wsl=False)
        recommendations = adapter.get_tool_recommendations()
        
        assert isinstance(recommendations, dict)
        assert 'shell' in recommendations
        assert 'package_manager' in recommendations
        assert 'text_editor' in recommendations


class TestGetWindowsAdapter:
    """Test get_windows_adapter convenience function."""
    
    def test_get_windows_adapter_returns_adapter(self):
        """Test that get_windows_adapter returns an adapter instance."""
        adapter = get_windows_adapter()
        assert isinstance(adapter, WindowsAdapter)


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
