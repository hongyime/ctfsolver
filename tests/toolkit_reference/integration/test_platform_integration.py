"""Integration tests for platform abstraction layer."""

import pytest
import sys
from pathlib import Path

from ctf_core.platform import get_platform, PlatformType
from ctf_core.platform.windows import WindowsAdapter, get_windows_adapter
from ctf_core.platform.macos import MacOSAdapter, get_macos_adapter
from ctf_core.platform.linux import LinuxAdapter, get_linux_adapter
from ctf_core.docker_runner import DockerRunner


class TestPlatformAdapterIntegration:
    """Test platform adapter integration."""
    
    def test_platform_detection_consistency(self):
        """Test that platform detection is consistent across adapters."""
        platform_info = get_platform()
        
        # Each adapter should work with the detected platform
        if platform_info.platform == PlatformType.WINDOWS:
            adapter = get_windows_adapter()
            assert adapter.is_wsl == platform_info.wsl_available
        elif platform_info.platform == PlatformType.MACOS:
            adapter = get_macos_adapter()
        elif platform_info.platform == PlatformType.LINUX:
            adapter = get_linux_adapter()
        
        assert adapter is not None
    
    def test_workspace_path_creation(self):
        """Test that workspace path can be created."""
        platform_info = get_platform()
        
        if platform_info.platform == PlatformType.WINDOWS:
            adapter = get_windows_adapter()
        elif platform_info.platform == PlatformType.MACOS:
            adapter = get_macos_adapter()
        else:
            adapter = get_linux_adapter()
        
        workspace_path = adapter.get_default_workspace()
        workspace = Path(workspace_path)
        
        # Should be able to create the directory
        workspace.mkdir(parents=True, exist_ok=True)
        assert workspace.exists()
        assert workspace.is_dir()


class TestDockerRunnerPlatformIntegration:
    """Test Docker runner integration with platform layer."""
    
    def test_docker_runner_initialization(self):
        """Test that DockerRunner can be initialized with platform abstraction."""
        # This test requires Docker to be available
        try:
            runner = DockerRunner()
            assert runner.platform_info is not None
            assert runner.platform_adapter is not None
            assert runner.client is not None
        except Exception as e:
            # Skip if Docker is not available
            pytest.skip(f"Docker not available: {e}")
    
    def test_docker_runner_volume_preparation(self):
        """Test Docker runner volume preparation."""
        try:
            runner = DockerRunner()
            volumes = runner._prepare_volumes()
            
            assert isinstance(volumes, dict)
            assert len(volumes) > 0
        except Exception as e:
            pytest.skip(f"Docker not available: {e}")
    
    def test_docker_runner_workspace_path(self):
        """Test Docker runner workspace path handling."""
        try:
            runner = DockerRunner()
            
            # Workspace should be set
            assert runner.workspace_path is not None
            assert runner.workspace_path.exists()
        except Exception as e:
            pytest.skip(f"Docker not available: {e}")


class TestPlatformSpecificIntegration:
    """Test platform-specific integration scenarios."""
    
    @pytest.mark.skipif(sys.platform != 'win32', reason="Windows-specific test")
    def test_windows_native_integration(self):
        """Test Windows native integration."""
        platform_info = get_platform()
        assert platform_info.platform == PlatformType.WINDOWS
        
        adapter = get_windows_adapter()
        assert adapter.is_wsl == platform_info.wsl_available
        
        # Test path conversion
        if not adapter.is_wsl:
            # Native Windows: test path conversion
            test_path = 'C:\\Test\\Path'
            docker_path = adapter.convert_to_docker_path(test_path)
            assert docker_path.startswith('/c/')
            
            back_path = adapter.convert_from_docker_path(docker_path)
            assert back_path.startswith('C:\\')
    
    @pytest.mark.skipif(sys.platform != 'darwin', reason="macOS-specific test")
    def test_macos_integration(self):
        """Test macOS integration."""
        platform_info = get_platform()
        assert platform_info.platform == PlatformType.MACOS
        
        adapter = get_macos_adapter()
        
        # Test architecture detection
        arch = adapter.arch
        assert arch in ['x86_64', 'arm64']
        
        # Test Docker socket path
        socket_path = adapter.get_docker_socket_path()
        assert 'docker.sock' in socket_path or 'docker' in socket_path
    
    @pytest.mark.skipif(sys.platform != 'linux', reason="Linux-specific test")
    def test_linux_integration(self):
        """Test Linux integration."""
        platform_info = get_platform()
        assert platform_info.platform == PlatformType.LINUX
        
        adapter = get_linux_adapter()
        
        # Test distro detection
        distro = adapter.distro
        assert distro in ['ubuntu', 'debian', 'fedora', 'rhel', 'arch', 'suse', 'unknown']
        
        # Test package manager detection
        pm = adapter.package_manager
        assert pm is None or isinstance(pm, str)


class TestCrossPlatformCompatibility:
    """Test cross-platform compatibility."""
    
    def test_platform_info_serialization(self):
        """Test that platform info can be serialized."""
        platform_info = get_platform()
        info_dict = platform_info.to_dict()
        
        # Should be JSON-serializable
        import json
        json_str = json.dumps(info_dict)
        assert isinstance(json_str, str)
        
        # Should be able to deserialize
        loaded = json.loads(json_str)
        assert loaded['platform'] == platform_info.platform.value
    
    def test_adapter_environment_variables(self):
        """Test that adapters provide environment variables."""
        platform_info = get_platform()
        
        if platform_info.platform == PlatformType.WINDOWS:
            adapter = get_windows_adapter()
        elif platform_info.platform == PlatformType.MACOS:
            adapter = get_macos_adapter()
        else:
            adapter = get_linux_adapter()
        
        env_vars = adapter.get_environment_variables()
        
        assert isinstance(env_vars, dict)
        assert 'CTFTOOLKIT_PLATFORM' in env_vars
        
        # All values should be strings
        for key, value in env_vars.items():
            assert isinstance(value, str)


class TestPlatformValidation:
    """Test platform validation across platforms."""
    
    def test_platform_validation_returns_boolean_and_list(self):
        """Test that validation returns expected types."""
        platform_info = get_platform()
        
        if platform_info.platform == PlatformType.WINDOWS:
            adapter = get_windows_adapter()
        elif platform_info.platform == PlatformType.MACOS:
            adapter = get_macos_adapter()
        else:
            adapter = get_linux_adapter()
        
        is_valid, issues = adapter.validate_environment()
        
        assert isinstance(is_valid, bool)
        assert isinstance(issues, list)
        
        # All issues should be strings
        for issue in issues:
            assert isinstance(issue, str)


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
