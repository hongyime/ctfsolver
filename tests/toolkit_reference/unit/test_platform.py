"""Unit tests for platform abstraction layer."""

import pytest
import sys
from unittest.mock import patch, MagicMock

# Import platform modules
from ctf_core.platform import (
    PlatformType,
    PlatformInfo,
    get_platform,
    is_windows,
    is_macos,
    is_linux,
    is_wsl,
    get_arch,
)


class TestPlatformType:
    """Test PlatformType enum."""
    
    def test_platform_types_exist(self):
        """Test that all expected platform types exist."""
        assert hasattr(PlatformType, 'WINDOWS')
        assert hasattr(PlatformType, 'MACOS')
        assert hasattr(PlatformType, 'LINUX')
        assert hasattr(PlatformType, 'UNKNOWN')
    
    def test_platform_type_values(self):
        """Test platform type values."""
        assert PlatformType.WINDOWS.value == 'windows'
        assert PlatformType.MACOS.value == 'macos'
        assert PlatformType.LINUX.value == 'linux'
        assert PlatformType.UNKNOWN.value == 'unknown'


class TestPlatformInfo:
    """Test PlatformInfo class."""
    
    def test_platform_detection(self):
        """Test platform detection logic."""
        platform_info = PlatformInfo()
        
        # Should detect one of the known platforms
        assert platform_info.platform in [
            PlatformType.WINDOWS,
            PlatformType.MACOS,
            PlatformType.LINUX,
        ]
    
    def test_arch_detection(self):
        """Test architecture detection."""
        platform_info = PlatformInfo()
        
        # Should detect a valid architecture
        assert platform_info.arch in ['x86_64', 'arm64', 'arm', 'aarch64']
    
    def test_docker_check(self):
        """Test Docker availability check."""
        platform_info = PlatformInfo()
        
        # Should return boolean
        assert isinstance(platform_info.docker_available, bool)
    
    def test_wsl_check_on_non_windows(self):
        """Test WSL check returns False on non-Windows."""
        platform_info = PlatformInfo()
        
        if platform_info.platform != PlatformType.WINDOWS:
            assert platform_info.wsl_available is False
    
    def test_is_native(self):
        """Test is_native method."""
        platform_info = PlatformInfo()
        
        # Should return boolean
        assert isinstance(platform_info.is_native(), bool)
        
        # On non-Windows, should always be True
        if platform_info.platform != PlatformType.WINDOWS:
            assert platform_info.is_native() is True
    
    def test_get_docker_socket(self):
        """Test Docker socket path retrieval."""
        platform_info = PlatformInfo()
        socket = platform_info.get_docker_socket()
        
        # Should return a string or None
        assert socket is None or isinstance(socket, str)
        
        # Should contain appropriate socket type
        if socket:
            assert '://' in socket
    
    def test_get_workspace_path(self):
        """Test workspace path generation."""
        platform_info = PlatformInfo()
        path = platform_info.get_workspace_path('/test/path')
        
        # Should return a string
        assert isinstance(path, str)
        assert len(path) > 0
    
    def test_to_dict(self):
        """Test platform info to dictionary conversion."""
        platform_info = PlatformInfo()
        info_dict = platform_info.to_dict()
        
        # Should return a dictionary with expected keys
        assert isinstance(info_dict, dict)
        assert 'platform' in info_dict
        assert 'arch' in info_dict
        assert 'docker_available' in info_dict
        assert 'wsl_available' in info_dict
        assert 'is_native' in info_dict
        assert 'docker_socket' in info_dict


class TestPlatformHelpers:
    """Test platform helper functions."""
    
    def test_get_platform_returns_singleton(self):
        """Test that get_platform returns the same instance."""
        platform1 = get_platform()
        platform2 = get_platform()
        
        assert platform1 is platform2
    
    def test_is_windows(self):
        """Test is_windows helper."""
        result = is_windows()
        assert isinstance(result, bool)
        
        # Should match platform detection
        platform = get_platform()
        if platform.platform == PlatformType.WINDOWS:
            assert result is True
        else:
            assert result is False
    
    def test_is_macos(self):
        """Test is_macos helper."""
        result = is_macos()
        assert isinstance(result, bool)
        
        platform = get_platform()
        if platform.platform == PlatformType.MACOS:
            assert result is True
        else:
            assert result is False
    
    def test_is_linux(self):
        """Test is_linux helper."""
        result = is_linux()
        assert isinstance(result, bool)
        
        platform = get_platform()
        if platform.platform == PlatformType.LINUX:
            assert result is True
        else:
            assert result is False
    
    def test_is_wsl(self):
        """Test is_wsl helper."""
        result = is_wsl()
        assert isinstance(result, bool)
        
        # WSL can only be True on Windows
        platform = get_platform()
        if platform.platform != PlatformType.WINDOWS:
            assert result is False
    
    def test_get_arch(self):
        """Test get_arch helper."""
        arch = get_arch()
        assert isinstance(arch, str)
        assert len(arch) > 0


class TestPlatformSpecificBehavior:
    """Test platform-specific behavior."""
    
    def test_windows_platform_detection(self):
        """Test Windows platform detection with mock."""
        # Create a new PlatformInfo with mocked sys.platform
        with patch('sys.platform', 'win32'):
            platform_info = PlatformInfo()
            assert platform_info.platform == PlatformType.WINDOWS
    
    def test_macos_platform_detection(self):
        """Test macOS platform detection with mock."""
        with patch('sys.platform', 'darwin'):
            platform_info = PlatformInfo()
            assert platform_info.platform == PlatformType.MACOS
    
    def test_linux_platform_detection(self):
        """Test Linux platform detection with mock."""
        with patch('sys.platform', 'linux'):
            platform_info = PlatformInfo()
            assert platform_info.platform == PlatformType.LINUX


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
