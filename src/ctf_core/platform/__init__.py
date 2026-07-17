"""Platform abstraction layer for cross-platform CTF Toolkit."""

import sys
import os
from typing import Optional
from enum import Enum


class PlatformType(Enum):
    """Supported platform types."""
    WINDOWS = "windows"
    MACOS = "macos"
    LINUX = "linux"
    UNKNOWN = "unknown"


class PlatformInfo:
    """Platform information and capabilities."""
    
    def __init__(self):
        self.platform = self._detect_platform()
        self.arch = self._detect_arch()
        self.docker_available = self._check_docker()
        self.wsl_available = self._check_wsl() if self.platform == PlatformType.WINDOWS else False
        
    def _detect_platform(self) -> PlatformType:
        """Detect current platform."""
        if sys.platform.startswith('win'):
            return PlatformType.WINDOWS
        elif sys.platform.startswith('darwin'):
            return PlatformType.MACOS
        elif sys.platform.startswith('linux'):
            return PlatformType.LINUX
        else:
            return PlatformType.UNKNOWN
    
    def _detect_arch(self) -> str:
        """Detect CPU architecture."""
        import platform
        machine = platform.machine().lower()
        if 'x86_64' in machine or 'amd64' in machine:
            return 'x86_64'
        elif 'arm64' in machine or 'aarch64' in machine:
            return 'arm64'
        elif 'arm' in machine:
            return 'arm'
        else:
            return machine
    
    def _check_docker(self) -> bool:
        """Check if Docker is available."""
        try:
            import docker
            client = docker.from_env()
            client.ping()
            return True
        except Exception:
            return False
    
    def _check_wsl(self) -> bool:
        """Check if running in WSL."""
        if self.platform != PlatformType.WINDOWS:
            return False
        
        # Check for WSL specific indicators
        try:
            with open('/proc/version', 'r') as f:
                version_info = f.read().lower()
                return 'microsoft' in version_info or 'wsl' in version_info
        except Exception:
            return False
    
    def is_native(self) -> bool:
        """Check if running natively (not in WSL)."""
        if self.platform == PlatformType.WINDOWS:
            return not self.wsl_available
        return True
    
    def get_docker_socket(self) -> Optional[str]:
        """Get Docker socket path for current platform."""
        if self.platform == PlatformType.LINUX:
            return 'unix:///var/run/docker.sock'
        elif self.platform == PlatformType.MACOS:
            # Docker Desktop on macOS
            return f'unix://{os.path.expanduser("~/.docker/run/docker.sock")}'
        elif self.platform == PlatformType.WINDOWS:
            if self.wsl_available:
                # WSL2 Docker
                return 'unix:///var/run/docker.sock'
            else:
                # Windows native Docker
                return 'npipe:////./pipe/docker_engine'
        return None
    
    def get_workspace_path(self, base_path: str) -> str:
        """Get platform-appropriate workspace path."""
        if self.platform == PlatformType.WINDOWS and not self.wsl_available:
            # Windows native: use absolute path
            from pathlib import Path
            return str(Path(base_path).resolve())
        elif self.platform == PlatformType.MACOS:
            # macOS: use home directory
            from pathlib import Path
            return str(Path.home() / "ctftoolkit" / "workspace")
        else:
            # Linux/WSL: use provided path
            return base_path
    
    def to_dict(self) -> dict:
        """Convert platform info to dictionary."""
        return {
            'platform': self.platform.value,
            'arch': self.arch,
            'docker_available': self.docker_available,
            'wsl_available': self.wsl_available,
            'is_native': self.is_native(),
            'docker_socket': self.get_docker_socket(),
        }


# Global platform info instance
_current_platform: Optional[PlatformInfo] = None


def get_platform() -> PlatformInfo:
    """Get current platform information."""
    global _current_platform
    if _current_platform is None:
        _current_platform = PlatformInfo()
    return _current_platform


def is_windows() -> bool:
    """Check if running on Windows."""
    return get_platform().platform == PlatformType.WINDOWS


def is_macos() -> bool:
    """Check if running on macOS."""
    return get_platform().platform == PlatformType.MACOS


def is_linux() -> bool:
    """Check if running on Linux."""
    return get_platform().platform == PlatformType.LINUX


def is_wsl() -> bool:
    """Check if running in WSL."""
    return get_platform().wsl_available


def get_arch() -> str:
    """Get CPU architecture."""
    return get_platform().arch


__all__ = [
    'PlatformType',
    'PlatformInfo',
    'get_platform',
    'is_windows',
    'is_macos',
    'is_linux',
    'is_wsl',
    'get_arch',
]
