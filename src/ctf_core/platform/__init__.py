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
        """Auto-detect the Docker socket path for the current platform.

        Priority order:
        1. ``DOCKER_HOST`` env var (always wins if set)
        2. Probe known socket paths in order (existence check via os.path.exists)
           - macOS Docker Desktop: ~/.docker/run/docker.sock
           - Colima:               ~/.colima/default/docker.sock
           - Rancher Desktop:      ~/.rd/docker.sock
           - Linux / WSL2 standard: /var/run/docker.sock
           - Rootless Docker (Linux): $XDG_RUNTIME_DIR/docker.sock
        3. Windows native named pipe (no existence check possible)
        4. None → caller falls back to docker.from_env()
        """
        # 1. Explicit DOCKER_HOST override
        docker_host = os.environ.get('DOCKER_HOST', '')
        if docker_host:
            return docker_host

        if self.platform == PlatformType.WINDOWS and not self.wsl_available:
            # Windows native — named pipe, cannot stat
            return 'npipe:////./pipe/docker_engine'

        # 2. Probe Unix socket candidates in priority order
        home = os.path.expanduser('~')
        xdg_runtime = os.environ.get('XDG_RUNTIME_DIR', '')
        candidates = [
            os.path.join(home, '.docker', 'run', 'docker.sock'),   # Docker Desktop macOS / Linux
            os.path.join(home, '.colima', 'default', 'docker.sock'), # Colima (macOS/Linux)
            os.path.join(home, '.rd', 'docker.sock'),               # Rancher Desktop
            '/var/run/docker.sock',                                  # Linux + Docker Desktop macOS symlink + WSL2
        ]
        if xdg_runtime:
            candidates.append(os.path.join(xdg_runtime, 'docker.sock'))  # rootless Docker

        for candidate in candidates:
            if os.path.exists(candidate):
                return f'unix://{candidate}'

        # 3. Nothing found — let docker.from_env() try its own detection
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
