"""Windows-specific platform adaptations."""

import os
import sys
import logging
from pathlib import Path
from typing import Optional, Tuple

logger = logging.getLogger(__name__)


class WindowsAdapter:
    """Windows-specific adaptations for CTF Toolkit."""
    
    def __init__(self, is_wsl: bool = False):
        """
        Initialize Windows adapter.
        
        Args:
            is_wsl: Whether running in WSL environment
        """
        self.is_wsl = is_wsl
        self.docker_desktop_installed = self._check_docker_desktop()
        
    def _check_docker_desktop(self) -> bool:
        """Check if Docker Desktop is installed."""
        if self.is_wsl:
            # In WSL, check for Docker daemon
            try:
                import docker
                client = docker.from_env()
                client.ping()
                return True
            except Exception:
                return False
        else:
            # Windows native: check for Docker Desktop
            docker_paths = [
                r"C:\Program Files\Docker\Docker\Docker Desktop.exe",
                r"%LOCALAPPDATA%\Docker\docker-cli.exe",
            ]
            for path in docker_paths:
                expanded = os.path.expandvars(path)
                if os.path.exists(expanded):
                    return True
            return False
    
    def convert_to_docker_path(self, host_path: str) -> str:
        """
        Convert Windows host path to Docker container path.
        
        Args:
            host_path: Path on Windows host
            
        Returns:
            Path suitable for Docker container
        """
        if self.is_wsl:
            # WSL paths are already Linux-style
            return host_path
        
        # Windows native: convert to Linux-style path
        # Docker Desktop on Windows automatically handles this
        path = Path(host_path)
        
        # Get the drive letter and path
        drive = path.drive.lower().rstrip(':')
        
        # Handle UNC paths or paths without drive letter
        if not drive:
            # Return as-is for UNC paths
            return host_path.replace('\\', '/')
        
        # Get relative path, handling the case where path is just a drive
        try:
            relative_path = str(path.relative_to(path.anchor)).replace('\\', '/')
        except ValueError:
            relative_path = ''
        
        # Convert to /drive/path format
        return f"/{drive}/{relative_path}" if relative_path else f"/{drive}"
    
    def convert_from_docker_path(self, container_path: str) -> str:
        """
        Convert Docker container path back to Windows host path.
        
        Args:
            container_path: Path from Docker container
            
        Returns:
            Path on Windows host
        """
        if self.is_wsl:
            return container_path
        
        # Convert /c/path to C:\path
        if container_path.startswith('/'):
            parts = container_path.split('/')
            if len(parts) >= 2:
                drive = parts[1].upper()
                relative = '/'.join(parts[2:])
                return f"{drive}:\\{relative.replace('/', '\\')}"
        
        return container_path
    
    def get_docker_volume_mount(self, host_path: str, container_path: str, mode: str = "rw") -> dict:
        """
        Get Docker volume mount configuration for Windows.
        
        Args:
            host_path: Path on Windows host
            container_path: Path in container
            mode: Mount mode (rw/ro)
            
        Returns:
            Docker volume mount dictionary
        """
        if self.is_wsl:
            return {host_path: {"bind": container_path, "mode": mode}}
        
        # Windows native: use the converted path
        docker_path = self.convert_to_docker_path(host_path)
        return {docker_path: {"bind": container_path, "mode": mode}}
    
    def get_default_workspace(self) -> str:
        """Get default workspace path for Windows."""
        if self.is_wsl:
            # In WSL, use home directory
            return str(Path.home() / "ctftoolkit" / "workspace")
        else:
            # Windows native: use user's home directory
            return str(Path.home() / "ctftoolkit" / "workspace")
    
    def validate_environment(self) -> Tuple[bool, list]:
        """
        Validate Windows environment for CTF Toolkit.
        
        Returns:
            Tuple of (is_valid, list_of_issues)
        """
        issues = []
        
        # Check Python version
        if sys.version_info < (3, 10):
            issues.append("Python 3.10+ is required")
        
        # Check Docker
        if not self.docker_desktop_installed:
            if self.is_wsl:
                issues.append("Docker daemon is not running in WSL")
            else:
                issues.append("Docker Desktop is not installed or not running")
        
        # Check workspace permissions (Windows native only)
        if not self.is_wsl:
            workspace = self.get_default_workspace()
            try:
                Path(workspace).mkdir(parents=True, exist_ok=True)
            except Exception as e:
                issues.append(f"Cannot create workspace directory: {e}")
        
        return len(issues) == 0, issues
    
    def get_setup_instructions(self) -> str:
        """Get platform-specific setup instructions."""
        if self.is_wsl:
            return """
WSL2 Setup Instructions:
1. Ensure Docker Desktop is installed on Windows
2. In Docker Desktop Settings, enable WSL2 integration
3. Install Docker CLI in WSL: sudo apt-get install docker.io
4. Add your user to the docker group: sudo usermod -aG docker $USER
5. Log out and log back in for group changes to take effect
"""
        else:
            return """
Windows Native Setup Instructions:
1. Install Docker Desktop from https://docker.com/products/docker-desktop
2. Start Docker Desktop and ensure it's running
3. In Docker Desktop Settings, enable "Use Docker Compose V2"
4. Ensure WSL2 backend is enabled in Docker Desktop settings
5. Install Python 3.10+ from https://python.org
6. Make sure Python is added to PATH during installation
"""
    
    def get_tool_recommendations(self) -> dict:
        """Get tool recommendations for Windows platform."""
        recommendations: dict[str, str | list[str]] = {
            "shell": "powershell" if not self.is_wsl else "bash",
            "package_manager": "choco" if not self.is_wsl else "apt",
            "text_editor": "notepad" if not self.is_wsl else "nano",
        }
        
        if not self.is_wsl:
            recommendations["additional_tools"] = [
                "Git for Windows",
                "Windows Terminal",
                "WSL2 (optional but recommended)",
            ]
        
        return recommendations
    
    def convert_command(self, command: str) -> str:
        """
        Convert a Unix-style command to Windows-compatible command.
        
        Args:
            command: Unix-style command
            
        Returns:
            Windows-compatible command
        """
        if self.is_wsl:
            return command
        
        # Common command conversions
        conversions = {
            "ls": "dir",
            "cat": "type",
            "grep": "findstr",
            "rm -rf": "rmdir /s /q",
            "mkdir -p": "mkdir",
            "cp -r": "xcopy /E /I",
            "mv": "move",
        }
        
        for unix_cmd, win_cmd in conversions.items():
            if command.startswith(unix_cmd):
                return command.replace(unix_cmd, win_cmd, 1)
        
        return command
    
    def get_environment_variables(self) -> dict:
        """Get platform-specific environment variables."""
        env_vars = {
            "CTFTOOLKIT_PLATFORM": "windows",
            "CTFTOOLKIT_IS_WSL": str(self.is_wsl).lower(),
        }
        
        if not self.is_wsl:
            # Windows-specific variables
            env_vars["CTFTOOLKIT_SHELL"] = "powershell"
            env_vars["CTFTOOLKIT_HOME"] = str(Path.home())
        
        return env_vars


# Convenience function
def get_windows_adapter() -> WindowsAdapter:
    """Get Windows adapter for current environment."""
    from . import is_wsl
    return WindowsAdapter(is_wsl=is_wsl())


__all__ = ['WindowsAdapter', 'get_windows_adapter']
