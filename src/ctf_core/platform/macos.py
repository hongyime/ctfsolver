"""macOS-specific platform adaptations."""

import os
import sys
import platform
import logging
from pathlib import Path
from typing import Tuple, Optional

logger = logging.getLogger(__name__)


class MacOSAdapter:
    """macOS-specific adaptations for CTF Toolkit."""
    
    def __init__(self):
        """Initialize macOS adapter."""
        self.arch = self._detect_arch()
        self.docker_desktop_installed = self._check_docker_desktop()
        self.rosetta_available = self._check_rosetta()
        
    def _detect_arch(self) -> str:
        """Detect macOS architecture (Intel or Apple Silicon)."""
        machine = platform.machine().lower()
        if 'arm64' in machine or 'aarch64' in machine:
            return 'arm64'
        elif 'x86_64' in machine or 'amd64' in machine:
            return 'x86_64'
        else:
            return machine
    
    def _check_docker_desktop(self) -> bool:
        """Check if Docker Desktop is installed."""
        docker_paths = [
            "/Applications/Docker.app",
            os.path.expanduser("~/Applications/Docker.app"),
        ]
        for path in docker_paths:
            if os.path.exists(path):
                # Also check if Docker daemon is running
                try:
                    import docker
                    client = docker.from_env()
                    client.ping()
                    return True
                except Exception:
                    pass
        return False
    
    def _check_rosetta(self) -> bool:
        """Check if Rosetta 2 is available (for Apple Silicon)."""
        if self.arch != 'arm64':
            return False
        
        # Check if Rosetta 2 is installed
        rosetta_path = "/Library/Apple/usr/libexec/oah/libRosettaRuntime"
        return os.path.exists(rosetta_path)
    
    def get_docker_socket_path(self) -> str:
        """Get Docker socket path for macOS."""
        # Docker Desktop on macOS uses this socket
        return os.path.expanduser("~/.docker/run/docker.sock")
    
    def get_default_workspace(self) -> str:
        """Get default workspace path for macOS."""
        return str(Path.home() / "ctftoolkit" / "workspace")
    
    def validate_environment(self) -> Tuple[bool, list]:
        """
        Validate macOS environment for CTF Toolkit.
        
        Returns:
            Tuple of (is_valid, list_of_issues)
        """
        issues = []
        
        # Check Python version
        if sys.version_info < (3, 10):
            issues.append("Python 3.10+ is required")
        
        # Check Docker Desktop
        if not self.docker_desktop_installed:
            issues.append("Docker Desktop is not installed or not running")
        
        # Check Homebrew (recommended)
        if not self._check_homebrew():
            issues.append("Homebrew is not installed (recommended for tool installation)")
        
        # Check workspace permissions
        workspace = self.get_default_workspace()
        try:
            Path(workspace).mkdir(parents=True, exist_ok=True)
        except Exception as e:
            issues.append(f"Cannot create workspace directory: {e}")
        
        # Apple Silicon specific checks
        if self.arch == 'arm64':
            if not self.rosetta_available:
                issues.append("Rosetta 2 is not installed (needed for some x86_64 tools)")
        
        return len(issues) == 0, issues
    
    def _check_homebrew(self) -> bool:
        """Check if Homebrew is installed."""
        homebrew_paths = [
            "/usr/local/bin/brew",  # Intel Macs
            "/opt/homebrew/bin/brew",  # Apple Silicon Macs
        ]
        return any(os.path.exists(path) for path in homebrew_paths)
    
    def get_setup_instructions(self) -> str:
        """Get platform-specific setup instructions."""
        arch_note = ""
        if self.arch == 'arm64':
            arch_note = """
Note: You're running on Apple Silicon (M1/M2/M3). Some x86_64 tools may require Rosetta 2.
Install Rosetta 2 with: softwareupdate --install-rosetta --agree-to-license
"""
        
        return f"""
macOS Setup Instructions:

1. Install Docker Desktop:
   - Download from https://docker.com/products/docker-desktop
   - Open Docker.app and grant necessary permissions
   - Wait for Docker to start (whale icon in menu bar)

2. Install Python 3.10+:
   - Using Homebrew: brew install python@3.12
   - Or download from https://python.org

3. Install additional tools (optional):
   - Using Homebrew: brew install git wget curl

4. Set up workspace:
   - The toolkit will create ~/ctftoolkit/workspace automatically

{arch_note}
"""
    
    def get_tool_recommendations(self) -> dict:
        """Get tool recommendations for macOS platform."""
        recommendations = {
            "shell": "zsh",  # Default shell on modern macOS
            "package_manager": "homebrew",
            "text_editor": "nano",
            "additional_tools": [
                "Homebrew",
                "Xcode Command Line Tools",
                "Docker Desktop",
            ],
        }
        
        if self.arch == 'arm64':
            recommendations["additional_tools"].append("Rosetta 2")
        
        return recommendations
    
    def convert_command(self, command: str) -> str:
        """
        Convert a Linux-style command to macOS-compatible command.
        
        Most commands work the same, but some have different flags.
        
        Args:
            command: Linux-style command
            
        Returns:
            macOS-compatible command
        """
        # macOS-specific command adjustments
        conversions = {
            # sed differences
            "sed -i": "sed -i ''",  # macOS sed requires backup extension
            # grep differences
            "grep -P": "grep -E",  # macOS grep doesn't support -P (Perl regex)
            # stat differences
            "stat -c": "stat -f",  # Different format flags
        }
        
        for linux_cmd, macos_cmd in conversions.items():
            if command.startswith(linux_cmd):
                return command.replace(linux_cmd, macos_cmd, 1)
        
        return command
    
    def get_environment_variables(self) -> dict:
        """Get platform-specific environment variables."""
        env_vars = {
            "CTFTOOLKIT_PLATFORM": "macos",
            "CTFTOOLKIT_ARCH": self.arch,
            "CTFTOOLKIT_SHELL": "zsh",
            "CTFTOOLKIT_HOME": str(Path.home()),
        }
        
        # Set architecture-specific variables
        if self.arch == 'arm64':
            env_vars["CTFTOOLKIT_USE_ROSETTA"] = str(self.rosetta_available).lower()
            # Homebrew on Apple Silicon is in /opt/homebrew
            if self._check_homebrew():
                env_vars["HOMEBREW_PREFIX"] = "/opt/homebrew"
        else:
            # Intel Mac: Homebrew is in /usr/local
            if self._check_homebrew():
                env_vars["HOMEBREW_PREFIX"] = "/usr/local"
        
        return env_vars
    
    def get_platform_specific_mounts(self) -> dict:
        """Get platform-specific volume mounts for Docker."""
        mounts = {}
        
        # Mount Homebrew directory if available
        if self._check_homebrew():
            brew_prefix = self.get_environment_variables().get("HOMEBREW_PREFIX")
            if brew_prefix and os.path.exists(brew_prefix):
                mounts[brew_prefix] = {"bind": brew_prefix, "mode": "ro"}
        
        # Mount Docker socket
        docker_socket = self.get_docker_socket_path()
        if os.path.exists(docker_socket):
            mounts[docker_socket] = {"bind": "/var/run/docker.sock", "mode": "ro"}
        
        return mounts
    
    def check_security_settings(self) -> Tuple[bool, list]:
        """
        Check macOS security settings that might affect the toolkit.
        
        Returns:
            Tuple of (is_ok, list_of_warnings)
        """
        warnings = []
        
        # Check Gatekeeper
        try:
            result = os.popen("spctl --status").read().strip()
            if result != "disabled":
                warnings.append(
                    "Gatekeeper is enabled. You may need to allow Docker and Python in "
                    "System Preferences > Security & Privacy > Privacy tab."
                )
        except Exception:
            pass
        
        # Check Full Disk Access
        # This is harder to check programmatically, so we just warn
        warnings.append(
            "Ensure Docker has Full Disk Access in System Preferences > "
            "Security & Privacy > Privacy > Full Disk Access."
        )
        
        return len(warnings) == 0, warnings
    
    def get_performance_tips(self) -> list:
        """Get performance optimization tips for macOS."""
        tips = [
            "Use Docker Desktop's resource settings to allocate more CPU/RAM if needed.",
            "Consider using Docker's VirtioFS for better file sharing performance.",
            "On Apple Silicon, native arm64 containers will be faster than x86_64 containers.",
            "Close unnecessary applications to free up memory for Docker containers.",
        ]
        return tips


# Convenience function
def get_macos_adapter() -> MacOSAdapter:
    """Get macOS adapter for current environment."""
    return MacOSAdapter()


__all__ = ['MacOSAdapter', 'get_macos_adapter']
