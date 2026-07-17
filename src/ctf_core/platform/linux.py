"""Linux-specific platform adaptations."""

import os
import sys
import shutil
import logging
from pathlib import Path
from typing import Tuple, Optional

logger = logging.getLogger(__name__)


class LinuxAdapter:
    """Linux-specific adaptations for CTF Toolkit."""
    
    def __init__(self):
        """Initialize Linux adapter."""
        self.distro = self._detect_distro()
        self.docker_available = self._check_docker()
        self.package_manager = self._detect_package_manager()
        
    def _detect_distro(self) -> str:
        """Detect Linux distribution."""
        # Try reading /etc/os-release
        try:
            with open('/etc/os-release', 'r') as f:
                content = f.read().lower()
                if 'ubuntu' in content:
                    return 'ubuntu'
                elif 'debian' in content:
                    return 'debian'
                elif 'fedora' in content:
                    return 'fedora'
                elif 'centos' in content or 'rocky' in content or 'almalinux' in content:
                    return 'rhel'
                elif 'arch' in content:
                    return 'arch'
                elif 'opensuse' in content or 'suse' in content:
                    return 'suse'
                else:
                    return 'unknown'
        except Exception:
            return 'unknown'
    
    def _check_docker(self) -> bool:
        """Check if Docker is available."""
        # Check if Docker daemon is running
        try:
            import docker
            client = docker.from_env()
            client.ping()
            return True
        except Exception:
            return False
    
    def _detect_package_manager(self) -> Optional[str]:
        """Detect available package manager."""
        managers = ['apt', 'apt-get', 'yum', 'dnf', 'pacman', 'zypper', 'snap']
        for manager in managers:
            if shutil.which(manager):
                return manager
        return None
    
    def get_docker_socket_path(self) -> str:
        """Get Docker socket path for Linux."""
        return '/var/run/docker.sock'
    
    def get_default_workspace(self) -> str:
        """Get default workspace path for Linux."""
        return str(Path.home() / "ctftoolkit" / "workspace")
    
    def validate_environment(self) -> Tuple[bool, list]:
        """
        Validate Linux environment for CTF Toolkit.
        
        Returns:
            Tuple of (is_valid, list_of_issues)
        """
        issues = []
        
        # Check Python version
        if sys.version_info < (3, 10):
            issues.append("Python 3.10+ is required")
        
        # Check Docker
        if not self.docker_available:
            issues.append("Docker daemon is not running or not accessible")
            issues.append("Install Docker: https://docs.docker.com/engine/install/")
            issues.append("Add user to docker group: sudo usermod -aG docker $USER")
        
        # Check package manager
        if not self.package_manager:
            issues.append("No supported package manager found (apt, yum, dnf, pacman, zypper)")
        
        # Check workspace permissions
        workspace = self.get_default_workspace()
        try:
            Path(workspace).mkdir(parents=True, exist_ok=True)
            # Test write permissions
            test_file = Path(workspace) / ".test_write"
            test_file.touch()
            test_file.unlink()
        except Exception as e:
            issues.append(f"Cannot create or write to workspace directory: {e}")
        
        # Check for common dependencies
        missing_deps = self._check_dependencies()
        if missing_deps:
            issues.append(f"Missing dependencies: {', '.join(missing_deps)}")
        
        return len(issues) == 0, issues
    
    def _check_dependencies(self) -> list:
        """Check for common dependencies."""
        deps = ['git', 'curl', 'wget']
        missing = []
        for dep in deps:
            if not shutil.which(dep):
                missing.append(dep)
        return missing
    
    def get_setup_instructions(self) -> str:
        """Get platform-specific setup instructions."""
        distro_instructions = {
            'ubuntu': """
Ubuntu/Debian Setup:
1. Update package list:
   sudo apt update

2. Install Docker (if not installed):
   sudo apt install docker.io docker-compose

3. Add user to docker group:
   sudo usermod -aG docker $USER
   (Log out and log back in for this to take effect)

4. Install Python 3.10+:
   sudo apt install python3 python3-pip python3-venv
   
   Or use deadsnakes PPA for newer versions:
   sudo add-apt-repository ppa:deadsnakes/ppa
   sudo apt install python3.12 python3.12-venv

5. Install additional tools:
   sudo apt install git curl wget
""",
            'debian': """
Debian Setup:
1. Update package list:
   sudo apt update

2. Install Docker:
   sudo apt install docker.io docker-compose

3. Add user to docker group:
   sudo usermod -aG docker $USER

4. Install Python 3.10+:
   sudo apt install python3 python3-pip python3-venv

5. Install additional tools:
   sudo apt install git curl wget
""",
            'fedora': """
Fedora Setup:
1. Update system:
   sudo dnf update

2. Install Docker:
   sudo dnf install docker docker-compose

3. Start and enable Docker:
   sudo systemctl start docker
   sudo systemctl enable docker

4. Add user to docker group:
   sudo usermod -aG docker $USER

5. Install Python 3.10+:
   sudo dnf install python3 python3-pip

6. Install additional tools:
   sudo dnf install git curl wget
""",
            'rhel': """
RHEL/CentOS/Rocky Setup:
1. Update system:
   sudo dnf update

2. Install Docker:
   sudo dnf install docker docker-compose

3. Start and enable Docker:
   sudo systemctl start docker
   sudo systemctl enable docker

4. Add user to docker group:
   sudo usermod -aG docker $USER

5. Install Python 3.10+:
   sudo dnf install python3 python3-pip

6. Install additional tools:
   sudo dnf install git curl wget
""",
            'arch': """
Arch Linux Setup:
1. Update system:
   sudo pacman -Syu

2. Install Docker:
   sudo pacman -S docker docker-compose

3. Start and enable Docker:
   sudo systemctl start docker
   sudo systemctl enable docker

4. Add user to docker group:
   sudo usermod -aG docker $USER

5. Install Python 3.10+:
   sudo pacman -S python

6. Install additional tools:
   sudo pacman -S git curl wget
""",
            'suse': """
openSUSE Setup:
1. Update system:
   sudo zypper refresh

2. Install Docker:
   sudo zypper install docker docker-compose

3. Start and enable Docker:
   sudo systemctl start docker
   sudo systemctl enable docker

4. Add user to docker group:
   sudo usermod -aG docker $USER

5. Install Python 3.10+:
   sudo zypper install python3 python3-pip

6. Install additional tools:
   sudo zypper install git curl wget
""",
        }
        
        base_instructions = distro_instructions.get(self.distro, f"""
Generic Linux Setup:
1. Install Docker:
   - Follow instructions at https://docs.docker.com/engine/install/

2. Add user to docker group:
   sudo usermod -aG docker $USER

3. Install Python 3.10+:
   - Use your distribution's package manager

4. Install additional tools:
   - git, curl, wget
""")
        
        return base_instructions
    
    def get_tool_recommendations(self) -> dict:
        """Get tool recommendations for Linux platform."""
        recommendations = {
            "shell": "bash",
            "package_manager": self.package_manager or "unknown",
            "text_editor": "nano",
            "additional_tools": [
                "Docker",
                "Docker Compose",
                "Git",
                "curl",
                "wget",
            ],
        }
        
        # Add distro-specific recommendations
        if self.distro == 'ubuntu':
            recommendations["additional_tools"].extend([
                "software-properties-common",
                "apt-transport-https",
            ])
        elif self.distro == 'arch':
            recommendations["additional_tools"].append("base-devel")
        
        return recommendations
    
    def get_platform_specific_mounts(self) -> dict:
        """Get platform-specific volume mounts for Docker."""
        mounts = {}
        
        # Mount Docker socket
        docker_socket = self.get_docker_socket_path()
        if os.path.exists(docker_socket):
            mounts[docker_socket] = {"bind": "/var/run/docker.sock", "mode": "ro"}
        
        # Mount /tmp if needed for some tools
        if os.path.exists('/tmp'):
            mounts['/tmp'] = {"bind": "/tmp", "mode": "rw"}
        
        return mounts
    
    def check_security_settings(self) -> Tuple[bool, list]:
        """
        Check Linux security settings that might affect the toolkit.
        
        Returns:
            Tuple of (is_ok, list_of_warnings)
        """
        warnings = []
        
        # Check if running as root (not recommended)
        # Only on Unix-like systems
        if hasattr(os, 'geteuid'):
            if os.geteuid() == 0:
                warnings.append(
                    "Running as root is not recommended. Consider using a regular user account."
                )
        
        # Check SELinux/AppArmor
        if os.path.exists('/usr/sbin/selinuxenabled'):
            try:
                rc = os.system('/usr/sbin/selinuxenabled 2>/dev/null')
                if rc == 0:
                    warnings.append(
                        "SELinux is enabled. You may need to set SELinux contexts for Docker volumes."
                    )
            except Exception:
                pass
        
        # Check if user is in docker group (Unix only)
        if hasattr(os, 'geteuid'):  # Unix-like systems
            try:
                import grp
                docker_group = getattr(grp, "getgrnam")('docker')
                current_user = os.getenv('USER')
                if current_user and current_user not in docker_group.gr_mem:
                    warnings.append(
                        f"User '{current_user}' is not in the docker group. "
                        "Run: sudo usermod -aG docker $USER"
                    )
            except (KeyError, ImportError):
                pass
        
        return len(warnings) == 0, warnings
    
    def get_performance_tips(self) -> list:
        """Get performance optimization tips for Linux."""
        tips = [
            "Use Docker's storage driver settings for optimal performance.",
            "Consider using tmpfs for temporary files if you have enough RAM.",
            "Adjust Docker daemon resource limits in /etc/docker/daemon.json.",
            "Use Docker BuildKit for faster image builds.",
            "Consider using rootless Docker for improved security.",
        ]
        return tips
    
    def get_system_info(self) -> dict:
        """Get detailed system information."""
        import platform
        
        info = {
            'os': 'Linux',
            'distro': self.distro,
            'version': platform.version(),
            'machine': platform.machine(),
            'processor': platform.processor(),
            'python_version': sys.version,
            'docker_available': self.docker_available,
            'package_manager': self.package_manager,
        }
        
        # Get memory info
        try:
            with open('/proc/meminfo', 'r') as f:
                meminfo = f.read()
                for line in meminfo.split('\n'):
                    if line.startswith('MemTotal:'):
                        info['total_memory'] = line.split()[1] + ' kB'
                    elif line.startswith('MemFree:'):
                        info['free_memory'] = line.split()[1] + ' kB'
        except Exception:
            pass
        
        return info
    
    def get_environment_variables(self) -> dict:
        """Get platform-specific environment variables."""
        return {
            'CTFTOOLKIT_PLATFORM': 'linux',
            'CTFTOOLKIT_DISTRO': self.distro,
            'CTFTOOLKIT_PACKAGE_MANAGER': self.package_manager or 'unknown',
            'CTFTOOLKIT_SHELL': 'bash',
            'CTFTOOLKIT_HOME': str(Path.home()),
        }


# Convenience function
def get_linux_adapter() -> LinuxAdapter:
    """Get Linux adapter for current environment."""
    return LinuxAdapter()


__all__ = ['LinuxAdapter', 'get_linux_adapter']
