#!/usr/bin/env python3
"""
Cross-platform installation script for CTF Toolkit.

This script provides a unified installation experience across Windows, macOS, and Linux.
It automatically detects the platform and installs appropriate dependencies.

Usage:
    python install.py [options]

Options:
    --skip-docker         Skip Docker installation check
    --skip-python         Skip Python version check
    --skip-deps           Skip dependency installation
    --workspace DIR       Set custom workspace directory
    --no-venv             Don't create virtual environment
    --verbose             Enable verbose output
    --uninstall           Uninstall CTF Toolkit
"""

import argparse
import os
import platform
import shutil
import subprocess
import sys
from pathlib import Path

# Project root
ROOT = Path(__file__).parent

# Minimum Python version
MIN_PYTHON = (3, 10)

# Required packages
REQUIRED_PACKAGES = [
    'mcp>=1.2.0',
    'aiosqlite>=0.19.0',
    'docker>=7.0.0',
    'xmltodict>=0.13.0',
    'pydantic>=2.5.0',
]

# Optional packages
OPTIONAL_PACKAGES = {
    'wasmtime': 'WebAssembly runtime (recommended for better performance)',
    'wasmedge': 'Alternative WebAssembly runtime',
    'pytest': 'Testing framework',
    'pytest-asyncio': 'Async testing support',
}


class Installer:
    """Cross-platform installer for CTF Toolkit."""
    
    def __init__(self, verbose: bool = False):
        self.verbose = verbose
        self.platform = self._detect_platform()
        self.python_version = sys.version_info
        self.workspace = None
    
    def _detect_platform(self) -> str:
        """Detect current platform."""
        if sys.platform == 'win32':
            return 'windows'
        elif sys.platform == 'darwin':
            return 'macos'
        else:
            return 'linux'
    
    def log(self, message: str, level: str = 'INFO'):
        """Log a message."""
        print(f"[{level}] {message}")
    
    def log_verbose(self, message: str):
        """Log a verbose message."""
        if self.verbose:
            self.log(message, 'DEBUG')
    
    def check_python_version(self) -> bool:
        """Check if Python version meets requirements."""
        self.log(f"Checking Python version: {self.python_version.major}.{self.python_version.minor}")
        
        if self.python_version < MIN_PYTHON:
            self.log(
                f"Python {MIN_PYTHON[0]}.{MIN_PYTHON[1]}+ is required. "
                f"Found {self.python_version.major}.{self.python_version.minor}.",
                'ERROR'
            )
            return False
        
        self.log(f"Python version OK: {self.python_version.major}.{self.python_version.minor}")
        return True
    
    def check_docker(self) -> bool:
        """Check if Docker is available."""
        self.log("Checking Docker availability...")
        
        try:
            import docker
            client = docker.from_env()
            client.ping()
            self.log("Docker is available and running")
            return True
        except Exception as e:
            self.log(f"Docker check failed: {e}", 'WARNING')
            return False
    
    def create_workspace(self, workspace_path: str = None) -> bool:
        """Create workspace directory."""
        if workspace_path:
            self.workspace = Path(workspace_path)
        else:
            # Use platform-specific default
            if self.platform == 'windows':
                self.workspace = Path.home() / 'ctftoolkit' / 'workspace'
            else:
                self.workspace = Path.home() / 'ctftoolkit' / 'workspace'
        
        try:
            self.workspace.mkdir(parents=True, exist_ok=True)
            self.log(f"Workspace created: {self.workspace}")
            return True
        except Exception as e:
            self.log(f"Failed to create workspace: {e}", 'ERROR')
            return False
    
    def create_virtual_environment(self) -> bool:
        """Create Python virtual environment."""
        venv_path = ROOT / '.venv'
        
        if venv_path.exists():
            self.log("Virtual environment already exists")
            return True
        
        self.log("Creating virtual environment...")
        try:
            subprocess.run([sys.executable, '-m', 'venv', str(venv_path)], check=True)
            self.log(f"Virtual environment created: {venv_path}")
            return True
        except subprocess.CalledProcessError as e:
            self.log(f"Failed to create virtual environment: {e}", 'ERROR')
            return False
    
    def install_dependencies(self, use_venv: bool = True) -> bool:
        """Install Python dependencies."""
        if use_venv:
            # Use virtual environment pip
            if self.platform == 'windows':
                pip_path = ROOT / '.venv' / 'Scripts' / 'pip.exe'
            else:
                pip_path = ROOT / '.venv' / 'bin' / 'pip'
        else:
            pip_path = Path(sys.executable).parent / 'pip'
        
        if not pip_path.exists():
            pip_path = shutil.which('pip') or shutil.which('pip3')
            if not pip_path:
                self.log("pip not found, using python -m pip", 'WARNING')
                pip_path = sys.executable
        
        # Install required packages
        self.log("Installing required dependencies...")
        cmd = [str(pip_path), 'install', '-q', '-U'] + REQUIRED_PACKAGES
        
        try:
            subprocess.run(cmd, check=True)
            self.log("Required dependencies installed")
            return True
        except subprocess.CalledProcessError as e:
            self.log(f"Failed to install dependencies: {e}", 'ERROR')
            return False
    
    def setup_mcp_configuration(self) -> bool:
        """Set up MCP configuration for the user's IDE."""
        self.log("Setting up MCP configuration...")
        
        # Generate MCP configuration
        mcp_config = self._generate_mcp_config()
        
        # Save to file
        config_path = ROOT / 'mcp-config.json'
        try:
            with open(config_path, 'w') as f:
                import json
                json.dump(mcp_config, f, indent=2)
            self.log(f"MCP configuration saved to: {config_path}")
            return True
        except Exception as e:
            self.log(f"Failed to save MCP config: {e}", 'ERROR')
            return False
    
    def _generate_mcp_config(self) -> dict:
        """Generate MCP server configuration."""
        # Determine the correct Python executable
        if (ROOT / '.venv').exists():
            if self.platform == 'windows':
                python_exe = str(ROOT / '.venv' / 'Scripts' / 'python.exe')
            else:
                python_exe = str(ROOT / '.venv' / 'bin' / 'python')
        else:
            python_exe = sys.executable
        
        # Generate configuration
        config = {
            "mcpServers": {
                "ctf-toolkit": {
                    "command": python_exe,
                    "args": [
                        "-m",
                        "ctf_core.server"
                    ],
                    "env": {
                        "CTFTOOLKIT_WORKSPACE": str(self.workspace) if self.workspace else "",
                        "CTFTOOLKIT_PLATFORM": self.platform,
                    }
                }
            }
        }
        
        return config
    
    def print_post_install_instructions(self):
        """Print post-installation instructions."""
        print("\n" + "="*60)
        print("CTF Toolkit Installation Complete!")
        print("="*60)
        print(f"""
Next Steps:

1. Configure your AI IDE:
   - Open the MCP configuration file: {ROOT / 'mcp-config.json'}
   - Copy the JSON content
   - In your IDE (Cursor, Trae AI, CodeFlicker, etc.):
     * Go to Settings → MCP → Add Server
     * Paste the JSON configuration

2. Verify installation:
   - Run: python -m ctf_core.server --health
   - Or use your IDE to test the MCP connection

3. Start using CTF Toolkit:
   - Open a new chat in your AI IDE
   - Describe your CTF challenge
   - The toolkit will automatically assist you

Workspace location: {self.workspace}

For troubleshooting, see: {ROOT / 'README.md'}
""")
    
    def uninstall(self) -> bool:
        """Uninstall CTF Toolkit."""
        self.log("Uninstalling CTF Toolkit...")
        
        # Remove virtual environment
        venv_path = ROOT / '.venv'
        if venv_path.exists():
            shutil.rmtree(venv_path)
            self.log("Removed virtual environment")
        
        # Remove workspace (optional)
        if self.workspace and self.workspace.exists():
            response = input(f"Remove workspace directory {self.workspace}? [y/N]: ")
            if response.lower() == 'y':
                shutil.rmtree(self.workspace)
                self.log("Removed workspace directory")
        
        # Remove generated files
        for file in ['mcp-config.json', 'ctf_state.db']:
            file_path = ROOT / file
            if file_path.exists():
                file_path.unlink()
                self.log(f"Removed {file}")
        
        self.log("Uninstallation complete")
        return True
    
    def install(self, args) -> bool:
        """Run installation process."""
        self.log(f"Installing CTF Toolkit on {self.platform}")
        
        # Check Python version
        if not args.skip_python:
            if not self.check_python_version():
                return False
        
        # Check Docker
        if not args.skip_docker:
            docker_available = self.check_docker()
            if not docker_available:
                self.log("Docker is not available. Some features may not work.", 'WARNING')
        
        # Create workspace
        if not self.create_workspace(args.workspace):
            return False
        
        # Create virtual environment
        if not args.no_venv:
            if not self.create_virtual_environment():
                return False
        
        # Install dependencies
        if not args.skip_deps:
            if not self.install_dependencies(use_venv=not args.no_venv):
                return False
        
        # Setup MCP configuration
        if not self.setup_mcp_configuration():
            return False
        
        # Print instructions
        self.print_post_install_instructions()
        
        return True


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(description='Install CTF Toolkit')
    parser.add_argument('--skip-docker', action='store_true',
                       help='Skip Docker installation check')
    parser.add_argument('--skip-python', action='store_true',
                       help='Skip Python version check')
    parser.add_argument('--skip-deps', action='store_true',
                       help='Skip dependency installation')
    parser.add_argument('--workspace', type=str,
                       help='Set custom workspace directory')
    parser.add_argument('--no-venv', action='store_true',
                       help="Don't create virtual environment")
    parser.add_argument('--verbose', action='store_true',
                       help='Enable verbose output')
    parser.add_argument('--uninstall', action='store_true',
                       help='Uninstall CTF Toolkit')
    
    args = parser.parse_args()
    
    installer = Installer(verbose=args.verbose)
    
    if args.uninstall:
        success = installer.uninstall()
    else:
        success = installer.install(args)
    
    sys.exit(0 if success else 1)


if __name__ == '__main__':
    main()
