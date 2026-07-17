#!/usr/bin/env python3
"""
Script to install and configure Wasmtime for CTF Toolkit.

Wasmtime is a standalone JIT-style WebAssembly runtime.

Usage:
    python setup_wasmtime.py [options]

Options:
    --version VERSION   Wasmtime version to install (default: latest)
    --skip-install      Skip installation, just verify
    --verbose           Enable verbose output
"""

import argparse
import os
import platform
import subprocess
import sys
from pathlib import Path

def get_platform_info():
    """Get platform information for Wasmtime installation."""
    system = platform.system().lower()
    machine = platform.machine().lower()
    
    # Map to Wasmtime naming
    if system == 'linux':
        os_name = 'linux'
    elif system == 'darwin':
        os_name = 'macos'
    elif system == 'windows':
        os_name = 'windows'
    else:
        return None, None
    
    if 'x86_64' in machine or 'amd64' in machine:
        arch = 'x86_64'
    elif 'arm64' in machine or 'aarch64' in machine:
        arch = 'aarch64'
    else:
        arch = machine
    
    return os_name, arch


def check_wasmtime_installed():
    """Check if Wasmtime is already installed."""
    try:
        # Check if wasmtime command is available
        result = subprocess.run(['wasmtime', '--version'], 
                              capture_output=True, text=True)
        if result.returncode == 0:
            print(f"Wasmtime found: {result.stdout.strip()}")
            return True
    except FileNotFoundError:
        pass
    
    # Check if wasmtime Python package is installed
    try:
        import wasmtime
        print("Wasmtime Python package found")
        return True
    except ImportError:
        pass
    
    return False


def install_wasmtime_python():
    """Install Wasmtime Python package."""
    print("Installing Wasmtime Python package...")
    
    try:
        subprocess.run([sys.executable, '-m', 'pip', 'install', 'wasmtime'], 
                      check=True)
        print("✓ Wasmtime Python package installed")
        return True
    except subprocess.CalledProcessError as e:
        print(f"✗ Failed to install Wasmtime: {e}")
        return False


def install_wasmtime_cli(version='latest'):
    """Install Wasmtime CLI using the official installer."""
    system, arch = get_platform_info()
    
    if not system:
        print("✗ Unsupported platform")
        return False
    
    print(f"Installing Wasmtime CLI for {system}/{arch}...")
    
    # Use official installer
    if system in ['linux', 'darwin']:
        # Unix-like systems
        cmd = f"curl https://wasmtime.dev/install.sh -sSf | bash"
        env = os.environ.copy()
        env['WASMTIME_VERSION'] = version if version != 'latest' else ''
        
        try:
            subprocess.run(cmd, shell=True, env=env, check=True)
            print("✓ Wasmtime CLI installed")
            return True
        except subprocess.CalledProcessError as e:
            print(f"✗ Failed to install Wasmtime CLI: {e}")
            return False
    
    elif system == 'windows':
        # Windows - use winget or manual download
        print("For Windows, please install Wasmtime manually:")
        print("  1. Download from: https://github.com/bytecodealliance/wasmtime/releases")
        print("  2. Extract to a directory")
        print("  3. Add to PATH")
        return False
    
    return False


def verify_wasmtime():
    """Verify Wasmtime installation."""
    print("\nVerifying Wasmtime installation...")
    
    # Check Python package
    try:
        import wasmtime
        # Try to get version, fallback to success message
        try:
            version = wasmtime.__version__
            print(f"✓ Wasmtime Python package: {version}")
        except AttributeError:
            print("✓ Wasmtime Python package installed")
    except ImportError:
        print("✗ Wasmtime Python package not found")
        return False
    
    # Check CLI
    try:
        result = subprocess.run(['wasmtime', '--version'], 
                              capture_output=True, text=True)
        if result.returncode == 0:
            print(f"✓ Wasmtime CLI: {result.stdout.strip()}")
        else:
            print("⚠ Wasmtime CLI not found (optional)")
    except FileNotFoundError:
        print("⚠ Wasmtime CLI not found (optional)")
    
    return True


def test_wasmtime_functionality():
    """Test basic Wasmtime functionality."""
    print("\nTesting Wasmtime functionality...")
    
    try:
        import wasmtime
        
        # Create a simple WebAssembly module
        engine = wasmtime.Engine()
        module = wasmtime.Module(engine, """
            (module
                (func $add (param i32 i32) (result i32)
                    local.get 0
                    local.get 1
                    i32.add)
                (export "add" (func $add))
            )
        """)
        
        # Create instance and call function
        store = wasmtime.Store()
        instance = wasmtime.Instance(store, module, [])
        add = instance.exports(store)["add"]
        
        # Test the function
        result = add(store, 2, 3)
        assert result == 5, f"Expected 5, got {result}"
        
        print("✓ Wasmtime functionality test passed")
        return True
        
    except Exception as e:
        print(f"✗ Wasmtime functionality test failed: {e}")
        return False


def update_pyproject(dependencies=True):
    """Update pyproject.toml to include wasmtime."""
    if not dependencies:
        return
    
    print("\nUpdating pyproject.toml...")
    
    pyproject_path = Path(__file__).parent / 'pyproject.toml'
    
    if not pyproject_path.exists():
        print("⚠ pyproject.toml not found")
        return
    
    # Read current content
    content = pyproject_path.read_text()
    
    # Check if wasmtime is already listed
    if 'wasmtime' in content:
        print("✓ wasmtime already in pyproject.toml")
        return
    
    # Add wasmtime to dependencies
    if 'dependencies = [' in content:
        # Find the dependencies section
        lines = content.split('\n')
        new_lines = []
        added = False
        
        for line in lines:
            new_lines.append(line)
            if line.strip() == ']' and not added:
                # Insert before closing bracket
                new_lines.insert(-1, '    "wasmtime>=15.0.0",')
                added = True
        
        if added:
            pyproject_path.write_text('\n'.join(new_lines))
            print("✓ Updated pyproject.toml")
        else:
            print("⚠ Could not update pyproject.toml")


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(description='Install and configure Wasmtime')
    parser.add_argument('--version', type=str, default='latest',
                       help='Wasmtime version to install')
    parser.add_argument('--skip-install', action='store_true',
                       help='Skip installation, just verify')
    parser.add_argument('--verbose', action='store_true',
                       help='Enable verbose output')
    
    args = parser.parse_args()
    
    print("=" * 60)
    print("Wasmtime Setup for CTF Toolkit")
    print("=" * 60)
    print()
    
    # Check if already installed
    if check_wasmtime_installed():
        print("Wasmtime is already installed!")
        verify_wasmtime()
        test_wasmtime_functionality()
        return 0
    
    if args.skip_install:
        print("Skipping installation (--skip-install)")
        return 0
    
    # Install Wasmtime
    print("Installing Wasmtime...")
    
    # Install Python package
    python_ok = install_wasmtime_python()
    
    # Install CLI (optional but recommended)
    cli_ok = install_wasmtime_cli(args.version)
    
    # Verify installation
    verify_ok = verify_wasmtime()
    
    # Test functionality
    test_ok = test_wasmtime_functionality()
    
    # Update pyproject.toml
    if python_ok:
        update_pyproject()
    
    # Summary
    print("\n" + "=" * 60)
    print("Installation Summary:")
    print(f"  Python package: {'✓' if python_ok else '✗'}")
    print(f"  CLI: {'✓' if cli_ok else '⚠ (optional)'}")
    print(f"  Verification: {'✓' if verify_ok else '✗'}")
    print(f"  Functionality test: {'✓' if test_ok else '✗'}")
    print("=" * 60)
    
    return 0 if (python_ok and verify_ok and test_ok) else 1


if __name__ == '__main__':
    sys.exit(main())
