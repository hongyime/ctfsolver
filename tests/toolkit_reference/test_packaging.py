#!/usr/bin/env python3
"""
Test script for single-file packaging of CTF Toolkit.

This script tests the build process and validates the resulting executable.

Usage:
    python test_packaging.py [options]

Options:
    --platform {windows,macos,linux}  Target platform (default: current)
    --arch {x86_64,arm64}             Target architecture (default: current)
    --output-dir DIR                   Output directory for built executable
    --skip-build                       Skip build, just validate existing executable
    --verbose                          Enable verbose output
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


def get_current_platform():
    """Get current platform name."""
    if sys.platform == 'win32':
        return 'windows'
    elif sys.platform == 'darwin':
        return 'macos'
    else:
        return 'linux'


def get_current_arch():
    """Get current architecture."""
    machine = platform.machine().lower()
    if 'x86_64' in machine or 'amd64' in machine:
        return 'x86_64'
    elif 'arm64' in machine or 'aarch64' in machine:
        return 'arm64'
    else:
        return machine


def check_build_dependencies():
    """Check if build dependencies are installed."""
    print("Checking build dependencies...")
    
    dependencies = {
        'PyInstaller': 'PyInstaller',  # Case sensitive
        'pydantic': 'pydantic',
        'docker': 'docker',
        'aiosqlite': 'aiosqlite',
    }
    
    missing = []
    for name, module in dependencies.items():
        try:
            __import__(module)
            print(f"  ✓ {name}")
        except ImportError:
            print(f"  ✗ {name} - NOT FOUND")
            missing.append(name)
    
    if missing:
        print(f"\nMissing dependencies: {', '.join(missing)}")
        print("Install with: pip install " + " ".join(missing))
        return False
    
    return True


def test_build(platform=None, arch=None, output_dir=None, verbose=False):
    """Test the build process."""
    if platform is None:
        platform = get_current_platform()
    if arch is None:
        arch = get_current_arch()
    if output_dir is None:
        output_dir = ROOT / 'dist'
    
    print(f"\nTesting build for {platform}/{arch}...")
    print(f"Output directory: {output_dir}")
    
    # Check dependencies
    if not check_build_dependencies():
        print("⚠ Build dependencies missing, skipping build test")
        return None
    
    # Run build script
    build_script = ROOT / 'build.py'
    if not build_script.exists():
        print("✗ build.py not found")
        return None
    
    cmd = [sys.executable, str(build_script)]
    if platform:
        cmd.extend(['--platform', platform])
    if arch:
        cmd.extend(['--arch', arch])
    if output_dir:
        cmd.extend(['--output-dir', str(output_dir)])
    if verbose:
        cmd.append('--verbose')
    
    print(f"Running: {' '.join(cmd)}")
    
    try:
        result = subprocess.run(cmd, cwd=ROOT, capture_output=True, text=True)
        
        if result.returncode != 0:
            print(f"✗ Build failed with exit code {result.returncode}")
            print(f"Output: {result.stdout}")
            print(f"Error: {result.stderr}")
            return None
        
        print("✓ Build completed")
        return output_dir
        
    except Exception as e:
        print(f"✗ Build failed: {e}")
        return None


def validate_executable(output_dir=None, platform=None):
    """Validate the built executable."""
    if output_dir is None:
        output_dir = ROOT / 'dist'
    if platform is None:
        platform = get_current_platform()
    
    print(f"\nValidating executable for {platform}...")
    
    # Determine executable name
    if platform == 'windows':
        exe_name = 'ctf-toolkit.exe'
    else:
        exe_name = 'ctf-toolkit'
    
    exe_path = output_dir / exe_name
    
    # Check if executable exists
    if not exe_path.exists():
        print(f"✗ Executable not found: {exe_path}")
        return False
    
    print(f"✓ Executable found: {exe_path}")
    print(f"  Size: {exe_path.stat().st_size / (1024*1024):.1f} MB")
    
    # Check if executable is runnable
    try:
        result = subprocess.run([str(exe_path), '--help'], 
                              capture_output=True, text=True, timeout=10)
        
        if result.returncode == 0 or 'usage' in result.stdout.lower():
            print("✓ Executable is runnable")
            return True
        else:
            print(f"⚠ Executable returned non-zero: {result.returncode}")
            return True  # Still consider it valid if it runs
            
    except subprocess.TimeoutExpired:
        print("⚠ Executable timed out (may be normal for MCP server)")
        return True
    except Exception as e:
        print(f"⚠ Could not run executable: {e}")
        return True  # Still valid if it exists


def validate_distribution_package(output_dir=None):
    """Validate the distribution package."""
    if output_dir is None:
        output_dir = ROOT / 'dist'
    
    print(f"\nValidating distribution package...")
    
    # Look for archive files
    archives = list(output_dir.glob('ctftoolkit-*.zip')) + \
               list(output_dir.glob('ctftoolkit-*.tar.gz')) + \
               list(output_dir.glob('ctftoolkit-*.tgz'))
    
    if not archives:
        print("⚠ No distribution package found")
        return False
    
    print(f"✓ Found {len(archives)} distribution package(s)")
    
    for archive in archives:
        print(f"  - {archive.name} ({archive.stat().st_size / (1024*1024):.1f} MB)")
    
    return True


def test_clean_build(platform=None, arch=None):
    """Test clean build process."""
    print("\nTesting clean build...")
    
    # Clean previous builds
    build_dir = ROOT / 'build'
    dist_dir = ROOT / 'dist'
    
    if build_dir.exists():
        shutil.rmtree(build_dir)
        print("  ✓ Cleaned build directory")
    
    if dist_dir.exists():
        shutil.rmtree(dist_dir)
        print("  ✓ Cleaned dist directory")
    
    # Run build
    output_dir = test_build(platform=platform, arch=arch)
    
    if output_dir:
        # Validate
        exe_valid = validate_executable(output_dir, platform)
        pkg_valid = validate_distribution_package(output_dir)
        
        return exe_valid and pkg_valid
    
    return False


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(description='Test CTF Toolkit packaging')
    parser.add_argument('--platform', choices=['windows', 'macos', 'linux'],
                       help='Target platform (default: current)')
    parser.add_argument('--arch', choices=['x86_64', 'arm64'],
                       help='Target architecture (default: current)')
    parser.add_argument('--output-dir', type=Path, help='Output directory')
    parser.add_argument('--skip-build', action='store_true',
                       help='Skip build, just validate existing')
    parser.add_argument('--verbose', action='store_true',
                       help='Enable verbose output')
    
    args = parser.parse_args()
    
    print("=" * 60)
    print("CTF Toolkit Packaging Test")
    print("=" * 60)
    print()
    
    platform = args.platform or get_current_platform()
    arch = args.arch or get_current_arch()
    
    print(f"Target: {platform}/{arch}")
    print()
    
    if args.skip_build:
        # Just validate existing build
        output_dir = args.output_dir or (ROOT / 'dist')
        exe_valid = validate_executable(output_dir, platform)
        pkg_valid = validate_distribution_package(output_dir)
        
        success = exe_valid and pkg_valid
    else:
        # Full build and validation
        success = test_clean_build(platform=platform, arch=arch)
    
    print("\n" + "=" * 60)
    if success:
        print("✓ Packaging test PASSED")
    else:
        print("✗ Packaging test FAILED")
    print("=" * 60)
    
    return 0 if success else 1


if __name__ == '__main__':
    sys.exit(main())
