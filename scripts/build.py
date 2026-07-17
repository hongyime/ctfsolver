#!/usr/bin/env python3
"""
Build script for CTF Toolkit single-file executable.

This script automates the build process for creating a standalone executable
using PyInstaller.

Usage:
    python build.py [options]

Options:
    --platform {windows,macos,linux}  Target platform (default: current platform)
    --arch {x86_64,arm64}             Target architecture (default: current arch)
    --output-dir DIR                   Output directory (default: dist/)
    --clean                            Clean build artifacts before building
    --no-upx                           Disable UPX compression
    --debug                            Enable debug mode
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


def get_current_platform() -> str:
    """Get current platform name."""
    if sys.platform == 'win32':
        return 'windows'
    elif sys.platform == 'darwin':
        return 'macos'
    else:
        return 'linux'


def get_current_arch() -> str:
    """Get current architecture."""
    machine = platform.machine().lower()
    if 'x86_64' in machine or 'amd64' in machine:
        return 'x86_64'
    elif 'arm64' in machine or 'aarch64' in machine:
        return 'arm64'
    else:
        return machine


def clean_build_artifacts():
    """Clean build artifacts from previous builds."""
    dirs_to_clean = [
        ROOT / 'build',
        ROOT / 'dist',
        ROOT / '__pycache__',
    ]
    
    for dir_path in dirs_to_clean:
        if dir_path.exists():
            print(f"Removing {dir_path}")
            shutil.rmtree(dir_path)
    
    # Clean .spec files (except the main one)
    for spec_file in ROOT.glob('*.spec'):
        if spec_file.name != 'pyinstaller.spec':
            spec_file.unlink()


def check_dependencies():
    """Check if required dependencies are installed."""
    required_packages = ['PyInstaller', 'pydantic', 'docker', 'aiosqlite']
    missing = []
    
    for package in required_packages:
        try:
            # Try both case-sensitive and lowercase import
            try:
                __import__(package)
            except ImportError:
                __import__(package.lower().replace('-', '_'))
        except ImportError:
            missing.append(package)
    
    if missing:
        print("Error: Missing required packages:")
        for pkg in missing:
            print(f"  - {pkg}")
        print("\nInstall with: pip install " + " ".join(missing))
        return False
    
    return True


def build_executable(
    platform: str = None,
    arch: str = None,
    output_dir: Path = None,
    use_upx: bool = True,
    debug: bool = False,
):
    """
    Build standalone executable.
    
    Args:
        platform: Target platform (windows, macos, linux)
        arch: Target architecture (x86_64, arm64)
        output_dir: Output directory for built executable
        use_upx: Whether to use UPX compression
        debug: Enable debug mode
    """
    # Use current platform/arch if not specified
    if platform is None:
        platform = get_current_platform()
    if arch is None:
        arch = get_current_arch()
    if output_dir is None:
        output_dir = ROOT / 'dist'
    
    print(f"Building CTF Toolkit for {platform} ({arch})")
    print(f"Output directory: {output_dir}")
    
    # Create output directory
    output_dir.mkdir(parents=True, exist_ok=True)
    
    # Build PyInstaller command
    cmd = [
        sys.executable,
        '-m',
        'PyInstaller',
        '--distpath', str(output_dir),
        '--workpath', str(ROOT / 'build'),
    ]
    
    # Add debug options
    if debug:
        cmd.append('--debug=all')
    
    # UPX compression
    if not use_upx:
        cmd.append('--no-upx')
    
    # Add spec file (platform-specific options are in the spec file)
    cmd.append(str(ROOT / 'pyinstaller.spec'))
    
    print(f"Running: {' '.join(cmd)}")
    
    # Execute build
    result = subprocess.run(cmd, cwd=ROOT)
    
    if result.returncode != 0:
        print(f"Build failed with exit code {result.returncode}")
        return False
    
    # Verify output
    if platform == 'windows':
        exe_name = 'ctf-toolkit.exe'
    else:
        exe_name = 'ctf-toolkit'
    
    output_exe = output_dir / exe_name
    if output_exe.exists():
        print(f"\n✓ Build successful!")
        print(f"Executable: {output_exe}")
        print(f"Size: {output_exe.stat().st_size / (1024*1024):.1f} MB")
        return True
    else:
        print(f"✗ Build completed but executable not found: {output_exe}")
        return False


def create_distribution_package(output_dir: Path = None):
    """Create a distribution package with the executable and supporting files."""
    if output_dir is None:
        output_dir = ROOT / 'dist'
    
    dist_package = output_dir / 'ctftoolkit-release'
    if dist_package.exists():
        shutil.rmtree(dist_package)
    dist_package.mkdir(parents=True)
    
    # Copy executable
    if platform.system() == 'Windows':
        exe_name = 'ctf-toolkit.exe'
    else:
        exe_name = 'ctf-toolkit'
    
    src_exe = output_dir / exe_name
    if src_exe.exists():
        shutil.copy2(src_exe, dist_package / exe_name)
    
    # Copy README and license
    for file in ['README.md', 'LICENSE']:
        src = ROOT / file
        if src.exists():
            shutil.copy2(src, dist_package / file)
    
    # Copy setup scripts
    for script in ['setup.bat', 'setup.sh']:
        src = ROOT / script
        if src.exists():
            shutil.copy2(src, dist_package / script)
    
    # Create archive
    archive_name = f"ctftoolkit-{get_current_platform()}-{get_current_arch()}"
    archive_path = output_dir / archive_name
    
    try:
        if platform.system() == 'Windows':
            # Create ZIP on Windows
            shutil.make_archive(str(archive_path), 'zip', dist_package)
        else:
            # Create tar.gz on Unix
            shutil.make_archive(str(archive_path), 'gztar', dist_package)
        
        print(f"✓ Distribution package created: {archive_path}")
        return True
    except Exception as e:
        print(f"✗ Failed to create distribution package: {e}")
        return False


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(description='Build CTF Toolkit standalone executable')
    parser.add_argument('--platform', choices=['windows', 'macos', 'linux'],
                       help='Target platform (default: current platform)')
    parser.add_argument('--arch', choices=['x86_64', 'arm64'],
                       help='Target architecture (default: current arch)')
    parser.add_argument('--output-dir', type=Path, help='Output directory')
    parser.add_argument('--clean', action='store_true', help='Clean build artifacts')
    parser.add_argument('--no-upx', action='store_true', help='Disable UPX compression')
    parser.add_argument('--debug', action='store_true', help='Enable debug mode')
    parser.add_argument('--no-package', action='store_true', 
                       help='Skip creating distribution package')
    
    args = parser.parse_args()
    
    # Check dependencies
    if not check_dependencies():
        sys.exit(1)
    
    # Clean if requested
    if args.clean:
        clean_build_artifacts()
    
    # Build executable
    success = build_executable(
        platform=args.platform,
        arch=args.arch,
        output_dir=args.output_dir,
        use_upx=not args.no_upx,
        debug=args.debug,
    )
    
    if not success:
        sys.exit(1)
    
    # Create distribution package
    if not args.no_package:
        create_distribution_package(args.output_dir)
    
    print("\nBuild complete!")


if __name__ == '__main__':
    main()
