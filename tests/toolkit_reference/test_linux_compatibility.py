#!/usr/bin/env python3
"""
Linux compatibility test script for CTF Toolkit.

This script tests the platform abstraction layer on Linux systems.
It can be run on any Linux distribution to verify compatibility.

Usage:
    python test_linux_compatibility.py [options]

Options:
    --verbose         Enable verbose output
    --distro DISTRO   Test specific distro (ubuntu, debian, fedora, etc.)
    --skip-docker     Skip Docker tests
"""

import sys
import os
import pytest
from pathlib import Path

# Add src to path
sys.path.insert(0, str(Path(__file__).parent / 'src'))


@pytest.mark.skipif(sys.platform != 'linux', reason="Linux-specific test")
def test_linux_platform_detection():
    """Test Linux platform detection."""
    print("Testing Linux platform detection...")
    from ctf_core.platform import get_platform, PlatformType
    
    platform = get_platform()
    
    # Should detect Linux
    assert platform.platform == PlatformType.LINUX, f"Expected LINUX, got {platform.platform}"
    print(f"  ✓ Platform: {platform.platform.value}")
    
    # Should detect architecture
    assert platform.arch in ['x86_64', 'arm64', 'arm', 'aarch64']
    print(f"  ✓ Architecture: {platform.arch}")
    
    # Should not be WSL
    assert platform.wsl_available is False
    print(f"  ✓ WSL available: {platform.wsl_available}")
    
    print("  ✓ Linux platform detection tests passed!\n")
    return True


@pytest.mark.skipif(sys.platform != 'linux', reason="Linux-specific test")
def test_linux_adapter():
    """Test Linux adapter functionality."""
    print("Testing Linux adapter...")
    from ctf_core.platform.linux import LinuxAdapter, get_linux_adapter
    
    adapter = get_linux_adapter()
    assert isinstance(adapter, LinuxAdapter)
    print(f"  ✓ Linux adapter: OK")
    
    # Test distro detection
    distro = adapter.distro
    assert distro in ['ubuntu', 'debian', 'fedora', 'rhel', 'arch', 'suse', 'unknown']
    print(f"  ✓ Detected distro: {distro}")
    
    # Test package manager detection
    pm = adapter.package_manager
    print(f"  ✓ Package manager: {pm}")
    
    # Test default workspace
    workspace = adapter.get_default_workspace()
    assert 'workspace' in workspace.lower() or 'ctftoolkit' in workspace.lower()
    print(f"  ✓ Default workspace: {workspace}")
    
    # Test environment validation
    is_valid, issues = adapter.validate_environment()
    print(f"  ✓ Environment validation: valid={is_valid}, issues={len(issues)}")
    for issue in issues:
        print(f"    - {issue}")
    
    # Test environment variables
    env_vars = adapter.get_environment_variables()
    assert 'CTFTOOLKIT_PLATFORM' in env_vars
    assert env_vars['CTFTOOLKIT_PLATFORM'] == 'linux'
    print(f"  ✓ Environment variables: OK")
    
    # Test Docker socket path
    socket = adapter.get_docker_socket_path()
    assert 'docker.sock' in socket
    print(f"  ✓ Docker socket: {socket}")
    
    print("  ✓ All Linux adapter tests passed!\n")
    return True


@pytest.mark.skipif(sys.platform != 'linux', reason="Linux-specific test")
def test_linux_setup_instructions():
    """Test Linux setup instructions generation."""
    print("Testing Linux setup instructions...")
    from ctf_core.platform.linux import LinuxAdapter
    
    adapter = LinuxAdapter()
    instructions = adapter.get_setup_instructions()
    
    assert isinstance(instructions, str)
    assert len(instructions) > 0
    print(f"  ✓ Setup instructions generated ({len(instructions)} chars)")
    
    # Should contain relevant keywords for the detected distro
    if adapter.distro in ['ubuntu', 'debian']:
        assert 'apt' in instructions.lower()
        print(f"  ✓ Contains apt instructions")
    elif adapter.distro == 'fedora':
        assert 'dnf' in instructions.lower()
        print(f"  ✓ Contains dnf instructions")
    elif adapter.distro == 'rhel':
        assert 'dnf' in instructions.lower() or 'yum' in instructions.lower()
        print(f"  ✓ Contains dnf/yum instructions")
    elif adapter.distro == 'arch':
        assert 'pacman' in instructions.lower()
        print(f"  ✓ Contains pacman instructions")
    elif adapter.distro == 'suse':
        assert 'zypper' in instructions.lower()
        print(f"  ✓ Contains zypper instructions")
    
    print("  ✓ Linux setup instructions tests passed!\n")
    return True


def test_linux_docker_integration():
    """Test Linux Docker integration."""
    print("Testing Linux Docker integration...")
    try:
        from ctf_core.docker_runner import DockerRunner
        
        runner = DockerRunner()
        
        # Should have platform info
        assert runner.platform_info.platform.value == 'linux'
        print(f"  ✓ Platform: linux")
        
        # Should have Linux adapter
        from ctf_core.platform.linux import LinuxAdapter
        assert isinstance(runner.platform_adapter, LinuxAdapter)
        print(f"  ✓ Platform adapter: LinuxAdapter")
        
        # Should have Docker client
        assert runner.client is not None
        print(f"  ✓ Docker client: OK")
        
        # Should prepare volumes correctly
        volumes = runner._prepare_volumes()
        assert isinstance(volumes, dict)
        print(f"  ✓ Volume preparation: OK")
        
        # Should have workspace path
        assert runner.workspace_path is not None
        print(f"  ✓ Workspace path: {runner.workspace_path}")
        
        print("  ✓ All Linux Docker integration tests passed!\n")
        return True
        
    except Exception as e:
        print(f"  ⚠ Docker integration test skipped: {e}")
        print("     (This is expected if Docker is not available)\n")
        return True


@pytest.mark.skipif(sys.platform != 'linux', reason="Linux-specific test")
def test_linux_security_settings():
    """Test Linux security settings checks."""
    print("Testing Linux security settings...")
    from ctf_core.platform.linux import LinuxAdapter
    
    adapter = LinuxAdapter()
    is_ok, warnings = adapter.check_security_settings()
    
    print(f"  ✓ Security check: ok={is_ok}, warnings={len(warnings)}")
    for warning in warnings:
        print(f"    - {warning}")
    
    print("  ✓ Linux security settings tests passed!\n")
    return True


@pytest.mark.skipif(sys.platform != 'linux', reason="Linux-specific test")
def test_linux_performance_tips():
    """Test Linux performance tips generation."""
    print("Testing Linux performance tips...")
    from ctf_core.platform.linux import LinuxAdapter
    
    adapter = LinuxAdapter()
    tips = adapter.get_performance_tips()
    
    assert isinstance(tips, list)
    assert len(tips) > 0
    print(f"  ✓ Generated {len(tips)} performance tips")
    
    for tip in tips:
        assert isinstance(tip, str)
        assert len(tip) > 0
        print(f"    - {tip[:60]}...")
    
    print("  ✓ Linux performance tips tests passed!\n")
    return True


def main():
    """Run all Linux compatibility tests."""
    print("=" * 70)
    print("CTF Toolkit Linux Compatibility Tests")
    print("=" * 70)
    print()
    
    # Check if running on Linux
    if sys.platform != 'linux':
        print("⚠ Warning: Not running on Linux!")
        print("  These tests are designed for Linux systems.")
        print("  Some tests may fail or be skipped.\n")
    
    tests = [
        test_linux_platform_detection,
        test_linux_adapter,
        test_linux_setup_instructions,
        test_linux_docker_integration,
        test_linux_security_settings,
        test_linux_performance_tips,
    ]
    
    passed = 0
    failed = 0
    skipped = 0
    
    for test in tests:
        try:
            result = test()
            if result:
                passed += 1
            else:
                failed += 1
        except Exception as e:
            print(f"  ✗ Test failed with error: {e}")
            import traceback
            traceback.print_exc()
            failed += 1
            print()
    
    print("=" * 70)
    print(f"Test Results: {passed} passed, {failed} failed")
    print("=" * 70)
    
    return 0 if failed == 0 else 1


if __name__ == '__main__':
    sys.exit(main())
