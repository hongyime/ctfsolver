#!/usr/bin/env python3
"""
Tier 1 Test: T1-005 & T1-006 Security Guards

Tests sudo prompt detection and network isolation policies.
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from tests.hands_on._lib import TestRunner, TestStatus, print_banner


def test_sudo_detection() -> dict:
    """Test sudo/password prompt detection."""
    from src.ctf_core.utils.sudo_guard import detect_sudo_prompt
    
    should_detect = [
        ("[sudo] password for user:", True),
        ("password:", True),
        ("please enter sudo password:", True),
        ("sorry, try again:", True),
        ("sudo: a password is required", True),
        ("Enter passphrase for key '/home/user/.ssh/id_rsa':", True),
    ]
    
    should_not_detect = [
        ("user@example.com:~$", False),
        ("Enter password for encryption:", False),
        ("Welcome to the system", False),
        ("Connection refused", False),
        ("No such file or directory", False),
    ]
    
    all_cases = should_detect + should_not_detect
    passed = 0
    failed = []
    
    for output, expected in all_cases:
        detected = detect_sudo_prompt(output)
        if detected == expected:
            passed += 1
        else:
            failed.append(f"'{output[:30]}...' expected={expected}, got={detected}")
    
    return {
        "passed": len(failed) == 0,
        "message": f"Sudo detection: {passed}/{len(all_cases)} correct",
        "details": {
            "test_cases": len(all_cases),
            "passed": passed,
            "failed": failed
        }
    }


def test_network_guard_private() -> dict:
    """Test that private network ranges are blocked."""
    from src.ctf_core.utils.net_guard import check_connection_allowed
    
    # Should be blocked (private ranges)
    private_ips = [
        "127.0.0.1",      # Loopback
        "127.0.0.2",      # Loopback
        "10.0.0.1",       # Private Class A
        "10.255.255.255",  # Private Class A
        "172.16.0.1",     # Private Class B
        "172.31.255.255", # Private Class B
        "192.168.0.1",    # Private Class C
        "192.168.255.255", # Private Class C
        "169.254.1.1",   # Link-local
    ]
    
    blocked_count = 0
    failed = []
    
    for ip in private_ips:
        allowed, reason = check_connection_allowed(ip, allow_private=False)
        if not allowed:
            blocked_count += 1
        else:
            failed.append(f"{ip} should be blocked but was allowed")
    
    return {
        "passed": len(failed) == 0,
        "message": f"Private IPs: {blocked_count}/{len(private_ips)} blocked correctly",
        "details": {
            "test_cases": len(private_ips),
            "blocked": blocked_count,
            "failed": failed
        }
    }


def test_network_guard_public() -> dict:
    """Test that public IPs are allowed."""
    from src.ctf_core.utils.net_guard import check_connection_allowed
    
    # Should be allowed (public ranges)
    public_ips = [
        "8.8.8.8",               # Google DNS
        "1.1.1.1",               # Cloudflare DNS
        "185.199.108.153",       # GitHub
        "151.101.1.140",         # Reddit
        "104.16.85.20",          # Cloudflare
    ]
    
    allowed_count = 0
    failed = []
    
    for ip in public_ips:
        allowed, reason = check_connection_allowed(ip, allow_private=False)
        if allowed:
            allowed_count += 1
        else:
            failed.append(f"{ip} should be allowed but was blocked: {reason}")
    
    return {
        "passed": len(failed) == 0,
        "message": f"Public IPs: {allowed_count}/{len(public_ips)} allowed correctly",
        "details": {
            "test_cases": len(public_ips),
            "allowed": allowed_count,
            "failed": failed
        }
    }


def test_network_guard_hostnames() -> dict:
    """Test that hostnames are allowed (can't determine range)."""
    from src.ctf_core.utils.net_guard import check_connection_allowed
    
    hostnames = [
        "scanme.nmap.org",
        "google.com",
        "example.com",
        "github.com",
    ]
    
    allowed_count = 0
    
    for hostname in hostnames:
        allowed, reason = check_connection_allowed(hostname)
        if allowed:
            allowed_count += 1
    
    return {
        "passed": allowed_count == len(hostnames),
        "message": f"Hostnames: {allowed_count}/{len(hostnames)} allowed (expected since range unknown)",
        "details": {
            "test_cases": len(hostnames),
            "allowed": allowed_count
        }
    }


def run_tests():
    """Run all Tier 1 security guard tests."""
    print_banner()
    
    runner = TestRunner(tier=1, suite_name="Security Guard Tests")
    runner.print_header("Tier 1: Security Guards (Sudo & Network)")
    
    print("Testing sudo prompt detection and network isolation policies.\n")
    
    runner.run_test(test_sudo_detection, "T1-005", "Sudo Prompt Detection")
    runner.run_test(test_network_guard_private, "T1-006a", "Private Network Blocking")
    runner.run_test(test_network_guard_public, "T1-006b", "Public Network Allowing")
    runner.run_test(test_network_guard_hostnames, "T1-006c", "Hostname Handling")
    
    result = runner.complete()
    runner.print_summary()
    
    return 0 if result.failed == 0 and result.errors == 0 else 1


if __name__ == "__main__":
    sys.exit(run_tests())
