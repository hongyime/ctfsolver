#!/usr/bin/env python3
"""
Tier 1 Test: T1-004 Flag Detection

Tests CTF flag detection in various output formats.
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from tests.hands_on._lib import TestRunner, TestStatus, print_banner


def test_flag_detection_standard() -> dict:
    """Test detection of standard CTF flag formats."""
    from src.ctf_core.utils.flag_detector import FlagPatternDetector
    
    detector = FlagPatternDetector()
    
    test_cases = [
        # Standard CTF flags
        ("CTF{this_is_valid}", ["CTF{this_is_valid}"]),
        ("flag{simple_flag}", ["flag{simple_flag}"]),
        ("Flag{capital_flag}", ["Flag{capital_flag}"]),
        ("ctf{lowercase}", ["ctf{lowercase}"]),
        
        # Complex flags
        ("CTF{fl4g_w1th_numb3rs_4nd_und3rsc0r3s}", 
         ["CTF{fl4g_w1th_numb3rs_4nd_und3rsc0r3s}"]),
        
        # Multiple flags in one output
        ("First CTF{a1b2c3} and second flag{d4e5f6}", 
         ["CTF{a1b2c3}", "flag{d4e5f6}"]),
    ]
    
    passed = 0
    failed = []
    
    for output, expected in test_cases:
        detected = detector.extract_flags(output)
        if set(detected) == set(expected):
            passed += 1
        else:
            failed.append(f"Expected {expected}, got {detected}")
    
    return {
        "passed": len(failed) == 0,
        "message": f"Standard flags: {passed}/{len(test_cases)} detected correctly",
        "details": {
            "test_cases": len(test_cases),
            "passed": passed,
            "failed": failed
        }
    }


def test_flag_detection_hex() -> dict:
    """Test detection of hex-style flags (MD5/SHA256)."""
    from src.ctf_core.utils.flag_detector import FlagPatternDetector
    
    detector = FlagPatternDetector()
    
    test_cases = [
        # MD5 style (32 chars)
        ("hash: 5ebe2294ecd0e0f08eab7690d2a6ee69", 
         ["5ebe2294ecd0e0f08eab7690d2a6ee69"]),
        
        # SHA1 style (40 chars)
        ("sha1: da39a3ee5e6b4b0d3255bfef95601890afd80709",
         ["da39a3ee5e6b4b0d3255bfef95601890afd80709"]),
        
        # Random alphanumeric (32 chars)
        ("password hash: a87ff679a2f3e71d9181a67b7542122c",
         ["a87ff679a2f3e71d9181a67b7542122c"]),
    ]
    
    passed = 0
    failed = []
    
    for output, expected in test_cases:
        detected = detector.extract_flags(output)
        if set(detected) == set(expected):
            passed += 1
        else:
            failed.append(f"Expected {expected}, got {detected}")
    
    return {
        "passed": len(failed) == 0,
        "message": f"Hex flags: {passed}/{len(test_cases)} detected correctly",
        "details": {
            "test_cases": len(test_cases),
            "passed": passed,
            "failed": failed
        }
    }


def test_flag_detection_no_false_positives() -> dict:
    """Test that normal text doesn't trigger false positives."""
    from src.ctf_core.utils.flag_detector import FlagPatternDetector
    
    detector = FlagPatternDetector()
    
    normal_outputs = [
        "This is normal text with no flags",
        "Connect to server at 192.168.1.1",
        "User admin logged in",
        "HTTP/1.1 200 OK",
        "Apache/2.4.41 Server",
    ]
    
    false_positives = 0
    for output in normal_outputs:
        flags = detector.extract_flags(output)
        if flags:
            false_positives += 1
    
    return {
        "passed": false_positives == 0,
        "message": f"No false positives in {len(normal_outputs)} normal outputs" if false_positives == 0 else f"{false_positives} false positives found",
        "details": {
            "normal_outputs_tested": len(normal_outputs),
            "false_positives": false_positives
        }
    }


def test_flag_detection_complex_output() -> dict:
    """Test flag detection in complex tool output."""
    from src.ctf_core.utils.flag_detector import FlagPatternDetector
    
    detector = FlagPatternDetector()
    
    complex_output = """
Starting Nmap 7.91 ( https://nmap.org )
Nmap scan report for scanme.nmap.org (45.33.32.156)
Host is up (0.029s latency).

PORT     STATE SERVICE
22/tcp   open  ssh
80/tcp   open  http
9929/tcp open  nmap-echo

Interesting findings:
- Admin panel found at /admin
- Default credentials may work
- Flag: CTF{nmap_scan_successful}
- Backup file: flag{default_creds_work}

Nmap done: 1 IP address (1 host up) scanned in 0.32 seconds
"""
    
    detected = detector.extract_flags(complex_output)
    
    expected = ["CTF{nmap_scan_successful}", "flag{default_creds_work}"]
    
    return {
        "passed": set(detected) == set(expected),
        "message": f"Found {len(detected)} flags in complex output",
        "details": {
            "detected_flags": detected,
            "expected_flags": expected
        }
    }


def run_tests():
    """Run all Tier 1 flag detection tests."""
    print_banner()
    
    runner = TestRunner(tier=1, suite_name="Flag Detection Tests")
    runner.print_header("Tier 1: CTF Flag Detection")
    
    print("Testing CTF flag pattern detection in various output formats.\n")
    
    runner.run_test(test_flag_detection_standard, "T1-004a", "Standard CTF Flags")
    runner.run_test(test_flag_detection_hex, "T1-004b", "Hex-style Flags")
    runner.run_test(test_flag_detection_no_false_positives, "T1-004c", "No False Positives")
    runner.run_test(test_flag_detection_complex_output, "T1-004d", "Complex Tool Output")
    
    result = runner.complete()
    runner.print_summary()
    
    return 0 if result.failed == 0 and result.errors == 0 else 1


if __name__ == "__main__":
    sys.exit(run_tests())
