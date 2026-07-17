#!/usr/bin/env python3
"""
Tier 1 Runner: Local Environment Tests

Runs all Tier 1 tests: Docker, Database, Sanitization, Flag Detection, Security Guards, MCP Health

Usage:
    python tests/hands_on/run_tier1.py          # Run all Tier 1 tests
    python tests/hands_on/run_tier1.py --t1-001 # Run specific test only
    python tests/hands_on/run_tier1.py --verbose # Verbose output
"""

import sys
import io
import asyncio
import argparse

# Force UTF-8 output on Windows so Unicode box chars in banners render correctly
if sys.platform == "win32" and hasattr(sys.stdout, "buffer"):
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")
    sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding="utf-8", errors="replace")
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from tests.hands_on._lib import TestRunner, TestStatus, print_banner, print_section, ReportGenerator


def get_tier1_tests():
    """Get list of Tier 1 test modules."""
    tier1_dir = Path(__file__).parent / "tier1"
    
    test_files = [
        ("T1-001", "Docker Images", "t1_001_docker_images.py", "test_docker_images"),
        ("T1-002", "Database Init", "t1_002_database.py", "test_database_init"),
        ("T1-003", "Sanitization", "t1_003_sanitization.py", "test_sanitization_valid"),
        ("T1-004", "Flag Detection", "t1_004_flag_detection.py", "test_flag_detection_standard"),
        ("T1-005", "Security Guards", "t1_005_006_security_guards.py", "test_sudo_detection"),
        ("T1-006", "Network Guard", "t1_005_006_security_guards.py", "test_network_guard_private"),
        ("T1-007", "MCP Health", "t1_007_mcp_health.py", "test_mcp_server_import"),
    ]
    
    return test_files


def run_all_tier1_tests(verbose: bool = True) -> int:
    """Run all Tier 1 tests."""
    print_banner()
    print_section("Tier 1: Local Environment Tests")
    
    print("This tier validates core infrastructure without external dependencies.")
    print("Tests: Docker images, Database, Command sanitization, Flag detection,")
    print("       Security guards (sudo/network), MCP server health\n")
    
    runner = TestRunner(tier=1, suite_name="Tier 1 - Local Environment")
    runner.verbose = verbose
    
    # Import and run all test modules
    from tests.hands_on.tier1 import t1_001_docker_images
    from tests.hands_on.tier1 import t1_002_database
    from tests.hands_on.tier1 import t1_003_sanitization
    from tests.hands_on.tier1 import t1_004_flag_detection
    from tests.hands_on.tier1 import t1_005_006_security_guards
    from tests.hands_on.tier1 import t1_007_mcp_health
    
    # Run tests from each module
    tests = [
        (t1_001_docker_images.test_docker_images, "T1-001", "Docker Image Verification"),
        (t1_001_docker_images.test_docker_connectivity, "T1-002", "Docker Daemon Connectivity"),
        (t1_002_database.test_database_init, "T1-003", "Database Initialization"),
        (t1_002_database.test_database_crud, "T1-004", "Database CRUD Operations"),
        (t1_003_sanitization.test_sanitization_valid, "T1-005", "Valid Commands Allowed"),
        (t1_003_sanitization.test_sanitization_dangerous, "T1-006", "Dangerous Commands Blocked"),
        (t1_003_sanitization.test_command_whitelist, "T1-007", "Command Whitelist Check"),
        (t1_004_flag_detection.test_flag_detection_standard, "T1-008", "Standard CTF Flags"),
        (t1_004_flag_detection.test_flag_detection_hex, "T1-009", "Hex-style Flags"),
        (t1_004_flag_detection.test_flag_detection_no_false_positives, "T1-010", "No False Positives"),
        (t1_004_flag_detection.test_flag_detection_complex_output, "T1-011", "Complex Tool Output"),
        (t1_005_006_security_guards.test_sudo_detection, "T1-012", "Sudo Prompt Detection"),
        (t1_005_006_security_guards.test_network_guard_private, "T1-013", "Private Network Blocking"),
        (t1_005_006_security_guards.test_network_guard_public, "T1-014", "Public Network Allowing"),
        (t1_005_006_security_guards.test_network_guard_hostnames, "T1-015", "Hostname Handling"),
        (t1_007_mcp_health.test_mcp_server_import, "T1-016", "MCP Server Import"),
        (t1_007_mcp_health.test_validate_environment, "T1-017", "Environment Validation"),
        (t1_007_mcp_health.test_health_check_function, "T1-018", "Health Check Function"),
    ]
    
    print(f"Running {len(tests)} tests...\n")
    
    for test_func, test_id, test_name in tests:
        runner.run_test(test_func, test_id, test_name)
    
    # Complete and summarize
    result = runner.complete()
    
    print("\n" + "=" * 60)
    print("TIER 1 SUMMARY")
    print("=" * 60)
    
    runner.print_summary()
    
    # Generate report
    print("\nGenerating report...")
    generator = ReportGenerator()
    _, report_path = generator.generate_markdown([result])
    print(f"Report saved to: {report_path}")
    
    # Return exit code
    if result.failed > 0 or result.errors > 0:
        print(f"\n[RESULT] Tier 1 completed with {result.failed} failures")
        return 1
    else:
        print(f"\n[RESULT] Tier 1 completed successfully!")
        return 0


def main():
    parser = argparse.ArgumentParser(description="Run Tier 1 Local Environment Tests")
    parser.add_argument("--quiet", "-q", action="store_true", help="Minimal output")
    parser.add_argument("--verbose", "-v", action="store_true", help="Verbose output")
    parser.add_argument("--report", "-r", action="store_true", help="Generate report")
    
    args = parser.parse_args()
    
    verbose = not args.quiet
    if args.verbose:
        verbose = True
    
    exit_code = run_all_tier1_tests(verbose=verbose)
    
    sys.exit(exit_code)


if __name__ == "__main__":
    main()
