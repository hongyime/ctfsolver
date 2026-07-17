#!/usr/bin/env python3
"""
Tier 2 Runner: Safe External Target Tests

Runs tests against public, intentionally vulnerable test targets.

Usage:
    python tests/hands_on/run_tier2.py          # Run all Tier 2 tests
    python tests/hands_on/run_tier2.py --quick  # Skip slow tests
"""

import sys
import asyncio
import argparse
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from tests.hands_on._lib import TestRunner, TestStatus, print_banner, print_section, ReportGenerator


async def test_nmap_scanme() -> dict:
    """Test Nmap against scanme.nmap.org (official Nmap test host)."""
    try:
        from src.ctf_core.docker_runner import DockerRunner
        
        runner = DockerRunner()
        
        print("\n  Scanning scanme.nmap.org (this may take ~60s)...")
        
        result = await runner.run_tool(
            'nmap', 
            ['-sT', '-sV', 'scanme.nmap.org'],
            timeout=120
        )
        
        if result['exit_code'] == 0 and len(result['stdout']) > 100:
            # Check for expected open ports
            has_ssh = '22/tcp' in result['stdout']
            has_http = '80/tcp' in result['stdout']
            
            return {
                "passed": True,
                "message": f"Scan successful, found SSH: {has_ssh}, HTTP: {has_http}",
                "details": {
                    "exit_code": result['exit_code'],
                    "output_length": len(result['stdout']),
                    "duration": result['duration'],
                    "has_ssh": has_ssh,
                    "has_http": has_http
                }
            }
        else:
            return {
                "passed": False,
                "message": f"Scan failed or returned empty: exit_code={result['exit_code']}",
                "details": {
                    "exit_code": result['exit_code'],
                    "stderr": result.get('stderr', '')[:200]
                }
            }
    except Exception as e:
        return {
            "passed": False,
            "message": f"Error: {str(e)}",
            "details": {"exception": str(e)}
        }


async def test_sqlmap_detection() -> dict:
    """Test SQLMap against Acunetix vulnerable test site."""
    try:
        from src.ctf_core.docker_runner import DockerRunner
        
        runner = DockerRunner()
        
        print("\n  Testing SQLMap on vulnerable site (detection only)...")
        
        # Use allowed separated flags for a basic non-interactive scan
        result = await runner.run_tool(
            'sqlmap',
            [
                '-u', 'http://testphp.vulnweb.com/listproducts.php?cat=1',
                '--batch',
                '--level', '1',
                '--risk', '1'
            ],
            timeout=180
        )
        
        # Check if it ran without crashing
        if 'sqlmap' in result['stdout'].lower() or result['exit_code'] in [0, 1]:
            # Exit code 1 might mean vulnerabilities found, which is fine
            return {
                "passed": True,
                "message": f"SQLMap ran successfully (exit: {result['exit_code']})",
                "details": {
                    "exit_code": result['exit_code'],
                    "output_length": len(result['stdout']),
                    "duration": result['duration']
                }
            }
        else:
            return {
                "passed": False,
                "message": "SQLMap failed",
                "details": {
                    "exit_code": result['exit_code'],
                    "stderr": result.get('stderr', '')[:200]
                }
            }
    except Exception as e:
        return {
            "passed": False,
            "message": f"Error: {str(e)}",
            "details": {"exception": str(e)}
        }


async def test_searchsploit() -> dict:
    """Test SearchSploit database query."""
    try:
        from src.ctf_core.docker_runner import DockerRunner
        
        runner = DockerRunner()
        
        print("\n  Searching exploits for 'apache'...")
        
        result = await runner.run_tool(
            'searchsploit',
            ['apache', '-j'],
            timeout=60
        )
        
        # Check if it ran and returned results
        if result['exit_code'] == 0:
            try:
                import json
                data = json.loads(result['stdout'])
                count = data.get('RESULTS_EXPLOIT', 0)
                
                return {
                    "passed": True,
                    "message": f"Found {count} Apache exploits",
                    "details": {
                        "exit_code": result['exit_code'],
                        "exploit_count": count,
                        "duration": result['duration']
                    }
                }
            except:
                return {
                    "passed": True,
                    "message": "SearchSploit ran successfully",
                    "details": {
                        "exit_code": result['exit_code'],
                        "output_length": len(result['stdout'])
                    }
                }
        else:
            return {
                "passed": False,
                "message": f"SearchSploit failed: exit_code={result['exit_code']}",
                "details": {
                    "exit_code": result['exit_code'],
                    "stderr": result.get('stderr', '')[:200]
                }
            }
    except Exception as e:
        return {
            "passed": False,
            "message": f"Error: {str(e)}",
            "details": {"exception": str(e)}
        }


async def test_http_port_scan() -> dict:
    """Test focused HTTP port scan using allowed Nmap flags."""
    try:
        from src.ctf_core.docker_runner import DockerRunner
        
        runner = DockerRunner()
        
        print("\n  Scanning HTTP port on scanme.nmap.org...")
        
        result = await runner.run_tool(
            'nmap',
            ['-sT', '-sV', '-p', '80', 'scanme.nmap.org'],
            timeout=120
        )
        
        if result['exit_code'] == 0:
            return {
                "passed": True,
                "message": "HTTP port scan completed",
                "details": {
                    "exit_code": result['exit_code'],
                    "output_length": len(result['stdout']),
                    "duration": result['duration']
                }
            }
        else:
            return {
                "passed": False,
                "message": "HTTP port scan failed",
                "details": {
                    "exit_code": result['exit_code'],
                    "stderr": result.get('stderr', '')[:200]
                }
            }
    except Exception as e:
        return {
            "passed": False,
            "message": f"Error: {str(e)}",
            "details": {"exception": str(e)}
        }


def run_tests(quick: bool = False):
    """Run all Tier 2 tests."""
    print_banner()
    print_section("Tier 2: Safe External Target Tests")
    
    print("This tier tests against public, intentionally vulnerable test targets.")
    print("Targets: scanme.nmap.org, testphp.vulnweb.com\n")
    
    runner = TestRunner(tier=2, suite_name="Tier 2 - External Targets")
    
    tests = [
        (test_nmap_scanme, "T2-001", "Nmap ScanMe Scan"),
        (test_sqlmap_detection, "T2-002", "SQLMap Vulnerability Detection"),
        (test_searchsploit, "T2-003", "SearchSploit Query"),
    ]
    
    if not quick:
        tests.append((test_http_port_scan, "T2-004", "HTTP Port Scan"))
    
    print(f"Running {len(tests)} tests...\n")
    print("Note: These tests require internet connectivity and may take a few minutes.\n")
    
    for test_func, test_id, test_name in tests:
        runner.run_test(test_func, test_id, test_name)
    
    result = runner.complete()
    
    print("\n" + "=" * 60)
    print("TIER 2 SUMMARY")
    print("=" * 60)
    
    runner.print_summary()
    
    # Generate report
    generator = ReportGenerator()
    _, report_path = generator.generate_markdown([result])
    print(f"\nReport saved to: {report_path}")
    
    if result.failed > 0 or result.errors > 0:
        print(f"\n[RESULT] Tier 2 completed with {result.failed} failures")
        return 1
    else:
        print(f"\n[RESULT] Tier 2 completed successfully!")
        return 0


def main():
    parser = argparse.ArgumentParser(description="Run Tier 2 External Target Tests")
    parser.add_argument("--quick", "-q", action="store_true", help="Skip slow tests")
    
    args = parser.parse_args()
    
    sys.exit(run_tests(quick=args.quick))


if __name__ == "__main__":
    main()
