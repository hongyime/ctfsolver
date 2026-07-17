#!/usr/bin/env python3
"""
Tier 3 Runner: Self-Hosted Vulnerable Targets

Runs tests against self-hosted vulnerable environments (DVWA, Juice Shop, etc.)

Usage:
    python tests/hands_on/run_tier3.py          # Run all Tier 3 tests
    python tests/hands_on/run_tier3.py --setup   # Setup Docker containers first
    python tests/hands_on/run_tier3.py --cleanup # Stop and remove containers after
"""

import sys
import asyncio
import subprocess
import argparse
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from tests.hands_on._lib import TestRunner, TestStatus, print_banner, print_section, ReportGenerator


# Docker vulnerable image configurations
DOCKER_TARGETS = {
    "dvwa": {
        "image": "vulnerables/web-dvwa",
        "name": "ctf-test-dvwa",
        "port": 8080,
        "description": "Damn Vulnerable Web Application"
    },
    "juice-shop": {
        "image": "bkimminich/juice-shop",
        "name": "ctf-test-juice-shop",
        "port": 3000,
        "description": "OWASP Juice Shop"
    }
}


def setup_docker_targets():
    """Setup Docker vulnerable targets."""
    print("\n[SETUP] Pulling and starting vulnerable Docker containers...\n")
    
    results = {}
    
    for target_id, config in DOCKER_TARGETS.items():
        print(f"  Setting up {config['description']}...")
        
        try:
            # Pull image
            subprocess.run(
                ['docker', 'pull', config['image']],
                capture_output=True,
                timeout=300
            )
            
            # Stop existing container if any
            subprocess.run(
                ['docker', 'stop', config['name']],
                capture_output=True,
                timeout=10
            )
            subprocess.run(
                ['docker', 'rm', config['name']],
                capture_output=True,
                timeout=10
            )
            
            # Run container
            subprocess.run(
                ['docker', 'run', '-d', 
                 '--name', config['name'],
                 '-p', f"{config['port']}:80",
                 config['image']],
                capture_output=True,
                timeout=60
            )
            
            print(f"    [OK] {config['description']} started on port {config['port']}")
            results[target_id] = True
            
        except Exception as e:
            print(f"    [FAIL] {config['description']}: {str(e)}")
            results[target_id] = False
    
    return results


def cleanup_docker_targets():
    """Stop and remove Docker containers."""
    print("\n[CLEANUP] Stopping vulnerable Docker containers...\n")
    
    for target_id, config in DOCKER_TARGETS.items():
        try:
            subprocess.run(
                ['docker', 'stop', config['name']],
                capture_output=True,
                timeout=10
            )
            subprocess.run(
                ['docker', 'rm', config['name']],
                capture_output=True,
                timeout=10
            )
            print(f"  [OK] {config['description']} stopped and removed")
        except:
            print(f"  [--] {config['description']} not running")


def check_docker_running(target_id: str) -> bool:
    """Check if a Docker container is running."""
    config = DOCKER_TARGETS.get(target_id)
    if not config:
        return False
    
    try:
        result = subprocess.run(
            ['docker', 'ps', '--filter', f'name={config["name"]}', '--format', '{{.Names}}'],
            capture_output=True,
            text=True,
            timeout=5
        )
        return config['name'] in result.stdout
    except:
        return False


async def test_dvwa_nmap() -> dict:
    """Test Nmap scan against DVWA container."""
    try:
        from src.ctf_core.docker_runner import DockerRunner
        
        if not check_docker_running("dvwa"):
            return {
                "passed": False,
                "message": "DVWA container not running. Run with --setup first.",
                "details": {"container": "dvwa"}
            }
        
        runner = DockerRunner()
        
        print("\n  Scanning DVWA on localhost:8080...")
        
        result = await runner.run_tool(
            'nmap',
            ['-sV', '-p', '8080', 'localhost'],
            timeout=60
        )
        
        if result['exit_code'] == 0:
            return {
                "passed": True,
                "message": f"DVWA scan completed",
                "details": {
                    "exit_code": result['exit_code'],
                    "duration": result['duration'],
                    "has_output": len(result['stdout']) > 0
                }
            }
        else:
            return {
                "passed": False,
                "message": "Scan failed",
                "details": {"exit_code": result['exit_code']}
            }
    except Exception as e:
        return {
            "passed": False,
            "message": f"Error: {str(e)}",
            "details": {"exception": str(e)}
        }


async def test_dvwa_sqlmap() -> dict:
    """Test SQLMap against DVWA."""
    try:
        from src.ctf_core.docker_runner import DockerRunner
        
        if not check_docker_running("dvwa"):
            return {
                "passed": False,
                "message": "DVWA container not running. Run with --setup first.",
                "details": {"container": "dvwa"}
            }
        
        runner = DockerRunner()
        
        print("\n  Testing SQLMap against DVWA (basic test)...")
        
        # Basic SQLMap test on DVWA using whitelist-safe arguments
        result = await runner.run_tool(
            'sqlmap',
            [
                '-u', 'http://localhost:8080/login.php',
                '--batch',
                '--level', '1'
            ],
            timeout=180
        )
        
        # Exit code 0 or 1 (vulnerability found) is success
        if result['exit_code'] in [0, 1]:
            return {
                "passed": True,
                "message": f"SQLMap completed (exit: {result['exit_code']})",
                "details": {
                    "exit_code": result['exit_code'],
                    "duration": result['duration']
                }
            }
        else:
            return {
                "passed": False,
                "message": "SQLMap failed",
                "details": {"exit_code": result['exit_code']}
            }
    except Exception as e:
        return {
            "passed": False,
            "message": f"Error: {str(e)}",
            "details": {"exception": str(e)}
        }


async def test_juice_shop() -> dict:
    """Test against OWASP Juice Shop."""
    try:
        from src.ctf_core.docker_runner import DockerRunner
        
        if not check_docker_running("juice-shop"):
            return {
                "passed": False,
                "message": "Juice Shop container not running. Run with --setup first.",
                "details": {"container": "juice-shop"}
            }
        
        runner = DockerRunner()
        
        print("\n  Scanning Juice Shop on localhost:3000...")
        
        result = await runner.run_tool(
            'nmap',
            ['-sV', '-p', '3000', 'localhost'],
            timeout=60
        )
        
        if result['exit_code'] == 0:
            # Try to access the page
            try:
                curl_result = subprocess.run(
                    ['curl', '-s', '-o', '/dev/null', '-w', '%{http_code}', 
                     'http://localhost:3000'],
                    capture_output=True,
                    text=True,
                    timeout=10
                )
                http_code = curl_result.stdout.strip()
            except:
                http_code = "unknown"
            
            return {
                "passed": True,
                "message": f"Juice Shop scan completed, HTTP status: {http_code}",
                "details": {
                    "exit_code": result['exit_code'],
                    "http_code": http_code,
                    "duration": result['duration']
                }
            }
        else:
            return {
                "passed": False,
                "message": "Scan failed",
                "details": {"exit_code": result['exit_code']}
            }
    except Exception as e:
        return {
            "passed": False,
            "message": f"Error: {str(e)}",
            "details": {"exception": str(e)}
        }


async def test_complete_workflow() -> dict:
    """Test complete CTF workflow against Docker target."""
    try:
        from src.ctf_core.docker_runner import DockerRunner
        from src.ctf_core.db import init_database, CTFDatabase
        from src.ctf_core.utils.flag_detector import FlagPatternDetector
        
        if not check_docker_running("dvwa"):
            return {
                "passed": False,
                "message": "DVWA container not running. Run with --setup first.",
                "details": {"container": "dvwa"}
            }
        
        runner = DockerRunner()
        detector = FlagPatternDetector()
        
        print("\n  Running complete CTF workflow against DVWA...")
        
        # Step 1: Service detection
        nmap_result = await runner.run_tool(
            'nmap',
            ['-sV', '-p', '8080', 'localhost'],
            timeout=60
        )
        
        # Step 2: Try SQLMap (detection only)
        sqlmap_result = await runner.run_tool(
            'sqlmap',
            [
                '-u', 'http://localhost:8080/login.php',
                '--batch',
                '--level', '1'
            ],
            timeout=120
        )
        
        # Combine outputs
        combined = nmap_result['stdout'] + sqlmap_result['stdout']
        
        # Look for flags
        flags = detector.extract_flags(combined)
        
        # Check results
        nmap_ok = nmap_result['exit_code'] == 0
        sqlmap_ok = sqlmap_result['exit_code'] in [0, 1]
        
        return {
            "passed": nmap_ok and sqlmap_ok,
            "message": f"Workflow complete: Nmap {'OK' if nmap_ok else 'FAIL'}, SQLMap {'OK' if sqlmap_ok else 'FAIL'}",
            "details": {
                "nmap_exit": nmap_result['exit_code'],
                "sqlmap_exit": sqlmap_result['exit_code'],
                "flags_found": len(flags)
            }
        }
    except Exception as e:
        return {
            "passed": False,
            "message": f"Error: {str(e)}",
            "details": {"exception": str(e)}
        }


def run_tests(setup: bool = False, cleanup: bool = False):
    """Run all Tier 3 tests."""
    print_banner()
    print_section("Tier 3: Self-Hosted Vulnerable Targets")
    
    if setup:
        setup_results = setup_docker_targets()
        if not all(setup_results.values()):
            print("\n[WARNING] Some containers failed to start. Continuing anyway...")
    
    print("This tier tests against self-hosted vulnerable Docker containers.")
    print("Targets: DVWA, OWASP Juice Shop\n")
    
    runner = TestRunner(tier=3, suite_name="Tier 3 - Self-Hosted Targets")
    
    tests = [
        (test_dvwa_nmap, "T3-001", "DVWA Nmap Scan"),
        (test_dvwa_sqlmap, "T3-002", "DVWA SQLMap Test"),
        (test_juice_shop, "T3-003", "Juice Shop Scan"),
        (test_complete_workflow, "T3-004", "Complete CTF Workflow"),
    ]
    
    print(f"Running {len(tests)} tests...\n")
    print("Note: Ensure Docker containers are running with --setup flag.\n")
    
    for test_func, test_id, test_name in tests:
        runner.run_test(test_func, test_id, test_name)
    
    result = runner.complete()
    
    print("\n" + "=" * 60)
    print("TIER 3 SUMMARY")
    print("=" * 60)
    
    runner.print_summary()
    
    # Generate report
    generator = ReportGenerator()
    _, report_path = generator.generate_markdown([result])
    print(f"\nReport saved to: {report_path}")
    
    if cleanup:
        cleanup_docker_targets()
    
    if result.failed > 0 or result.errors > 0:
        print(f"\n[RESULT] Tier 3 completed with {result.failed} failures")
        return 1
    else:
        print(f"\n[RESULT] Tier 3 completed successfully!")
        return 0


def main():
    parser = argparse.ArgumentParser(description="Run Tier 3 Self-Hosted Target Tests")
    parser.add_argument("--setup", "-s", action="store_true", help="Setup Docker containers first")
    parser.add_argument("--cleanup", "-c", action="store_true", help="Cleanup Docker containers after")
    parser.add_argument("--setup-only", action="store_true", help="Only setup, don't run tests")
    
    args = parser.parse_args()
    
    if args.setup_only:
        setup_docker_targets()
        print("\n[OK] Setup complete. Run without --setup-only to run tests.")
        sys.exit(0)
    
    sys.exit(run_tests(setup=args.setup, cleanup=args.cleanup))


if __name__ == "__main__":
    main()
