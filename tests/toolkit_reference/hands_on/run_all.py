#!/usr/bin/env python3
"""
CTF Toolkit Hands-On Test Master Runner

Runs all tier tests and generates a combined validation report.

Usage:
    python tests/hands_on/run_all.py          # Run all tiers
    python tests/hands_on/run_all.py --tier1   # Run specific tier
    python tests/hands_on/run_all.py --quick   # Skip slow tests
    python tests/hands_on/run_all.py --setup   # Setup Docker targets
    python tests/hands_on/run_all.py --report  # Generate report only
"""

import sys
import asyncio
import argparse
import subprocess
from pathlib import Path
from datetime import datetime

sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from tests.hands_on._lib import print_banner, print_section, ReportGenerator, Colors


# Tier configurations
TIERS = {
    1: {
        "name": "Local Environment",
        "description": "Core infrastructure without external dependencies",
        "estimated_time": "2-5 minutes",
        "requires_internet": False,
        "requires_docker": True,
    },
    2: {
        "name": "Safe External Targets",
        "description": "Public vulnerable test sites (ScanMe, VulnWeb)",
        "estimated_time": "5-15 minutes",
        "requires_internet": True,
        "requires_docker": True,
    },
    3: {
        "name": "Self-Hosted Vulnerable VMs",
        "description": "Docker vulnerable apps (DVWA, Juice Shop)",
        "estimated_time": "15-30 minutes",
        "requires_internet": True,
        "requires_docker": True,
    },
    4: {
        "name": "Real CTF Platforms",
        "description": "picoCTF, HackTheBox, TryHackMe (human-in-loop)",
        "estimated_time": "Ongoing",
        "requires_internet": True,
        "requires_docker": False,
        "requires_human": True,
    },
}


def check_prerequisites() -> dict:
    """Check if prerequisites are met."""
    results = {
        "docker": {"check": False, "message": ""},
        "internet": {"check": False, "message": ""},
        "python": {"check": False, "message": ""},
    }
    
    # Check Python
    try:
        from src.ctf_core.db import init_database
        results["python"]["check"] = True
        results["python"]["message"] = "Python environment OK"
    except Exception as e:
        results["python"]["message"] = f"Python error: {e}"
    
    # Check Docker
    try:
        subprocess.run(["docker", "--version"], capture_output=True, timeout=5)
        results["docker"]["check"] = True
        results["docker"]["message"] = "Docker available"
    except:
        results["docker"]["message"] = "Docker not found"
    
    # Check Internet (simple ping)
    try:
        subprocess.run(["ping", "-n", "1", "-w", "1000", "8.8.8.8"], 
                      capture_output=True, timeout=5)
        results["internet"]["check"] = True
        results["internet"]["message"] = "Internet connectivity OK"
    except:
        results["internet"]["message"] = "No internet (Tier 2+ will fail)"
    
    return results


def print_prerequisites(prereqs: dict):
    """Print prerequisites check results."""
    print(f"\n{Colors.HEADER}{'=' * 60}{Colors.ENDC}")
    print(f"{Colors.HEADER}Prerequisites Check{Colors.ENDC}")
    print(f"{Colors.HEADER}{'=' * 60}{Colors.ENDC}\n")
    
    for name, result in prereqs.items():
        status = f"{Colors.GREEN}OK{Colors.ENDC}" if result["check"] else f"{Colors.RED}FAIL{Colors.ENDC}"
        print(f"  [{status}] {name.upper()}: {result['message']}")
    
    print()


def run_tier1() -> int:
    """Run Tier 1 tests."""
    print_section("Running Tier 1: Local Environment Tests")
    
    try:
        from tests.hands_on.run_tier1 import run_all_tier1_tests
        return run_all_tier1_tests(verbose=True)
    except Exception as e:
        print(f"{Colors.RED}Error running Tier 1: {e}{Colors.ENDC}")
        return 1


def run_tier2(quick: bool = False) -> int:
    """Run Tier 2 tests."""
    print_section("Running Tier 2: Safe External Target Tests")
    
    try:
        from tests.hands_on.run_tier2 import run_tests as run_tier2_tests
        return run_tier2_tests(quick=quick)
    except Exception as e:
        print(f"{Colors.RED}Error running Tier 2: {e}{Colors.ENDC}")
        return 1


def run_tier3(setup: bool = False) -> int:
    """Run Tier 3 tests."""
    print_section("Running Tier 3: Self-Hosted Vulnerable Targets")
    
    try:
        from tests.hands_on.run_tier3 import run_tests as run_tier3_tests
        return run_tier3_tests(setup=setup, cleanup=False)
    except Exception as e:
        print(f"{Colors.RED}Error running Tier 3: {e}{Colors.ENDC}")
        return 1


def setup_docker() -> bool:
    """Setup Docker vulnerable targets."""
    print_section("Setting Up Docker Vulnerable Targets")
    
    try:
        from tests.hands_on.run_tier3 import setup_docker_targets
        
        results = setup_docker_targets()
        
        if all(results.values()):
            print(f"\n{Colors.GREEN}All Docker targets set up successfully!{Colors.ENDC}")
            return True
        else:
            failed = [k for k, v in results.items() if not v]
            print(f"\n{Colors.YELLOW}Some targets failed to set up: {', '.join(failed)}{Colors.ENDC}")
            return False
    except Exception as e:
        print(f"{Colors.RED}Error setting up Docker: {e}{Colors.ENDC}")
        return False


def cleanup_docker() -> bool:
    """Cleanup Docker vulnerable targets."""
    print_section("Cleaning Up Docker Vulnerable Targets")
    
    try:
        from tests.hands_on.run_tier3 import cleanup_docker_targets
        cleanup_docker_targets()
        return True
    except Exception as e:
        print(f"{Colors.RED}Error cleaning up Docker: {e}{Colors.ENDC}")
        return False


def show_tier4():
    """Show Tier 4 instructions."""
    try:
        from tests.hands_on.run_tier4 import run_interactive
        run_interactive()
    except Exception as e:
        print(f"{Colors.RED}Error showing Tier 4: {e}{Colors.ENDC}")


def generate_final_report(all_results: list) -> str:
    """Generate final combined report."""
    generator = ReportGenerator()
    
    markdown_report, md_path = generator.generate_markdown(all_results)
    json_data, json_path = generator.generate_json(all_results)
    
    return md_path, json_path


def print_final_summary(all_results: list):
    """Print final summary of all tiers."""
    print(f"\n{Colors.CYAN}{Colors.BOLD}{'=' * 60}{Colors.ENDC}")
    print(f"{Colors.CYAN}{Colors.BOLD}FINAL VALIDATION SUMMARY{Colors.ENDC}")
    print(f"{Colors.CYAN}{Colors.BOLD}{'=' * 60}{Colors.ENDC}\n")
    
    total_tests = 0
    total_passed = 0
    total_failed = 0
    total_errors = 0
    
    for result in all_results:
        tier_num = result.tier
        tier_name = TIERS.get(tier_num, {}).get("name", f"Tier {tier_num}")
        
        status = f"{Colors.GREEN}PASS{Colors.ENDC}" if result.failed == 0 and result.errors == 0 else f"{Colors.RED}FAIL{Colors.ENDC}"
        
        print(f"  Tier {tier_num} ({tier_name}): {status}")
        print(f"    Tests: {result.total} | Passed: {result.passed} | Failed: {result.failed} | Errors: {result.errors}")
        print(f"    Pass Rate: {result.pass_rate:.1f}% | Duration: {result.total_duration:.2f}s")
        print()
        
        total_tests += result.total
        total_passed += result.passed
        total_failed += result.failed
        total_errors += result.errors
    
    overall_pass_rate = (total_passed / total_tests * 100) if total_tests > 0 else 0
    
    print(f"{Colors.CYAN}{'=' * 60}{Colors.ENDC}")
    print(f"\n  {Colors.BOLD}OVERALL RESULTS{Colors.ENDC}")
    print(f"  Total Tests: {total_tests}")
    print(f"  {Colors.GREEN}Passed: {total_passed}{Colors.ENDC}")
    if total_failed > 0:
        print(f"  {Colors.RED}Failed: {total_failed}{Colors.ENDC}")
    if total_errors > 0:
        print(f"  {Colors.RED}Errors: {total_errors}{Colors.ENDC}")
    print(f"  Overall Pass Rate: {overall_pass_rate:.1f}%")
    print()


def main():
    parser = argparse.ArgumentParser(
        description="CTF Toolkit Hands-On Test Master Runner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python tests/hands_on/run_all.py              # Run all automated tiers
  python tests/hands_on/run_all.py --tier1      # Run only Tier 1
  python tests/hands_on/run_all.py --tier2 --quick  # Run Tier 2, skip slow tests
  python tests/hands_on/run_all.py --setup      # Setup Docker targets
  python tests/hands_on/run_all.py --cleanup     # Cleanup Docker targets
  python tests/hands_on/run_all.py --tier4       # Show Tier 4 instructions
        """
    )
    
    parser.add_argument("--tier1", action="store_true", help="Run Tier 1 only")
    parser.add_argument("--tier2", action="store_true", help="Run Tier 2 only")
    parser.add_argument("--tier3", action="store_true", help="Run Tier 3 only")
    parser.add_argument("--tier4", action="store_true", help="Show Tier 4 instructions")
    parser.add_argument("--quick", "-q", action="store_true", help="Skip slow tests")
    parser.add_argument("--setup", "-s", action="store_true", help="Setup Docker targets")
    parser.add_argument("--cleanup", "-c", action="store_true", help="Cleanup Docker targets")
    parser.add_argument("--prereqs", "-p", action="store_true", help="Check prerequisites only")
    parser.add_argument("--list", "-l", action="store_true", help="List all tiers")
    
    args = parser.parse_args()
    
    print_banner()
    
    # List tiers
    if args.list:
        print_section("Available Tiers")
        for tier_num, tier_info in TIERS.items():
            print(f"\n  Tier {tier_num}: {tier_info['name']}")
            print(f"    {tier_info['description']}")
            print(f"    Time: {tier_info['estimated_time']}")
            if tier_info.get("requires_human"):
                print(f"    {Colors.YELLOW}Human-in-the-loop required{Colors.ENDC}")
        print()
        return 0
    
    # Check prerequisites
    prereqs = check_prerequisites()
    print_prerequisites(prereqs)
    
    if args.prereqs:
        return 0
    
    # Setup or cleanup
    if args.setup:
        setup_docker()
        return 0
    
    if args.cleanup:
        cleanup_docker()
        return 0
    
    # Show Tier 4
    if args.tier4:
        show_tier4()
        return 0
    
    # Determine which tiers to run
    run_tier_1 = args.tier1 or not any([args.tier2, args.tier3, args.tier4])
    run_tier_2 = args.tier2 or not any([args.tier1, args.tier3, args.tier4])
    run_tier_3 = args.tier3 or not any([args.tier1, args.tier2, args.tier4])
    
    # Run tiers
    all_results = []
    exit_code = 0
    
    if run_tier_1:
        code = run_tier1()
        if code != 0:
            exit_code = code
    
    if run_tier_2 and prereqs["internet"]["check"]:
        code = run_tier2(quick=args.quick)
        if code != 0:
            exit_code = code
    elif run_tier_2 and not prereqs["internet"]["check"]:
        print(f"{Colors.YELLOW}Skipping Tier 2 (no internet){Colors.ENDC}")
    
    if run_tier_3 and prereqs["docker"]["check"]:
        code = run_tier3(setup=args.setup)
        if code != 0:
            exit_code = code
    elif run_tier_3 and not prereqs["docker"]["check"]:
        print(f"{Colors.YELLOW}Skipping Tier 3 (Docker not available){Colors.ENDC}")
    
    # Show Tier 4 note
    print_section("Tier 4: Human-in-the-Loop")
    print("""
  Tier 4 requires human participation for real CTF platforms.
  
  To get started:
    python tests/hands_on/run_tier4.py
  
  Platforms:
    - picoCTF (https://play.picoctf.org/) - Free, no account needed
    - HackTheBox Academy (https://academy.hackthebox.com/) - Free modules
    - TryHackMe (https://tryhackme.com/) - Beginner friendly
  
  Run specific platform guides:
    python tests/hands_on/run_tier4.py --picoctf
    python tests/hands_on/run_tier4.py --htb
    """)
    
    # Final message
    print_section("Validation Complete")
    
    if exit_code == 0:
        print(f"{Colors.GREEN}{Colors.BOLD}")
        print("  ╔════════════════════════════════════════════════════════════╗")
        print("  ║                                                            ║")
        print("  ║   🎉 All automated tests passed! 🎉                        ║")
        print("  ║                                                            ║")
        print("  ║   Your CTF Toolkit is ready for use.                       ║")
        print("  ║   Proceed to Tier 4 for real CTF practice.                  ║")
        print("  ║                                                            ║")
        print("  ╚════════════════════════════════════════════════════════════╝")
        print(f"{Colors.ENDC}")
    else:
        print(f"{Colors.RED}{Colors.BOLD}")
        print("  Some tests failed. Review the output above for details.")
        print("  Common fixes:")
        print("    - Run with --setup to configure Docker targets")
        print("    - Check internet connectivity")
        print("    - Verify Docker images are available")
        print(f"{Colors.ENDC}")
    
    return exit_code


if __name__ == "__main__":
    sys.exit(main())
