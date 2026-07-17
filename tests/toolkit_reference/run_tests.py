#!/usr/bin/env python3
"""
Test runner for CTF Toolkit platform abstraction tests.

This script runs all unit and integration tests and generates a report.

Usage:
    python run_tests.py [options]

Options:
    --verbose         Enable verbose output
    --coverage        Generate coverage report
    --output FILE     Write results to file
    --unit-only       Run only unit tests
    --integration-only Run only integration tests
"""

import argparse
import sys
import subprocess
from pathlib import Path

# Project root
ROOT = Path(__file__).parent


def run_tests(
    verbose: bool = False,
    coverage: bool = False,
    unit_only: bool = False,
    integration_only: bool = False,
) -> int:
    """
    Run test suite.
    
    Returns:
        Exit code (0 for success, non-zero for failures)
    """
    # Build pytest command
    cmd = [sys.executable, '-m', 'pytest']
    
    if verbose:
        cmd.append('-v')
    
    if coverage:
        cmd.extend(['--cov=src/ctf_core', '--cov-report=html', '--cov-report=term'])
    
    # Determine which tests to run
    test_paths = []
    
    if not integration_only:
        test_paths.append(str(ROOT / 'tests' / 'unit'))
    
    if not unit_only:
        test_paths.append(str(ROOT / 'tests' / 'integration'))
    
    cmd.extend(test_paths)
    
    print(f"Running tests: {' '.join(cmd)}")
    print("=" * 60)
    
    # Run tests
    result = subprocess.run(cmd, cwd=ROOT)
    
    if result.returncode == 0:
        print("\n✓ All tests passed!")
    else:
        print(f"\n✗ Tests failed with exit code {result.returncode}")
    
    return result.returncode


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(description='Run CTF Toolkit tests')
    parser.add_argument('--verbose', '-v', action='store_true',
                       help='Enable verbose output')
    parser.add_argument('--coverage', '-c', action='store_true',
                       help='Generate coverage report')
    parser.add_argument('--output', '-o', type=str,
                       help='Write results to file')
    parser.add_argument('--unit-only', action='store_true',
                       help='Run only unit tests')
    parser.add_argument('--integration-only', action='store_true',
                       help='Run only integration tests')
    
    args = parser.parse_args()
    
    # Check if pytest is installed
    try:
        import pytest
    except ImportError:
        print("Error: pytest is not installed")
        print("Install with: pip install pytest pytest-asyncio")
        sys.exit(1)
    
    # Run tests
    exit_code = run_tests(
        verbose=args.verbose,
        coverage=args.coverage,
        unit_only=args.unit_only,
        integration_only=args.integration_only,
    )
    
    sys.exit(exit_code)


if __name__ == '__main__':
    main()
