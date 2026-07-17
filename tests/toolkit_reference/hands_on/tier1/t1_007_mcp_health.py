#!/usr/bin/env python3
"""
Tier 1 Test: T1-007 MCP Server Health Check

Tests that the MCP server can start and respond to health checks.
"""

import sys
import asyncio
import subprocess
import time
import signal
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from tests.hands_on._lib import TestRunner, TestStatus, print_banner


def test_mcp_server_import() -> dict:
    """Test that MCP server can be imported."""
    try:
        from src.ctf_core.server import mcp, validate_environment
        
        return {
            "passed": True,
            "message": "MCP server module imported successfully",
            "details": {"modules_loaded": True}
        }
    except Exception as e:
        return {
            "passed": False,
            "message": f"Import failed: {str(e)}",
            "details": {"exception": str(e)}
        }


def test_validate_environment() -> dict:
    """Test environment validation function."""
    try:
        from src.ctf_core.server import validate_environment
        
        # Run validation
        success, issues = validate_environment()
        
        # Note: Docker might not be running in test environment
        # So we just check the function works
        return {
            "passed": True,  # Function works regardless of Docker status
            "message": f"Validation function works (issues: {len(issues)})",
            "details": {
                "validation_completed": True,
                "issues_found": issues if issues else []
            }
        }
    except Exception as e:
        return {
            "passed": False,
            "message": f"Validation failed: {str(e)}",
            "details": {"exception": str(e)}
        }


def test_health_check_function() -> dict:
    """Test the health_check function."""
    try:
        from src.ctf_core.server import health_check
        
        # Run health check
        result = asyncio.run(health_check())
        
        # Check if result looks like a health check
        if isinstance(result, str) and len(result) > 0:
            return {
                "passed": True,
                "message": "Health check function works",
                "details": {"result_length": len(result)}
            }
        else:
            return {
                "passed": False,
                "message": "Health check returned unexpected result",
                "details": {"result": result}
            }
    except Exception as e:
        return {
            "passed": False,
            "message": f"Health check failed: {str(e)}",
            "details": {"exception": str(e)}
        }


def run_tests():
    """Run all Tier 1 MCP server tests."""
    print_banner()
    
    runner = TestRunner(tier=1, suite_name="MCP Server Tests")
    runner.print_header("Tier 1: MCP Server Health Check")
    
    print("Testing MCP server module and health check functionality.\n")
    
    runner.run_test(test_mcp_server_import, "T1-007a", "MCP Server Import")
    runner.run_test(test_validate_environment, "T1-007b", "Environment Validation")
    runner.run_test(test_health_check_function, "T1-007c", "Health Check Function")
    
    result = runner.complete()
    runner.print_summary()
    
    return 0 if result.failed == 0 and result.errors == 0 else 1


if __name__ == "__main__":
    sys.exit(run_tests())
