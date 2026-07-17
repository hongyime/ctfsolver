#!/usr/bin/env python3
"""
Tier 1 Test: T1-001 Docker Image Verification

Validates that all CTF toolkit Docker images are available locally.
"""

import sys
import asyncio
from pathlib import Path

# Add src to path
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from tests.hands_on._lib import TestRunner, TestStatus, print_banner


async def test_docker_images() -> dict:
    """Test Docker image availability."""
    try:
        from src.ctf_core.docker_runner import DockerRunner
        
        runner = DockerRunner()
        images = runner.list_available_images()
        
        # Try to verify images
        success, missing = runner.verify_images()
        
        return {
            "passed": success,
            "message": f"Found {len(images)} images configured" if success else f"Missing: {missing}",
            "details": {
                "configured_images": images,
                "missing_images": missing,
                "all_available": success
            }
        }
    except Exception as e:
        return {
            "passed": False,
            "message": f"Error: {str(e)}",
            "details": {"exception": str(e)}
        }


async def test_docker_connectivity() -> dict:
    """Test Docker daemon connectivity."""
    try:
        import docker
        client = docker.from_env()
        client.ping()
        
        return {
            "passed": True,
            "message": "Docker daemon is reachable",
            "details": {"status": "connected"}
        }
    except Exception as e:
        return {
            "passed": False,
            "message": f"Docker connectivity failed: {str(e)}",
            "details": {"exception": str(e)}
        }


def run_tests():
    """Run all Tier 1 tests."""
    print_banner()
    
    runner = TestRunner(tier=1, suite_name="Local Environment Tests")
    runner.print_header("Tier 1: Local Environment Validation")
    
    print("This tier tests core infrastructure without external dependencies.\n")
    
    # T1-001
    runner.run_test(test_docker_images, "T1-001", "Docker Image Verification")
    
    # T1-002
    runner.run_test(test_docker_connectivity, "T1-002", "Docker Daemon Connectivity")
    
    # Complete and print summary
    result = runner.complete()
    runner.print_summary()
    
    # Return exit code
    if result.failed > 0 or result.errors > 0:
        print(f"{runner.result.suite_name} completed with failures.")
        return 1
    else:
        print(f"{runner.result.suite_name} completed successfully!")
        return 0


if __name__ == "__main__":
    sys.exit(asyncio.run(run_tests()) if asyncio.iscoroutinefunction(run_tests) else run_tests())
