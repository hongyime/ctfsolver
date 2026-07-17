#!/usr/bin/env python3
"""Quick test to verify Docker images and MCP health."""
import sys
sys.path.insert(0, '.')

print("=" * 60)
print("Docker Image Verification")
print("=" * 60)

from src.ctf_core.docker_runner import DockerRunner

runner = DockerRunner()
images = runner.list_available_images()
print(f'Configured images: {images}')

success, missing = runner.verify_images()
print(f'Verification success: {success}')
print(f'Missing images: {missing}')

if success:
    print('All Docker images verified successfully!')
else:
    print(f'Some images are missing: {missing}')

print()
print("=" * 60)
print("MCP Health Check")
print("=" * 60)

from src.ctf_core.server import health_check
import asyncio

result = asyncio.run(health_check())
print(f'Health check result: {result}')

print()
print("=" * 60)
print("Test Complete!")
print("=" * 60)
