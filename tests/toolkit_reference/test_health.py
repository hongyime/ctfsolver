#!/usr/bin/env python3
"""Quick health check test script."""

import asyncio
import sys

# Add src to path
sys.path.insert(0, 'src')

from ctf_core.server import health_check

async def main():
    result = await health_check()
    print("HEALTH CHECK RESULT:")
    print(result)
    return result

if __name__ == "__main__":
    asyncio.run(main())
