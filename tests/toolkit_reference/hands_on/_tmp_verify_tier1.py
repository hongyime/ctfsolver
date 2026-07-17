import sys
import asyncio
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from tests.hands_on.tier1.t1_002_database import test_database_crud
from src.ctf_core.utils.flag_detector import FlagPatternDetector

async def main():
    db_result = await test_database_crud()
    print("DB_RESULT", db_result)

    detector = FlagPatternDetector()
    text = "sha1: da39a3ee5e6b4b0d3255bfef95601890afd80709"
    print("HEX_FLAGS", detector.extract_flags(text))

if __name__ == "__main__":
    asyncio.run(main())
