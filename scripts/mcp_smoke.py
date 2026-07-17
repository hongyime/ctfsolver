from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]
SRC_ROOT = PROJECT_ROOT / "src"
if str(SRC_ROOT) not in sys.path:
    sys.path.insert(0, str(SRC_ROOT))

from ctf_core.smoke import run_smoke_sync  # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser(description="Run lightweight ctfsolver backend smoke checks.")
    parser.add_argument("--json", action="store_true", help="Print JSON instead of text.")
    parser.add_argument("--workspace", type=Path, help="Workspace path for challenge roundtrip.")
    parser.add_argument("--db-path", type=Path, help="Database path for challenge roundtrip.")
    parser.add_argument(
        "--no-challenge",
        action="store_true",
        help="Skip create_challenge/challenge_status roundtrip.",
    )
    args = parser.parse_args()

    if (args.workspace is None) ^ (args.db_path is None):
        parser.error("--workspace and --db-path must be provided together")

    report = run_smoke_sync(
        workspace=args.workspace,
        db_path=args.db_path,
        challenge_roundtrip=not args.no_challenge,
    )
    if args.json:
        print(json.dumps(report.to_dict(), indent=2, sort_keys=True))
    else:
        print(report.to_text())
    return 0 if report.ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
