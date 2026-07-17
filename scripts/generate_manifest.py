from __future__ import annotations

import argparse
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
SRC_ROOT = PROJECT_ROOT / "src"
if str(SRC_ROOT) not in sys.path:
    sys.path.insert(0, str(SRC_ROOT))

from ctf_core.manifest import build_manifest, dumps_manifest, write_manifest  # noqa: E402


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Generate the deterministic ctfsolver toolkit manifest."
    )
    parser.add_argument(
        "--write",
        action="store_true",
        help="update toolkit_manifest.json in the repository root",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    manifest = build_manifest(PROJECT_ROOT)
    text = dumps_manifest(manifest)

    if args.write:
        write_manifest(PROJECT_ROOT)

    print(text, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
