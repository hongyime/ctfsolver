#!/usr/bin/env python3
"""
scripts/migrate_workspace.py

Move challenge folders out of the repo workspace/ into a user-supplied
working directory.  Safe to re-run: existing non-empty destinations are
skipped, never overwritten.

Usage
-----
  uv run python scripts/migrate_workspace.py --dst "C:\\Users\\bryan\\CTFs\\active"

  # dry-run (prints what would happen, moves nothing)
  uv run python scripts/migrate_workspace.py --dst "D:\\CTFs" --dry-run

  # custom source (defaults to <repo_root>/workspace)
  uv run python scripts/migrate_workspace.py --src "C:\\ctfsolver\\workspace" --dst "D:\\CTFs"

Behaviour
---------
For each direct child folder of --src:
  - If --dst/<folder> already exists AND is non-empty  → skip (idempotent).
  - If it has a metadata.json                          → move as a structured challenge folder.
  - If it has no metadata.json                         → move as-is, write a stub metadata.json
                                                         so downstream tooling recognises it.
  - After moving, write _migrated_from.txt inside the destination folder.

On full success with no errors, the source directory is left empty (only
a .gitkeep is created so git does not complain about a missing tracked dir).
"""
from __future__ import annotations

import argparse
import json
import shutil
import sys
from datetime import datetime, timezone
from pathlib import Path


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------

REPO_ROOT = Path(__file__).resolve().parent.parent


def _utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _is_empty(path: Path) -> bool:
    """True if the directory either does not exist or contains no files/subdirs."""
    if not path.exists():
        return True
    return not any(path.iterdir())


def _write_stub_metadata(folder: Path) -> None:
    """Write a minimal metadata.json so the harness can recognise the folder."""
    meta_path = folder / "metadata.json"
    if meta_path.exists():
        return  # already there; don't clobber
    meta = {
        "id": 0,
        "name": folder.name,
        "category": "unknown",
        "value": None,
        "description": f"Migrated from repo workspace. Original folder: {folder.name}",
        "connection_info": None,
        "files": [],
        "tags": [],
        "hints": [],
        "platform": "manual",
        "status": "migrated",
        "migrated_at": _utc_now(),
    }
    meta_path.write_text(json.dumps(meta, indent=2), encoding="utf-8")


def _write_migrated_from(dst_folder: Path, src_folder: Path) -> None:
    record = (
        f"migrated_from: {src_folder.resolve()}\n"
        f"migrated_at:   {_utc_now()}\n"
        f"migrated_by:   scripts/migrate_workspace.py\n"
    )
    (dst_folder / "_migrated_from.txt").write_text(record, encoding="utf-8")


def _move_folder(src: Path, dst: Path, dry_run: bool) -> None:
    """Move src → dst using shutil.move (works across drives)."""
    if dry_run:
        return
    dst.parent.mkdir(parents=True, exist_ok=True)
    shutil.move(str(src), str(dst))


# ---------------------------------------------------------------------------
# core logic
# ---------------------------------------------------------------------------

def migrate(src_dir: Path, dst_dir: Path, dry_run: bool = False) -> int:
    """
    Migrate all direct child folders from src_dir into dst_dir.

    Returns the number of errors encountered (0 = clean run).
    """
    if not src_dir.exists():
        print(f"[SKIP] Source directory does not exist: {src_dir}")
        return 0

    subfolders = sorted(
        p for p in src_dir.iterdir() if p.is_dir() and p.name != "__pycache__"
    )

    if not subfolders:
        print(f"[INFO] Source directory is already empty: {src_dir}")
        return 0

    moved = skipped = errors = 0
    dry_tag = "[DRY-RUN] " if dry_run else ""

    for src_folder in subfolders:
        dst_folder = dst_dir / src_folder.name

        # Idempotency: skip if destination is already non-empty
        if not _is_empty(dst_folder):
            print(f"[SKIP]  {src_folder.name}  ->  already exists at {dst_folder}")
            skipped += 1
            continue

        has_metadata = (src_folder / "metadata.json").exists()

        try:
            if dry_run:
                tag = "structured" if has_metadata else "unstructured (stub metadata)"
                print(f"{dry_tag}MOVE  {src_folder}  ->  {dst_folder}  [{tag}]")
                moved += 1
                continue

            # Real move
            dst_folder.mkdir(parents=True, exist_ok=True)
            # Move contents rather than the folder itself so we can inject
            # files first without race conditions.
            for item in src_folder.iterdir():
                shutil.move(str(item), str(dst_folder / item.name))

            if not has_metadata:
                _write_stub_metadata(dst_folder)

            _write_migrated_from(dst_folder, src_folder)

            # Remove now-empty source dir
            try:
                src_folder.rmdir()
            except OSError:
                # Not empty (e.g. some file couldn't be moved) – leave it
                pass

            print(f"[MOVED] {src_folder.name}  ->  {dst_folder}")
            moved += 1

        except Exception as exc:  # noqa: BLE001
            print(f"[ERROR] {src_folder.name}: {exc}", file=sys.stderr)
            errors += 1

    # Summary
    print()
    print(f"{'[DRY-RUN] ' if dry_run else ''}Summary: {moved} moved, {skipped} skipped, {errors} errors")

    # Leave a .gitkeep so git doesn't complain about the empty dir
    if not dry_run and errors == 0:
        remaining = [p for p in src_dir.iterdir() if p.name != ".gitkeep"]
        if not remaining:
            (src_dir / ".gitkeep").touch()
            print(f"[INFO] Left .gitkeep in {src_dir}")

    return errors


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main() -> int:
    parser = argparse.ArgumentParser(
        description="Migrate challenge folders from repo workspace/ to a user-supplied directory.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument(
        "--src",
        type=Path,
        default=REPO_ROOT / "workspace",
        help="Source directory (default: <repo>/workspace)",
    )
    parser.add_argument(
        "--dst",
        type=Path,
        required=True,
        help="Destination working directory (required)",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Print what would happen without moving anything",
    )
    args = parser.parse_args()

    src = args.src.resolve()
    dst = args.dst.resolve()

    # Safety: refuse to migrate INTO the repo
    try:
        dst.relative_to(REPO_ROOT)
        print(
            f"[ERROR] Destination {dst} is inside the repo root {REPO_ROOT}.\n"
            "  The working directory must be outside the repo.",
            file=sys.stderr,
        )
        return 1
    except ValueError:
        pass  # dst is outside repo — good

    print(f"Source : {src}")
    print(f"Dest   : {dst}")
    if args.dry_run:
        print("[DRY-RUN] No files will be moved.")
    print()

    errors = migrate(src, dst, dry_run=args.dry_run)
    return 0 if errors == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
