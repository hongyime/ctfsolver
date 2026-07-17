"""Per-challenge persistent workspace + memory (Phase 2, borrowed from clank-the-flag).

Each challenge gets a stable directory under the workspace:

    workspace/challenges/<slug>/
        files/         # ingested challenge artifacts (binaries, pcaps, ...)
        .agent-home/   # scratch / agent memory that survives across runs
        WRITEUP.md     # auto-maintained running write-up

This fixes the GREYCTF "cold restart" pain: an agent resuming a challenge finds
its files, notes, and prior findings already on disk and in the DB (challenge_id
links flags/credentials/services to the challenge).
"""

from __future__ import annotations

import re
import logging
from datetime import datetime
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)


def _slugify(name: str) -> str:
    s = re.sub(r"[^a-zA-Z0-9._-]+", "-", name.strip().lower()).strip("-")
    return s or "challenge"


def _workspace_root() -> Path:
    from .docker_runner import WORKSPACE_PATH
    return Path(WORKSPACE_PATH)


def challenge_dir(slug: str) -> Path:
    return _workspace_root() / "challenges" / slug


async def create_challenge(name: str, category: Optional[str] = None,
                           description: Optional[str] = None) -> dict:
    """Create a persistent per-challenge workspace + DB row. Returns paths + id."""
    slug = _slugify(name)
    base = challenge_dir(slug)
    files = base / "files"
    agent_home = base / ".agent-home"
    for d in (files, agent_home):
        d.mkdir(parents=True, exist_ok=True)

    writeup = base / "WRITEUP.md"
    if not writeup.exists():
        writeup.write_text(
            f"# {name}\n\n"
            f"- Category: {category or 'unknown'}\n"
            f"- Created: {datetime.now().isoformat(timespec='seconds')}\n\n"
            f"## Description\n\n{description or '(none)'}\n\n"
            f"## Findings\n\n## Solution\n\n## Flag\n\n",
            encoding="utf-8")

    from .db import get_database
    db = await get_database()
    # container-visible paths are under /workspace; host paths are the real dirs
    cvis = f"/workspace/challenges/{slug}"
    await db.create_challenge(
        challenge_id=slug, name=name, category=category, description=description,
        workspace_path=cvis, agent_home_path=f"{cvis}/.agent-home")
    return {
        "challenge_id": slug,
        "workspace": str(base),
        "files_dir": str(files),
        "agent_home": str(agent_home),
        "writeup": str(writeup),
        "container_path": cvis,
    }


async def ingest_file(slug: str, src_path: str) -> dict:
    """Copy a host file into the challenge's files/ dir and record it."""
    import shutil
    import hashlib
    base = challenge_dir(slug)
    files = base / "files"
    files.mkdir(parents=True, exist_ok=True)
    src = Path(src_path)
    if not src.is_file():
        return {"error": f"source file not found: {src_path}"}
    dst = files / src.name
    shutil.copy2(src, dst)
    sha = hashlib.sha256(dst.read_bytes()).hexdigest()

    from .db import get_database
    db = await get_database()
    if db._db is not None:
        try:
            await db._db.execute(
                "INSERT OR IGNORE INTO challenge_files "
                "(challenge_id, file_path, file_name, file_size, sha256_hash) "
                "VALUES (?, ?, ?, ?, ?)",
                (slug, f"/workspace/challenges/{slug}/files/{src.name}",
                 src.name, dst.stat().st_size, sha))
            await db._maybe_commit()
        except Exception as e:
            logger.warning("challenge_files insert failed: %s", e)
    return {"ingested": src.name, "sha256": sha,
            "container_path": f"/workspace/challenges/{slug}/files/{src.name}"}


async def record_finding(slug: str, kind: str, value: str, notes: str = "") -> dict:
    """Record a finding against a challenge (flag/credential/note) + append to WRITEUP."""
    from .db import get_database
    db = await get_database()
    k = kind.strip().lower()
    if k == "flag":
        await db.insert_flag(flag=value, source="challenge", pattern="manual")
        if db._db is not None:
            await db._db.execute("UPDATE flags SET challenge_id=? WHERE flag_value=? AND challenge_id IS NULL",
                                 (slug, value))
            await db._maybe_commit()
        await db.set_challenge_status(slug, "solved", flag=value)
    # Append to the running write-up
    base = challenge_dir(slug)
    writeup = base / "WRITEUP.md"
    if writeup.exists():
        stamp = datetime.now().isoformat(timespec="seconds")
        entry = f"- [{stamp}] **{kind}**: {value}" + (f" — {notes}" if notes else "") + "\n"
        content = writeup.read_text(encoding="utf-8")
        if "## Findings" in content:
            content = content.replace("## Findings\n", f"## Findings\n{entry}", 1)
        else:
            content += "\n" + entry
        writeup.write_text(content, encoding="utf-8")
    await db.touch_challenge(slug)
    return {"recorded": kind, "value": value, "challenge_id": slug}


async def challenge_status(slug: str) -> dict:
    """Return a challenge's DB row + on-disk presence."""
    from .db import get_database
    db = await get_database()
    row = await db.get_challenge(slug)
    if not row:
        return {"error": f"unknown challenge '{slug}'"}
    base = challenge_dir(slug)
    files = base / "files"
    row["files_on_disk"] = sorted(p.name for p in files.glob("*")) if files.is_dir() else []
    row["workspace_exists"] = base.is_dir()
    return row
