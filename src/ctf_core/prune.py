"""Two-gate idle-TTL image reaper (Phase 4).

Oracle pressure-test rule (UPGRADE_PLAN §1): auto-prune is DANGEROUS if naive.
This implements the safe version:

  * TWO GATES — an image is only prunable if BOTH hold:
      1. idle: not pulled/used within CTFTOOLKIT_IMAGE_TTL_DAYS, AND
      2. zero-reference: no container (running OR stopped) uses it, AND it is not
         referenced by any running/durable scan_jobs row.
  * NEVER `docker rmi -f`: force-removal untags an image while leaving dangling
    layer "ghosts". We untag/remove only via the normal (non-forced) API, which
    refuses if anything still references it — a third backstop.
  * NEVER mid-solve: a hard veto on any image with a live container or an active
    job row, so a prune can't pull the rug from under a running exploit.

Exposed via the prune_images / disk_usage MCP tools. Runs at startup + on demand.
"""

from __future__ import annotations

import logging
import os
from datetime import datetime, timezone, timedelta

logger = logging.getLogger(__name__)

TTL_DAYS = int(os.environ.get("CTFTOOLKIT_IMAGE_TTL_DAYS", "7"))
_MANAGED_PREFIX = "ctftoolkit/"


def _client():
    from .docker_runner import DockerRunner
    return DockerRunner().client


def _parse_docker_time(s: str):
    """Parse a docker RFC3339-ish timestamp; return aware datetime or None."""
    if not s:
        return None
    try:
        s2 = s.split(".")[0].replace("Z", "")
        return datetime.fromisoformat(s2).replace(tzinfo=timezone.utc)
    except Exception:
        return None


async def _referenced_images() -> set[str]:
    """Image tags referenced by ANY container (running or stopped) or active job row."""
    refs: set[str] = set()
    client = _client()
    try:
        for c in client.containers.list(all=True):
            tags = (c.image.tags if c.image else []) or []
            refs.update(tags)
            # also the image the container was created from
            img = c.attrs.get("Config", {}).get("Image")
            if img:
                refs.add(img)
    except Exception as e:
        logger.warning("could not enumerate containers for prune veto: %s", e)
    # Images referenced by running/durable scan jobs.
    try:
        from .db import get_database
        db = await get_database()
        for job in await db.list_scan_jobs(status="running"):
            if job.get("image_name"):
                refs.add(job["image_name"])
    except Exception as e:
        logger.warning("could not enumerate jobs for prune veto: %s", e)
    return {r for r in refs if r}


async def prune_images(ttl_days: int | None = None, dry_run: bool = True) -> dict:
    """Two-gate idle-TTL prune of ctftoolkit/* images.

    Returns a report. dry_run=True (default) only lists candidates; pass dry_run=False
    to actually remove. NEVER force-removes; refuses any in-use/referenced image.
    """
    ttl = TTL_DAYS if ttl_days is None else ttl_days
    cutoff = datetime.now(timezone.utc) - timedelta(days=ttl)
    client = _client()
    referenced = await _referenced_images()

    report = {"ttl_days": ttl, "dry_run": dry_run, "removed": [], "kept": [], "vetoed": []}
    try:
        images = client.images.list()
    except Exception as e:
        return {"error": f"could not list images: {e}"}

    for img in images:
        tags = [t for t in (img.tags or []) if t.startswith(_MANAGED_PREFIX)]
        if not tags:
            continue
        tag = tags[0]

        # GATE 2 (veto): referenced by a container or active job -> never touch.
        if any(t in referenced for t in tags):
            report["vetoed"].append({"image": tag, "reason": "in use (container/job reference)"})
            continue

        # GATE 1: idle by TTL (use image Created/Metadata LastTagTime as a proxy).
        created = _parse_docker_time(img.attrs.get("Created", ""))
        meta = img.attrs.get("Metadata", {}) or {}
        last_used = _parse_docker_time(meta.get("LastTagTime", "")) or created
        if last_used and last_used > cutoff:
            report["kept"].append({"image": tag, "reason": f"used within {ttl}d"})
            continue

        # Both gates passed -> prunable.
        if dry_run:
            report["removed"].append({"image": tag, "reason": "would remove (idle + unreferenced)"})
            continue
        try:
            # NON-forced removal: Docker refuses if still referenced (third backstop).
            client.images.remove(tag, force=False, noprune=False)
            report["removed"].append({"image": tag, "reason": "removed (idle + unreferenced)"})
            logger.info("pruned idle image %s", tag)
        except Exception as e:
            report["vetoed"].append({"image": tag, "reason": f"remove refused: {e}"})
    return report


async def disk_usage() -> dict:
    """Report disk used by ctftoolkit images + dangling layers."""
    client = _client()
    out = {"images": [], "total_mb": 0.0, "dangling_mb": 0.0}
    try:
        for img in client.images.list():
            tags = [t for t in (img.tags or []) if t.startswith(_MANAGED_PREFIX)]
            size_mb = (img.attrs.get("Size", 0) or 0) / (1024 * 1024)
            if tags:
                out["images"].append({"image": tags[0], "size_mb": round(size_mb, 1)})
                out["total_mb"] += size_mb
        # dangling (untagged) layers
        for img in client.images.list(filters={"dangling": True}):
            out["dangling_mb"] += (img.attrs.get("Size", 0) or 0) / (1024 * 1024)
    except Exception as e:
        return {"error": f"could not compute disk usage: {e}"}
    out["total_mb"] = round(out["total_mb"], 1)
    out["dangling_mb"] = round(out["dangling_mb"], 1)
    return out
