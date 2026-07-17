"""Tiered-durability job execution + startup reconciliation (Phase 2).

The MCP server is a stdio child of the IDE and is killed/restarted frequently
(every IDE close). This module makes long scans survive that:

  * SHORT jobs  -> ephemeral asyncio task running an auto-removed container.
                   If the server dies they die too; reconciliation marks them failed.
  * DURABLE jobs -> opt-in detached container (`--rm=false`) labeled
                   ctftoolkit.job=true / ctftoolkit.job_id=<id>, whose container id is
                   persisted in scan_jobs. Survives an IDE/server close; on restart we
                   re-attach (collect logs if it exited, leave it if still running).

Safety rails (Oracle pressure-test):
  * Max N concurrent durable jobs (default 3) and a hard 24h cap.
  * Startup reconciliation resolves every `running` row exactly once:
      NotFound      -> failed
      exited        -> collect logs + complete
      still running -> re-attach (leave running)
      label-orphan  -> grace-remove
  * Reconciliation runs in the FastMCP lifespan BEFORE tools register.
"""

from __future__ import annotations

import asyncio
import logging
import os
from typing import Optional

logger = logging.getLogger(__name__)

MAX_DURABLE_JOBS = int(os.environ.get("CTFTOOLKIT_MAX_DURABLE_JOBS", "3"))
DURABLE_JOB_MAX_HOURS = int(os.environ.get("CTFTOOLKIT_DURABLE_JOB_MAX_HOURS", "24"))

JOB_LABEL = "ctftoolkit.job"
JOB_ID_LABEL = "ctftoolkit.job_id"


def _client():
    from .docker_runner import DockerRunner
    return DockerRunner().client


async def count_durable_running() -> int:
    """Number of durable jobs currently marked running in the DB."""
    from .db import get_database
    db = await get_database()
    rows = await db.list_scan_jobs(status="running", durable=True)
    return len(rows)


async def start_durable_job(job_id: str, tool: str, args: list[str], image: str,
                            timeout: int) -> dict:
    """Launch a detached, labeled, NON-auto-removed container for a long job.

    Returns {"container_id": ...} or {"error": ...}. The container is reaped by
    reconciliation or finish; never auto-removed so output survives a server restart.
    """
    if await count_durable_running() >= MAX_DURABLE_JOBS:
        return {"error": f"durable job limit reached ({MAX_DURABLE_JOBS}); "
                         f"wait for one to finish or raise CTFTOOLKIT_MAX_DURABLE_JOBS"}

    from .docker_runner import DockerRunner, TOOL_IMAGES, _OFFLINE_TOOLS
    runner = DockerRunner()
    client = runner.client
    image = image or TOOL_IMAGES.get(tool) or ""
    if not image:
        return {"error": f"no image for tool {tool}"}

    # Ensure the image exists (lazy build) before detaching.
    if not await runner._ensure_image(image):
        return {"error": f"image {image} unavailable"}

    from .utils.sanitize import sanitize_command
    try:
        _, binary, sargs = sanitize_command(tool, args)
    except ValueError as e:
        return {"error": f"command rejected: {e}"}

    volumes = runner._prepare_volumes()
    name = f"ctftoolkit-job-{job_id[:8]}"
    loop = asyncio.get_running_loop()
    try:
        container = await loop.run_in_executor(None, lambda: client.containers.run(
            image=image,
            command=[binary] + sargs,
            name=name,
            detach=True,
            remove=False,                       # survive restart; reaped explicitly
            network_disabled=tool in _OFFLINE_TOOLS,
            cap_drop=["ALL"],
            security_opt=["no-new-privileges:true"],
            user=os.environ.get("CTFTOOLKIT_CONTAINER_USER", "1000:1000"),
            mem_limit=os.environ.get("CTFTOOLKIT_MEM_LIMIT", "1g"),
            pids_limit=int(os.environ.get("CTFTOOLKIT_PIDS_LIMIT", "256")),
            volumes=volumes,
            labels={
                "ctftoolkit.managed": "true",
                JOB_LABEL: "true",
                JOB_ID_LABEL: job_id,
                "ctftoolkit.tool": tool,
            },
        ))
    except Exception as e:
        return {"error": f"failed to start durable container: {e}"}

    from .db import get_database
    db = await get_database()
    await db.set_scan_job_container(job_id, container.id)
    logger.info("durable job %s started in container %s", job_id, container.id[:12])
    return {"container_id": container.id}


async def reconcile_stale_jobs() -> dict:
    """Resolve every `running` scan_jobs row against actual Docker state.

    Returns a summary dict of counts. Safe to run at startup before tools register.
    """
    summary = {"failed": 0, "completed": 0, "reattached": 0, "orphans_removed": 0}
    try:
        from .db import get_database
        db = await get_database()
        client = _client()
        loop = asyncio.get_running_loop()

        running = await db.list_scan_jobs(status="running")
        for job in running:
            job_id = job["job_id"]
            cid = job.get("container_id")
            if not cid:
                # Short ephemeral job whose process died with the server -> failed.
                await db.finish_scan_job(job_id, status="failed", exit_code=-1,
                                         output="", error="server restarted; job lost")
                summary["failed"] += 1
                continue
            try:
                container = await loop.run_in_executor(None, lambda c=cid: client.containers.get(c))
            except Exception:
                await db.finish_scan_job(job_id, status="failed", exit_code=-1,
                                         output="", error="container not found on restart")
                summary["failed"] += 1
                continue
            state = container.attrs.get("State", {})
            if state.get("Running"):
                summary["reattached"] += 1  # leave it; still working
                continue
            # Exited: collect logs, complete, remove.
            try:
                logs = await loop.run_in_executor(
                    None, lambda c=container: c.logs(stdout=True, stderr=True))
                output = logs.decode("utf-8", "replace") if isinstance(logs, bytes) else str(logs)
                exit_code = state.get("ExitCode", 0)
            except Exception as e:
                output, exit_code = f"(log fetch failed: {e})", -1
            await db.finish_scan_job(
                job_id, status="failed" if exit_code else "completed",
                exit_code=exit_code, output=output[:20000], error=None)
            try:
                await loop.run_in_executor(None, lambda c=container: c.remove(force=True))
            except Exception:
                pass
            summary["completed"] += 1

        # Remove labeled job containers with NO matching running DB row (true orphans).
        try:
            labeled = await loop.run_in_executor(None, lambda: client.containers.list(
                all=True, filters={"label": f"{JOB_LABEL}=true"}))
            known_ids = {j.get("container_id") for j in running}
            for c in labeled:
                if c.id in known_ids:
                    continue
                if c.attrs.get("State", {}).get("Running"):
                    continue  # belongs to a live in-process task
                await loop.run_in_executor(None, lambda c=c: c.remove(force=True))
                summary["orphans_removed"] += 1
        except Exception as e:
            logger.warning("durable orphan sweep skipped: %s", e)

        if any(summary.values()):
            logger.info("job reconciliation: %s", summary)
        return summary
    except Exception as e:
        logger.warning("job reconciliation skipped: %s", e)
        return summary
