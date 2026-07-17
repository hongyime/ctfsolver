"""F3 regression: async scan handles (start_scan/poll_scan/get_scan_result + scan_jobs)."""

import tempfile
from pathlib import Path
from unittest.mock import AsyncMock

import pytest

from src.ctf_core.db import init_database, CTFDatabase
import src.ctf_core.server as srv


class TestAsyncScanF3:
    @pytest.mark.asyncio
    async def test_scan_jobs_table_created(self, tmp_path):
        p = tmp_path / "f3a.db"
        assert await init_database(p)
        db = CTFDatabase(p)
        await db.connect()
        try:
            row = await (
                await db._db.execute(
                    "SELECT name FROM sqlite_master WHERE name='scan_jobs'"
                )
            ).fetchone()
            assert row is not None
        finally:
            await db.close()

    @pytest.mark.asyncio
    async def test_full_job_lifecycle(self, tmp_path):
        p = tmp_path / "f3b.db"
        assert await init_database(p)
        srv.db = CTFDatabase(p)
        await srv.db.connect()
        srv.docker_runner = AsyncMock()
        srv.docker_runner.run_tool = AsyncMock(
            return_value={"stdout": "22/tcp open ssh", "stderr": "", "exit_code": 0}
        )
        try:
            msg = await srv.start_scan("nmap", "-sV target.example")
            assert "Started scan job" in msg
            job_id = msg.split("job ")[1].split(" ")[0]

            task = srv._scan_tasks.get(job_id)
            if task is not None:
                await task  # let the background worker finish

            poll = await srv.poll_scan(job_id)
            assert "completed" in poll

            result = await srv.get_scan_result(job_id)
            assert "22/tcp open ssh" in result
        finally:
            await srv.db.close()
            srv.db = None
            srv.docker_runner = None

    @pytest.mark.asyncio
    async def test_poll_unknown_job(self, tmp_path):
        p = tmp_path / "f3c.db"
        assert await init_database(p)
        srv.db = CTFDatabase(p)
        await srv.db.connect()
        try:
            assert "No scan job" in await srv.poll_scan("deadbeef")
        finally:
            await srv.db.close()
            srv.db = None
