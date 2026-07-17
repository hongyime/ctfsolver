"""F1 regression: run_binary_analysis invokes the static-analysis tools and
combines their output (real-container execution verified out-of-band)."""

import tempfile
from pathlib import Path
from unittest.mock import AsyncMock

import pytest

from src.ctf_core.db import init_database, CTFDatabase
import src.ctf_core.server as srv


class TestBinaryAnalysisF1:
    @pytest.mark.asyncio
    async def test_runs_all_tools_and_combines(self, tmp_path):
        p = tmp_path / "f1.db"
        assert await init_database(p)
        srv.db = CTFDatabase(p)
        await srv.db.connect()

        calls = []

        async def fake_run_tool(tool, args, timeout=120, image=None):
            calls.append((tool, list(args)))
            return {"stdout": f"<{tool} output>", "stderr": "", "exit_code": 0}

        srv.docker_runner = AsyncMock()
        srv.docker_runner.run_tool = AsyncMock(side_effect=fake_run_tool)
        try:
            out = await srv.run_binary_analysis("challenge.bin")
        finally:
            await srv.db.close()
            srv.db = None
            srv.docker_runner = None

        invoked = {c[0] for c in calls}
        assert {"file", "readelf", "nm", "strings"} <= invoked
        # every tool targeted the workspace path
        assert all("/workspace/challenge.bin" in c[1] for c in calls)
        # combined output includes each tool's section + output
        for t in ("file", "readelf", "nm", "strings"):
            assert f"<{t} output>" in out
