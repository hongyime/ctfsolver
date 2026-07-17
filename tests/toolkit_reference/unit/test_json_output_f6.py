"""F6 regression: parsing MCP tools return structured JSON when format='json'."""

import json
import tempfile
from pathlib import Path
from unittest.mock import AsyncMock

import pytest

from src.ctf_core.db import init_database, CTFDatabase
import src.ctf_core.server as srv

NMAP_XML = (
    '<?xml version="1.0"?><nmaprun><host>'
    '<address addr="10.10.10.9" addrtype="ipv4"/>'
    '<ports><port protocol="tcp" portid="80"><state state="open"/>'
    '<service name="http"/></port></ports></host></nmaprun>'
)


class TestJsonOutputF6:
    @pytest.mark.asyncio
    async def test_run_nmap_json_format(self, tmp_path):
        p = tmp_path / "f6.db"
        assert await init_database(p)
        srv.db = CTFDatabase(p)
        await srv.db.connect()
        srv.docker_runner = AsyncMock()
        srv.docker_runner.run_tool = AsyncMock(
            return_value={"stdout": NMAP_XML, "stderr": "", "exit_code": 0}
        )
        try:
            out = await srv.run_nmap("10.10.10.9", format="json")
            data = json.loads(out)  # must be valid JSON
            assert "hosts" in data
            assert data["hosts"][0]["ip_address"] == "10.10.10.9"
            assert data["hosts"][0]["services"][0]["port"] == 80

            # default (text) is NOT json
            text = await srv.run_nmap("10.10.10.9")
            with pytest.raises(json.JSONDecodeError):
                json.loads(text)
        finally:
            await srv.db.close()
            srv.db = None
            srv.docker_runner = None
