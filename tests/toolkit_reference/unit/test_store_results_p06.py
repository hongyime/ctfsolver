"""P0-006 regression: Executor.store_results parses tool output and persists
structured findings + flags (the autonomous pipeline is no longer a stub)."""

import tempfile
from pathlib import Path

import pytest

from src.ctf_core.db import init_database, CTFDatabase
from src.ctf_core.agents.executor import Executor

NMAP_XML = (
    '<?xml version="1.0"?><nmaprun><host>'
    '<address addr="10.10.10.7" addrtype="ipv4"/>'
    '<ports><port protocol="tcp" portid="22"><state state="open"/>'
    '<service name="ssh" product="OpenSSH"/></port></ports></host></nmaprun>'
)


async def _db(tmp_path):
    p = tmp_path / "pipe.db"
    assert await init_database(p)
    db = CTFDatabase(p)
    await db.connect()
    return db


class TestStoreResultsP0_6:
    @pytest.mark.asyncio
    async def test_nmap_persists_target_and_service(self, tmp_path):
        db = await _db(tmp_path)
        try:
            ex = Executor(docker_runner=None, db=db)
            await ex.store_results({"tool": "nmap", "output": NMAP_XML}, target_id=None)
            targets = await db.get_targets(limit=10)
            services = await db.get_services(limit=10)
            assert any(t["ip_address"] == "10.10.10.7" for t in targets)
            assert any(s["port"] == 22 for s in services)
        finally:
            await db.close()

    @pytest.mark.asyncio
    async def test_flag_captured_from_output(self, tmp_path):
        db = await _db(tmp_path)
        try:
            ex = Executor(docker_runner=None, db=db)
            await ex.store_results(
                {"tool": "feroxbuster", "output": "200 /admin flag{found_it}"}, target_id=None
            )
            rows = await (await db._db.execute("SELECT flag_value FROM flags")).fetchall()
            assert any("found_it" in r["flag_value"] for r in rows)
        finally:
            await db.close()

    @pytest.mark.asyncio
    async def test_sqlmap_credential_persisted(self, tmp_path):
        db = await _db(tmp_path)
        try:
            ex = Executor(docker_runner=None, db=db)
            tid = await db.insert_target("192.0.2.10")
            await ex.store_results(
                {"tool": "sqlmap", "output": "admin:5f4dcc3b5aa765d61d8327deb882cf99\n"},
                target_id=tid,
            )
            creds = await db.get_credentials(target_id=tid)
            assert any(c["username"] == "admin" for c in creds)
        finally:
            await db.close()
