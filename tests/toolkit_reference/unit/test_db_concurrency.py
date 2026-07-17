"""Concurrency + atomicity tests for the shared SQLite connection (P2-008).

Validates the Sprint-2 state-integrity substrate:
  P2-002 foreign_keys enforcement
  P2-003 insert_target RETURNING id (no TOCTOU)
  P2-004 single shared connection survives concurrent writers
  P2-006 transaction() atomicity (commit-as-unit / rollback-on-error)
"""

import asyncio

import pytest

from src.ctf_core.db import CTFDatabase, init_database


async def _fresh_db(tmp_path):
    db_path = tmp_path / "concurrency.db"
    assert await init_database(db_path), "init_database failed"
    db = CTFDatabase(db_path)
    await db.connect()
    return db


class TestSharedConnectionConcurrency:
    """Concurrent writes through the single shared aiosqlite connection must
    not lose or corrupt rows."""

    @pytest.mark.asyncio
    async def test_concurrent_insert_targets_no_lost_writes(self, tmp_path):
        db = await _fresh_db(tmp_path)
        try:
            n = 50
            ids = await asyncio.gather(
                *[db.insert_target(f"10.0.0.{i}", hostname=f"h{i}") for i in range(n)]
            )
            rows = await db.get_targets(limit=1000)
            assert len(rows) == n, "lost writes under concurrency"
            assert len(set(ids)) == n, "duplicate/colliding target ids"
            assert all(isinstance(i, int) for i in ids)
        finally:
            await db.close()

    @pytest.mark.asyncio
    async def test_concurrent_insert_flags_count(self, tmp_path):
        db = await _fresh_db(tmp_path)
        try:
            n = 40
            await asyncio.gather(
                *[db.insert_flag(flag=f"flag{{{i}}}", source="t") for i in range(n)]
            )
            count = (await (await db._db.execute("SELECT COUNT(*) FROM flags")).fetchone())[0]
            assert count == n
        finally:
            await db.close()

    @pytest.mark.asyncio
    async def test_insert_target_upsert_returns_stable_id(self, tmp_path):
        db = await _fresh_db(tmp_path)
        try:
            id1 = await db.insert_target("172.16.0.1", hostname="a")
            id2 = await db.insert_target("172.16.0.1", hostname="b")  # upsert
            assert id1 == id2, "P2-003: upsert must return the same id"
            rows = await db.get_targets(limit=10)
            assert len(rows) == 1
        finally:
            await db.close()


class TestTransactionAtomicity:
    """transaction() groups writes into one atomic unit (P2-006)."""

    @pytest.mark.asyncio
    async def test_transaction_rolls_back_on_error(self, tmp_path):
        db = await _fresh_db(tmp_path)
        try:
            with pytest.raises(RuntimeError):
                async with db.transaction():
                    await db.insert_target("192.168.1.1", hostname="x")
                    raise RuntimeError("boom")
            rows = await db.get_targets(limit=10)
            assert len(rows) == 0, "rolled-back write must not persist"
        finally:
            await db.close()

    @pytest.mark.asyncio
    async def test_transaction_commits_as_unit(self, tmp_path):
        db = await _fresh_db(tmp_path)
        try:
            async with db.transaction():
                tid = await db.insert_target("192.168.1.2", hostname="y")
                await db.insert_service(target_id=tid, port=22, service_name="ssh")
                await db.insert_service(target_id=tid, port=80, service_name="http")
            services = await db.get_services(target_id=tid)
            assert len(services) == 2
        finally:
            await db.close()


class TestForeignKeyEnforcement:
    """foreign_keys pragma is ON and actually enforced (P2-002)."""

    @pytest.mark.asyncio
    async def test_foreign_keys_pragma_on(self, tmp_path):
        db = await _fresh_db(tmp_path)
        try:
            fk = (await (await db._db.execute("PRAGMA foreign_keys")).fetchone())[0]
            assert fk == 1
        finally:
            await db.close()

    @pytest.mark.asyncio
    async def test_orphan_service_rejected(self, tmp_path):
        db = await _fresh_db(tmp_path)
        try:
            with pytest.raises(Exception):
                await db.insert_service(target_id=999999, port=1, service_name="x")
        finally:
            await db.close()
