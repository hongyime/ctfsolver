#!/usr/bin/env python3
"""
Tier 1 Test: T1-002 Database Initialization

Tests database auto-initialization and basic operations.
"""

import os
import sys
import asyncio
import sqlite3
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from tests.hands_on._lib import TestRunner, TestStatus, print_banner


async def test_database_init() -> dict:
    """Test database initialization."""
    try:
        from src.ctf_core.db import init_database, CTFDatabase
        
        fd, temp_path = tempfile.mkstemp(suffix=".db")
        os.close(fd)
        db_path = Path(temp_path)
        
        try:
            result = await init_database(db_path)
            
            if not result:
                return {
                    "passed": False,
                    "message": "Database initialization failed",
                    "details": {}
                }
            
            if not db_path.exists():
                return {
                    "passed": False,
                    "message": "Database file not created",
                    "details": {}
                }
            
            db = CTFDatabase(db_path)
            await db.connect()
            await db.insert_target('127.0.0.1', 'localhost', 'linux')
            targets = await db.get_targets()
            await db.close()
            
            return {
                "passed": True,
                "message": f"Database initialized, {len(targets)} targets in test DB",
                "details": {
                    "db_path": str(db_path),
                    "target_count": len(targets)
                }
            }
        finally:
            sqlite3.connect(str(db_path)).close()
    except Exception as e:
        return {
            "passed": False,
            "message": f"Error: {str(e)}",
            "details": {"exception": str(e)}
        }


async def test_database_crud() -> dict:
    """Test CRUD operations on database."""
    try:
        from src.ctf_core.db import init_database, CTFDatabase
        
        fd, temp_path = tempfile.mkstemp(suffix=".db")
        os.close(fd)
        db_path = Path(temp_path)
        
        try:
            await init_database(db_path)
            
            db = CTFDatabase(db_path)
            await db.connect()
            
            target_id = await db.insert_target('192.168.1.100', 'testhost', 'linux')
            targets = await db.get_targets()
            await db.get_services(target_id=target_id)
            await db.insert_service(target_id, 22, 'tcp', 'ssh', 'OpenSSH 8.0')
            await db.insert_service(target_id, 80, 'tcp', 'http', 'Apache 2.4')
            services_after = await db.get_services(target_id=target_id)
            await db.log_action(
                tool_used='test',
                command_string='test command',
                reason='success',
                target_id=target_id,
            )
            actions = await db.get_recent_actions(limit=10)
            await db.close()
            
            return {
                "passed": len(services_after) >= 2 and len(actions) > 0,
                "message": f"CRUD: {len(targets)} targets, {len(services_after)} services, {len(actions)} actions",
                "details": {
                    "targets": len(targets),
                    "services": len(services_after),
                    "actions": len(actions)
                }
            }
        finally:
            sqlite3.connect(str(db_path)).close()
    except Exception as e:
        return {
            "passed": False,
            "message": f"Error: {str(e)}",
            "details": {"exception": str(e)}
        }


def run_tests():
    """Run all Tier 1 database tests."""
    print_banner()
    
    runner = TestRunner(tier=1, suite_name="Database Tests")
    runner.print_header("Tier 1: Database Initialization & CRUD")
    
    print("Testing database auto-initialization and basic operations.\n")
    
    runner.run_test(test_database_init, "T1-002", "Database Initialization")
    runner.run_test(test_database_crud, "T1-003", "Database CRUD Operations")
    
    result = runner.complete()
    runner.print_summary()
    
    return 0 if result.failed == 0 and result.errors == 0 else 1


if __name__ == "__main__":
    sys.exit(asyncio.run(run_tests()))
