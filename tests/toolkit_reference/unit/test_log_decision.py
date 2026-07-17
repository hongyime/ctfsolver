"""Tests for log_decision functionality."""

import pytest
import tempfile
import os
from pathlib import Path


class TestLogDecision:
    """Test the log_decision method."""

    @pytest.mark.asyncio
    async def test_log_decision_basic(self):
        """Test basic decision logging."""
        from src.ctf_core.db import CTFDatabase
        
        # Create a temp database
        with tempfile.NamedTemporaryFile(suffix='.db', delete=False) as f:
            db_path = Path(f.name)
        
        try:
            db = CTFDatabase(db_path=db_path)
            await db.connect()
            
            # Create the decisions table
            await db._db.execute("""
                CREATE TABLE IF NOT EXISTS decisions (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    target_id INTEGER,
                    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    decision_path TEXT NOT NULL,
                    confidence_scores TEXT,
                    reasoning TEXT,
                    selected_action TEXT
                )
            """)
            await db._db.commit()
            
            # Log a decision
            decision_id = await db.log_decision(
                decision_path="web/sqli",
                reasoning="Target shows SQL error messages indicating SQL injection vulnerability",
                confidence_scores={"data_quality": 0.8, "impact": 0.9},
                selected_action="sqlmap -u http://target.com/login.php"
            )
            
            assert decision_id > 0
            
            await db.close()
        finally:
            # Clean up
            if db_path.exists():
                os.unlink(db_path)

    @pytest.mark.asyncio
    async def test_log_decision_without_confidence_scores(self):
        """Test decision logging without confidence scores."""
        from src.ctf_core.db import CTFDatabase
        
        with tempfile.NamedTemporaryFile(suffix='.db', delete=False) as f:
            db_path = Path(f.name)
        
        try:
            db = CTFDatabase(db_path=db_path)
            await db.connect()
            
            # Create the decisions table
            await db._db.execute("""
                CREATE TABLE IF NOT EXISTS decisions (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    target_id INTEGER,
                    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    decision_path TEXT NOT NULL,
                    confidence_scores TEXT,
                    reasoning TEXT,
                    selected_action TEXT
                )
            """)
            await db._db.commit()
            
            # Log a decision without confidence scores
            decision_id = await db.log_decision(
                decision_path="recon/nmap",
                reasoning="Initial reconnaissance to discover open ports"
            )
            
            assert decision_id > 0
            
            await db.close()
        finally:
            if db_path.exists():
                os.unlink(db_path)

    @pytest.mark.asyncio
    async def test_get_decisions(self):
        """Test getting decision history."""
        from src.ctf_core.db import CTFDatabase
        
        with tempfile.NamedTemporaryFile(suffix='.db', delete=False) as f:
            db_path = Path(f.name)
        
        try:
            db = CTFDatabase(db_path=db_path)
            await db.connect()
            
            # Create the decisions table
            await db._db.execute("""
                CREATE TABLE IF NOT EXISTS decisions (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    target_id INTEGER,
                    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    decision_path TEXT NOT NULL,
                    confidence_scores TEXT,
                    reasoning TEXT,
                    selected_action TEXT
                )
            """)
            await db._db.commit()
            
            # Log some decisions
            await db.log_decision(decision_path="web/xss", reasoning="Test 1")
            await db.log_decision(decision_path="web/sqli", reasoning="Test 2")
            
            # Get decisions
            decisions = await db.get_decisions(limit=10)
            
            assert len(decisions) == 2
            
            await db.close()
        finally:
            if db_path.exists():
                os.unlink(db_path)
