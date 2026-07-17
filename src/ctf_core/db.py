"""Async SQLite database helpers for CTF state management."""

import asyncio
import aiosqlite
import logging
import os
from contextlib import asynccontextmanager
from datetime import datetime
from pathlib import Path
from typing import Any, Optional

logger = logging.getLogger(__name__)

# Default database path - use environment variable if set, otherwise project-relative
if os.environ.get("CTFTOOLKIT_DB_PATH"):
    DEFAULT_DB_PATH = Path(os.environ["CTFTOOLKIT_DB_PATH"])
else:
    # Project-relative path
    DEFAULT_DB_PATH = Path(__file__).parent.parent.parent / "ctf_state.db"


class CTFDatabase:
    """Async SQLite database wrapper for CTF state management."""
    
    def __init__(self, db_path: Path = DEFAULT_DB_PATH):
        self.db_path = db_path
        self._db: Optional[aiosqlite.Connection] = None
        self._in_transaction = False
    
    async def connect(self) -> None:
        """Establish database connection."""
        self._db = await aiosqlite.connect(self.db_path)
        self._db.row_factory = aiosqlite.Row
        await self._db.execute("PRAGMA journal_mode=WAL")
        await self._db.execute("PRAGMA synchronous=NORMAL")
        await self._db.execute("PRAGMA cache_size=10000")
        await self._db.execute("PRAGMA foreign_keys=ON")
        logger.info(f"Connected to database: {self.db_path}")
    
    async def close(self) -> None:
        """Close database connection."""
        if self._db:
            await self._db.close()
            self._db = None

    async def _maybe_commit(self) -> None:
        """Commit unless inside an explicit transaction() block (P2-006)."""
        if not self._in_transaction and self._db is not None:
            await self._db.commit()

    @asynccontextmanager
    async def transaction(self):
        """Group multiple writes into one atomic transaction (P2-006)."""
        if self._db is None:
            raise RuntimeError("Database not connected. Call connect() first.")
        self._in_transaction = True
        try:
            yield
            await self._db.commit()
        except Exception:
            await self._db.rollback()
            raise
        finally:
            self._in_transaction = False
    
    async def insert_target(
        self,
        ip_address: str,
        hostname: Optional[str] = None,
        os_type: Optional[str] = None,
    ) -> int:
        """Insert or update a target. Returns target ID."""
        if self._db is None: raise RuntimeError("Database not connected. Call connect() first.")
        
        cursor = await self._db.execute(
            """
            INSERT INTO targets (ip_address, hostname, os_type)
            VALUES (?, ?, ?)
            ON CONFLICT(ip_address) DO UPDATE SET
                hostname = excluded.hostname,
                os_type = excluded.os_type,
                status = 'active'
            RETURNING id
            """,
            (ip_address, hostname, os_type),
        )
        row = await cursor.fetchone()
        await self._maybe_commit()
        return row["id"] if row else 0
    
    async def insert_service(
        self,
        target_id: int,
        port: int,
        protocol: str = "tcp",
        service_name: Optional[str] = None,
        banner: Optional[str] = None,
    ) -> int:
        """Insert or update a service."""
        if self._db is None: raise RuntimeError("Database not connected. Call connect() first.")
        
        cursor = await self._db.execute(
            """
            INSERT INTO services (target_id, port, protocol, service_name, banner)
            VALUES (?, ?, ?, ?, ?)
            ON CONFLICT(target_id, port, protocol) DO UPDATE SET
                service_name = excluded.service_name,
                banner = excluded.banner
            """,
            (target_id, port, protocol, service_name, banner),
        )
        await self._maybe_commit()
        return cursor.lastrowid or 0
    
    async def insert_web_directory(
        self,
        target_id: int,
        path: str,
        status_code: Optional[int] = None,
    ) -> int:
        """Insert a discovered web directory."""
        if self._db is None: raise RuntimeError("Database not connected. Call connect() first.")
        
        cursor = await self._db.execute(
            """
            INSERT INTO web_directories (target_id, path, status_code)
            VALUES (?, ?, ?)
            ON CONFLICT(target_id, path) DO UPDATE SET
                status_code = excluded.status_code
            """,
            (target_id, path, status_code),
        )
        await self._maybe_commit()
        return cursor.lastrowid or 0
    
    async def insert_credential(
        self,
        target_id: int,
        username: str,
        password_hash: Optional[str] = None,
        cleartext: Optional[str] = None,
    ) -> int:
        """Insert discovered credentials."""
        if self._db is None: raise RuntimeError("Database not connected. Call connect() first.")
        
        cursor = await self._db.execute(
            """
            INSERT INTO credentials (target_id, username, password_hash, cleartext)
            VALUES (?, ?, ?, ?)
            """,
            (target_id, username, password_hash, cleartext),
        )
        await self._maybe_commit()
        return cursor.lastrowid or 0
    
    async def insert_exploit(
        self,
        target_id: int,
        exploit_path: str,
        cve_id: Optional[str] = None,
    ) -> int:
        """Insert an exploit reference."""
        if self._db is None: raise RuntimeError("Database not connected. Call connect() first.")
        
        cursor = await self._db.execute(
            """
            INSERT INTO exploits (target_id, cve_id, exploit_path)
            VALUES (?, ?, ?)
            """,
            (target_id, cve_id, exploit_path),
        )
        await self._maybe_commit()
        return cursor.lastrowid or 0
    
    async def insert_flag(
        self,
        flag: str,
        source: Optional[str] = None,
        pattern: Optional[str] = None,
        target_id: Optional[int] = None,
        flag_value: Optional[str] = None,
    ) -> int:
        """Insert a captured flag. Accepts either `flag` or legacy `flag_value` kwarg."""
        if self._db is None: raise RuntimeError("Database not connected. Call connect() first.")
        value = flag if flag is not None else flag_value
        # P4-009: dedup - skip insert if this (value, source) flag already exists
        existing = await self._db.execute(
            "SELECT id FROM flags WHERE flag_value IS ? AND source IS ?", (value, source)
        )
        dup = await existing.fetchone()
        if dup is not None:
            return dup["id"]
        cursor = await self._db.execute(
            """
            INSERT INTO flags (target_id, flag_value, source, pattern)
            VALUES (?, ?, ?, ?)
            """,
            (target_id, value, source, pattern),
        )
        await self._maybe_commit()
        return cursor.lastrowid or 0
    
    async def log_action(
        self,
        tool_used: str,
        command_string: str,
        reason: Optional[str] = None,
        target_id: Optional[int] = None,
    ) -> int:
        """Log an action to the audit trail."""
        if self._db is None: raise RuntimeError("Database not connected. Call connect() first.")
        
        cursor = await self._db.execute(
            """
            INSERT INTO action_log (target_id, tool_used, command_string, reason)
            VALUES (?, ?, ?, ?)
            """,
            (target_id, tool_used, command_string, reason),
        )
        await self._maybe_commit()
        return cursor.lastrowid or 0

    async def log_reasoning_step(
        self,
        step_number: int,
        step_description: str,
        challenge_id: Optional[str] = None,
        action_id: Optional[int] = None,
    ) -> Optional[int]:
        """Insert a reasoning_log step (P2-001: public API, no raw _db access)."""
        if self._db is None:
            raise RuntimeError("Database not connected. Call connect() first.")
        cursor = await self._db.execute(
            "INSERT INTO reasoning_log (challenge_id, action_id, step_number, step_description, timestamp)"
            " VALUES (?, ?, ?, ?, datetime('now'))",
            (challenge_id, action_id, step_number, step_description),
        )
        await self._maybe_commit()
        return cursor.lastrowid or 0

    async def update_reasoning_output(
        self,
        step_output: str,
        step_number: int,
        challenge_id: Optional[str] = None,
    ) -> None:
        """Update a reasoning_log step's output (P2-001). NULL-safe on challenge_id."""
        if self._db is None:
            raise RuntimeError("Database not connected. Call connect() first.")
        await self._db.execute(
            "UPDATE reasoning_log SET step_output=? WHERE challenge_id IS ? AND step_number=?",
            (step_output, challenge_id, step_number),
        )
        await self._maybe_commit()
    
    async def log_decision(
        self,
        decision_path: str,
        reasoning: str,
        confidence_scores: Optional[dict[str, float]] = None,
        selected_action: Optional[str] = None,
        target_id: Optional[int] = None,
    ) -> int:
        """
        Log a decision to the decision history.
        
        Args:
            decision_path: The path/category of the decision (e.g., "web/sqli", "recon/nmap")
            reasoning: The reasoning behind the decision
            confidence_scores: Dict of confidence scores for different factors
            selected_action: The action that was selected
            target_id: Optional target ID this decision relates to
            
        Returns:
            The ID of the inserted decision record
        """
        if self._db is None: raise RuntimeError("Database not connected. Call connect() first.")
        
        # Convert confidence_scores dict to JSON string for storage
        scores_json = None
        if confidence_scores:
            import json
            scores_json = json.dumps(confidence_scores)
        
        cursor = await self._db.execute(
            """
            INSERT INTO decisions (target_id, decision_path, confidence_scores, reasoning, selected_action)
            VALUES (?, ?, ?, ?, ?)
            """,
            (target_id, decision_path, scores_json, reasoning, selected_action),
        )
        await self._maybe_commit()
        return cursor.lastrowid or 0
    
    async def get_decisions(
        self,
        target_id: Optional[int] = None,
        limit: int = 50,
        offset: int = 0,
    ) -> list[dict[str, Any]]:
        """
        Get decision history with pagination.
        
        Args:
            target_id: Optional target ID to filter by
            limit: Maximum number of results to return
            offset: Number of results to skip
            
        Returns:
            List of decision records
        """
        if self._db is None: raise RuntimeError("Database not connected. Call connect() first.")
        
        if target_id:
            cursor = await self._db.execute(
                """
                SELECT * FROM decisions 
                WHERE target_id = ?
                ORDER BY timestamp DESC
                LIMIT ? OFFSET ?
                """,
                (target_id, limit, offset),
            )
        else:
            cursor = await self._db.execute(
                """
                SELECT * FROM decisions 
                ORDER BY timestamp DESC
                LIMIT ? OFFSET ?
                """,
                (limit, offset),
            )
        
        rows = await cursor.fetchall()
        return [dict(row) for row in rows]
    
    async def get_services(
        self,
        target_id: Optional[int] = None,
        limit: int = 50,
        offset: int = 0,
    ) -> list[dict[str, Any]]:
        """Get services with pagination. Includes ip_address via JOIN with targets."""
        if self._db is None: raise RuntimeError("Database not connected. Call connect() first.")

        base = """
            SELECT s.*, t.ip_address
            FROM services s
            LEFT JOIN targets t ON t.id = s.target_id
        """
        if target_id:
            cursor = await self._db.execute(
                base + "WHERE s.target_id = ? ORDER BY s.port LIMIT ? OFFSET ?",
                (target_id, limit, offset),
            )
        else:
            cursor = await self._db.execute(
                base + "ORDER BY s.target_id, s.port LIMIT ? OFFSET ?",
                (limit, offset),
            )

        rows = await cursor.fetchall()
        return [dict(row) for row in rows]
    
    async def get_targets(
        self,
        status: Optional[str] = None,
        limit: int = 50,
    ) -> list[dict[str, Any]]:
        """Get targets with optional status filter."""
        if self._db is None: raise RuntimeError("Database not connected. Call connect() first.")
        
        if status:
            cursor = await self._db.execute(
                "SELECT * FROM targets WHERE status = ? LIMIT ?",
                (status, limit),
            )
        else:
            cursor = await self._db.execute(
                "SELECT * FROM targets LIMIT ?", (limit,)
            )
        
        rows = await cursor.fetchall()
        return [dict(row) for row in rows]
    
    async def get_target_by_ip(self, ip_address: str) -> Optional[dict[str, Any]]:
        """Get a target by IP address."""
        if self._db is None: raise RuntimeError("Database not connected. Call connect() first.")
        
        cursor = await self._db.execute(
            "SELECT * FROM targets WHERE ip_address = ?", (ip_address,)
        )
        row = await cursor.fetchone()
        return dict(row) if row else None
    
    async def get_recent_actions(
        self,
        target_id: Optional[int] = None,
        limit: int = 20,
    ) -> list[dict[str, Any]]:
        """Get recent actions from the audit log."""
        if self._db is None: raise RuntimeError("Database not connected. Call connect() first.")
        
        if target_id:
            cursor = await self._db.execute(
                """
                SELECT * FROM action_log 
                WHERE target_id = ?
                ORDER BY timestamp DESC
                LIMIT ?
                """,
                (target_id, limit),
            )
        else:
            cursor = await self._db.execute(
                "SELECT * FROM action_log ORDER BY timestamp DESC LIMIT ?", (limit,)
            )
        
        rows = await cursor.fetchall()
        return [dict(row) for row in rows]
    
    async def get_credentials(
        self,
        target_id: Optional[int] = None,
        limit: int = 50,
    ) -> list[dict[str, Any]]:
        """Get discovered credentials."""
        if self._db is None: raise RuntimeError("Database not connected. Call connect() first.")
        
        if target_id:
            cursor = await self._db.execute(
                "SELECT * FROM credentials WHERE target_id = ? LIMIT ?",
                (target_id, limit),
            )
        else:
            cursor = await self._db.execute(
                "SELECT * FROM credentials LIMIT ?", (limit,)
            )
        
        rows = await cursor.fetchall()
        return [dict(row) for row in rows]
    
    async def get_exploits(
        self,
        target_id: Optional[int] = None,
        limit: int = 50,
    ) -> list[dict[str, Any]]:
        """Get available exploits for a target."""
        if self._db is None: raise RuntimeError("Database not connected. Call connect() first.")
        
        if target_id:
            cursor = await self._db.execute(
                "SELECT * FROM exploits WHERE target_id = ? LIMIT ?",
                (target_id, limit),
            )
        else:
            cursor = await self._db.execute(
                "SELECT * FROM exploits LIMIT ?", (limit,)
            )
        
        rows = await cursor.fetchall()
        return [dict(row) for row in rows]

    async def create_scan_job(self, job_id: str, tool: str, args: str,
                              job_type: str = "short", durable: bool = False,
                              image_name: Optional[str] = None,
                              container_id: Optional[str] = None) -> None:
        """Create a running scan job row (F3 / Phase 2 tiered durability)."""
        if self._db is None:
            raise RuntimeError("Database not connected. Call connect() first.")
        await self._db.execute(
            "INSERT INTO scan_jobs (job_id, tool, args, status, job_type, durable, "
            "image_name, container_id, last_active_at) "
            "VALUES (?, ?, ?, 'running', ?, ?, ?, ?, datetime('now'))",
            (job_id, tool, args, job_type, 1 if durable else 0, image_name, container_id),
        )
        await self._maybe_commit()

    async def finish_scan_job(self, job_id: str, status: str, exit_code: Optional[int],
                              output: str, error: Optional[str] = None) -> None:
        """Mark a scan job finished with its result (F3)."""
        if self._db is None:
            raise RuntimeError("Database not connected. Call connect() first.")
        await self._db.execute(
            "UPDATE scan_jobs SET status=?, exit_code=?, output=?, error=?, "
            "finished_at=datetime('now') WHERE job_id=?",
            (status, exit_code, output, error, job_id),
        )
        await self._maybe_commit()

    async def get_scan_job(self, job_id: str) -> Optional[dict[str, Any]]:
        """Fetch a scan job by id (F3)."""
        if self._db is None:
            raise RuntimeError("Database not connected. Call connect() first.")
        cursor = await self._db.execute("SELECT * FROM scan_jobs WHERE job_id = ?", (job_id,))
        row = await cursor.fetchone()
        return dict(row) if row else None

    # --- Phase 2: durable job lifecycle ---
    async def set_scan_job_container(self, job_id: str, container_id: str) -> None:
        """Record the detached container id for a durable job."""
        if self._db is None:
            raise RuntimeError("Database not connected. Call connect() first.")
        await self._db.execute(
            "UPDATE scan_jobs SET container_id=?, last_active_at=datetime('now') WHERE job_id=?",
            (container_id, job_id),
        )
        await self._maybe_commit()

    async def touch_scan_job(self, job_id: str) -> None:
        """Update last_active_at heartbeat for a job."""
        if self._db is None:
            raise RuntimeError("Database not connected. Call connect() first.")
        await self._db.execute(
            "UPDATE scan_jobs SET last_active_at=datetime('now') WHERE job_id=?", (job_id,))
        await self._maybe_commit()

    async def list_scan_jobs(self, status: Optional[str] = None,
                             durable: Optional[bool] = None) -> list[dict[str, Any]]:
        """List scan jobs, optionally filtered by status and/or durability."""
        if self._db is None:
            raise RuntimeError("Database not connected. Call connect() first.")
        clauses, params = [], []
        if status is not None:
            clauses.append("status = ?"); params.append(status)
        if durable is not None:
            clauses.append("durable = ?"); params.append(1 if durable else 0)
        where = (" WHERE " + " AND ".join(clauses)) if clauses else ""
        cursor = await self._db.execute(
            f"SELECT * FROM scan_jobs{where} ORDER BY started_at DESC", params)
        rows = await cursor.fetchall()
        return [dict(r) for r in rows]

    # --- Phase 2: per-challenge tracking ---
    async def create_challenge(self, challenge_id: str, name: str,
                               category: Optional[str] = None,
                               workspace_path: Optional[str] = None,
                               agent_home_path: Optional[str] = None,
                               description: Optional[str] = None) -> int:
        """Create (or update) a challenge row. Returns its rowid."""
        if self._db is None:
            raise RuntimeError("Database not connected. Call connect() first.")
        cursor = await self._db.execute(
            """
            INSERT INTO challenges (challenge_id, name, category, description,
                                    workspace_path, agent_home_path, last_active_at)
            VALUES (?, ?, ?, ?, ?, ?, datetime('now'))
            ON CONFLICT(challenge_id) DO UPDATE SET
                name=excluded.name, category=excluded.category,
                workspace_path=excluded.workspace_path,
                agent_home_path=excluded.agent_home_path,
                last_active_at=datetime('now')
            """,
            (challenge_id, name, category, description, workspace_path, agent_home_path),
        )
        await self._maybe_commit()
        return cursor.lastrowid or 0

    async def get_challenge(self, challenge_id: str) -> Optional[dict[str, Any]]:
        """Fetch a challenge by its challenge_id."""
        if self._db is None:
            raise RuntimeError("Database not connected. Call connect() first.")
        cursor = await self._db.execute(
            "SELECT * FROM challenges WHERE challenge_id = ?", (challenge_id,))
        row = await cursor.fetchone()
        return dict(row) if row else None

    async def touch_challenge(self, challenge_id: str) -> None:
        """Update a challenge's last_active_at."""
        if self._db is None:
            raise RuntimeError("Database not connected. Call connect() first.")
        await self._db.execute(
            "UPDATE challenges SET last_active_at=datetime('now') WHERE challenge_id=?",
            (challenge_id,))
        await self._maybe_commit()

    async def set_challenge_status(self, challenge_id: str, status: str,
                                   flag: Optional[str] = None) -> None:
        """Update a challenge's status (and optionally captured flag / solved time)."""
        if self._db is None:
            raise RuntimeError("Database not connected. Call connect() first.")
        if flag is not None:
            await self._db.execute(
                "UPDATE challenges SET status=?, flag_captured=?, "
                "solved_at=datetime('now') WHERE challenge_id=?",
                (status, flag, challenge_id))
        else:
            await self._db.execute(
                "UPDATE challenges SET status=? WHERE challenge_id=?", (status, challenge_id))
        await self._maybe_commit()

# Global database instance
_db_instance: Optional[CTFDatabase] = None
_db_init_lock: Optional[asyncio.Lock] = None


async def get_database() -> CTFDatabase:
    """Get or create the global database instance."""
    global _db_instance, _db_init_lock
    if _db_init_lock is None:
        _db_init_lock = asyncio.Lock()
    async with _db_init_lock:
        if _db_instance is None:
            _db_instance = CTFDatabase()
            await _db_instance.connect()
    return _db_instance


async def close_database() -> None:
    """Close the global database instance."""
    global _db_instance
    if _db_instance:
        await _db_instance.close()
        _db_instance = None


async def init_database(db_path: Optional[Path] = None) -> bool:
    """
    Initialize the database schema if it doesn't exist.
    
    Creates all required tables from schema/init_db.sql.
    This allows the server to start without manual database setup.
    
    Args:
        db_path: Optional custom database path
        
    Returns:
        True if initialization succeeded, False otherwise
    """
    if db_path is None:
        db_path = DEFAULT_DB_PATH
    
    try:
        # Ensure parent directory exists
        db_path.parent.mkdir(parents=True, exist_ok=True)
        
        # Load schema SQL - look for schema file in project root
        # Try multiple possible locations
        possible_paths = [
            Path(__file__).parent.parent.parent / "schema" / "init_db.sql",  # Project root
            Path(__file__).parent.parent / "schema" / "init_db.sql",  # Relative to src/ctf_core
        ]
        
        schema_path = None
        for p in possible_paths:
            if p.exists():
                schema_path = p
                break
        
        if schema_path is None:
            logger.error(f"Schema file not found in any expected location")
            return False
        
        with open(schema_path) as f:
            schema_sql = f.read()
        
        # Load audit enhancements schema
        audit_paths = [
            Path(__file__).parent.parent.parent / "schema" / "audit_enhancements.sql",
            Path(__file__).parent.parent / "schema" / "audit_enhancements.sql",
        ]
        audit_schema_path = next((p for p in audit_paths if p.exists()), None)

        # Create tables
        async with aiosqlite.connect(db_path) as db:
            await db.executescript(schema_sql)
            if audit_schema_path:
                with open(audit_schema_path) as f:
                    audit_sql = f.read()
                await db.executescript(audit_sql)
            else:
                logger.warning("audit_enhancements.sql not found — audit tables will be missing")
            await db.commit()
            await _apply_migrations(db)

        logger.info(f"Database initialized at {db_path}")
        return True
        
    except Exception as e:
        logger.error(f"Failed to initialize database: {e}")
        return False


# --- Schema migrations (P2-005) ---
SCHEMA_VERSION = 3
MIGRATIONS: list[tuple[int, str]] = [
    # (version, sql): applied in order when PRAGMA user_version < version.
    (
        1,
        """
        CREATE TABLE reasoning_log_new (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            challenge_id TEXT,
            action_id INTEGER,
            step_number INTEGER NOT NULL,
            step_description TEXT NOT NULL,
            step_output TEXT,
            timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (challenge_id) REFERENCES challenges(challenge_id) ON DELETE SET NULL
        );
        INSERT INTO reasoning_log_new (id, challenge_id, action_id, step_number, step_description, step_output, timestamp)
            SELECT id, challenge_id, action_id, step_number, step_description, step_output, timestamp FROM reasoning_log;
        DROP TABLE reasoning_log;
        ALTER TABLE reasoning_log_new RENAME TO reasoning_log;
        CREATE TABLE token_usage_new (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            challenge_id TEXT,
            action_id INTEGER,
            tool_name TEXT,
            input_tokens INTEGER,
            output_tokens INTEGER,
            total_tokens INTEGER,
            timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (challenge_id) REFERENCES challenges(challenge_id) ON DELETE SET NULL
        );
        INSERT INTO token_usage_new (id, challenge_id, action_id, tool_name, input_tokens, output_tokens, total_tokens, timestamp)
            SELECT id, challenge_id, action_id, tool_name, input_tokens, output_tokens, total_tokens, timestamp FROM token_usage;
        DROP TABLE token_usage;
        ALTER TABLE token_usage_new RENAME TO token_usage;
        """,
    ),
    (
        2,
        """
        CREATE TABLE IF NOT EXISTS scan_jobs (
            job_id TEXT PRIMARY KEY,
            tool TEXT NOT NULL,
            args TEXT,
            status TEXT NOT NULL DEFAULT 'running',
            started_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            finished_at TIMESTAMP,
            exit_code INTEGER,
            output TEXT,
            error TEXT
        );
        """,
    ),
    (
        3,
        """
        -- Phase 2: tiered-durability + lifecycle columns on scan_jobs (additive).
        ALTER TABLE scan_jobs ADD COLUMN job_type TEXT DEFAULT 'short';
        ALTER TABLE scan_jobs ADD COLUMN image_name TEXT;
        ALTER TABLE scan_jobs ADD COLUMN container_id TEXT;
        ALTER TABLE scan_jobs ADD COLUMN durable INTEGER NOT NULL DEFAULT 0;
        ALTER TABLE scan_jobs ADD COLUMN last_active_at TIMESTAMP;
        -- Phase 2: per-challenge workspace + activity tracking (additive).
        ALTER TABLE challenges ADD COLUMN workspace_path TEXT;
        ALTER TABLE challenges ADD COLUMN agent_home_path TEXT;
        ALTER TABLE challenges ADD COLUMN last_active_at TIMESTAMP;
        -- Phase 2: attach findings to a challenge (additive; nullable, no enforced FK
        -- because SQLite cannot add a FK constraint via ALTER — kept as plain columns).
        ALTER TABLE flags ADD COLUMN challenge_id TEXT;
        ALTER TABLE credentials ADD COLUMN challenge_id TEXT;
        ALTER TABLE services ADD COLUMN challenge_id TEXT;
        """,
    ),
]


async def _apply_migrations(db: aiosqlite.Connection) -> None:
    """Apply pending migrations based on PRAGMA user_version (P2-005)."""
    cursor = await db.execute("PRAGMA user_version")
    row = await cursor.fetchone()
    current = (row[0] if row else 0) or 0
    for version, sql in MIGRATIONS:
        if version > current:
            logger.info(f"Applying migration {version}...")
            await db.executescript(sql)
            await db.execute(f"PRAGMA user_version = {version}")
            current = version
    if current < SCHEMA_VERSION:
        await db.execute(f"PRAGMA user_version = {SCHEMA_VERSION}")
    await db.commit()


async def migrate_database(db_path: Optional[Path] = None) -> bool:
    """Open an existing DB and apply any pending migrations (P2-005)."""
    if db_path is None:
        db_path = DEFAULT_DB_PATH
    try:
        async with aiosqlite.connect(db_path) as db:
            await _apply_migrations(db)
        return True
    except Exception as e:
        logger.error(f"Migration failed: {e}")
        return False
