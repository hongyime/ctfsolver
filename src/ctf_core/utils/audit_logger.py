"""Enhanced audit logging for CTF Toolkit.

Provides detailed auditing for network activity, security events, resource usage,
and file access. Extends the base database module with comprehensive audit capabilities.
"""

import json
import logging
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

import aiosqlite

from ..db import CTFDatabase, get_database

logger = logging.getLogger(__name__)


import re as _re

# Patterns whose VALUE should be masked in any logged command (clank mask_command).
_SECRET_FLAG_RE = _re.compile(
    r"(-e\s+\w+=)(\S+)"            # docker -e KEY=value"
    r"|(--?(?:password|passwd|pass|token|secret|api[-_]?key|key|auth)\s*[=\s]\s*)(\S+)",
    _re.IGNORECASE,
)


def mask_command(command: str) -> str:
    """Mask secret values in a command string before it is logged or stored.

    Turns `-e KEY=val` into `-e KEY=<set>` and `--password X` / `--token=X` into
    `--password <redacted>`, so secrets never land in the audit log or DB.
    """
    if not command:
        return command

    def _repl(m: _re.Match) -> str:
        if m.group(1):  # -e KEY=value
            return f"{m.group(1)}<set>"
        return f"{m.group(3)}<redacted>"

    return _SECRET_FLAG_RE.sub(_repl, command)

class AuditLogger:
    """
    Enhanced audit logger for CTF Toolkit.
    
    Provides comprehensive auditing for:
    - Network activity (connections, blocks, rate limits)
    - Security events (threats, anomalies, violations)
    - Resource usage (CPU, memory, disk, network)
    - File access (read, write, execute, delete)
    """
    
    def __init__(self, db: Optional[CTFDatabase] = None):
        """Initialize audit logger with database connection."""
        self.db = db
        self._enabled = True
    
    async def _get_connection(self) -> aiosqlite.Connection:
        """Get database connection."""
        if self.db is None:
            self.db = await get_database()
        # Access internal _db attribute - in production, add a public method to CTFDatabase
        return self.db._db  # type: ignore
    
    def enable(self) -> None:
        """Enable audit logging."""
        self._enabled = True
        logger.info("Audit logging enabled")
    
    def disable(self) -> None:
        """Disable audit logging."""
        self._enabled = False
        logger.info("Audit logging disabled")
    
    # Network Activity Auditing
    
    async def log_network_activity(
        self,
        tool_name: str,
        source_ip: str,
        destination_ip: str,
        destination_port: int,
        protocol: str,
        action: str,
        target_id: Optional[int] = None,
        zone: Optional[str] = None,
        details: Optional[Dict] = None,
    ) -> int:
        """
        Log network activity.
        
        Args:
            tool_name: Name of the tool making the connection
            source_ip: Source IP address
            destination_ip: Destination IP address
            destination_port: Destination port
            protocol: Network protocol (tcp/udp/icmp)
            action: allowed, blocked, rate_limited
            target_id: Optional target ID from database
            zone: Network zone (internal, lab, controlled, unrestricted)
            details: Additional details as dict
            
        Returns:
            ID of inserted record
        """
        if not self._enabled:
            return -1
        
        conn = await self._get_connection()
        details_json = json.dumps(details) if details else None
        
        cursor = await conn.execute(
            """
            INSERT INTO network_audit 
            (tool_name, target_id, source_ip, destination_ip, destination_port, 
             protocol, action, zone, details)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (tool_name, target_id, source_ip, destination_ip, destination_port,
             protocol, action, zone, details_json)
        )
        await conn.commit()
        return cursor.lastrowid or 0
    
    # Security Events Auditing
    
    async def log_security_event(
        self,
        event_type: str,
        threat_level: str,
        description: str,
        tool_name: Optional[str] = None,
        target_id: Optional[int] = None,
        details: Optional[Dict] = None,
        action_taken: Optional[str] = None,
    ) -> int:
        """
        Log a security event.
        
        Args:
            event_type: Type of security event
            threat_level: low, medium, high, critical
            description: Human-readable description
            tool_name: Optional tool name
            target_id: Optional target ID
            details: Additional details as dict
            action_taken: Action taken (logged, blocked, terminated)
            
        Returns:
            ID of inserted record
        """
        if not self._enabled:
            return -1
        
        conn = await self._get_connection()
        details_json = json.dumps(details) if details else None
        
        cursor = await conn.execute(
            """
            INSERT INTO security_events 
            (event_type, threat_level, tool_name, target_id, description, details, action_taken)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (event_type, threat_level, tool_name, target_id, description, details_json, action_taken)
        )
        await conn.commit()
        return cursor.lastrowid or 0
    
    # Resource Usage Auditing
    
    async def log_resource_usage(
        self,
        tool_name: str,
        target_id: Optional[int] = None,
        process_id: Optional[int] = None,
        cpu_percent: Optional[float] = None,
        memory_mb: Optional[float] = None,
        disk_read_bytes: Optional[int] = None,
        disk_write_bytes: Optional[int] = None,
        network_bytes_sent: Optional[int] = None,
        network_bytes_received: Optional[int] = None,
        duration_seconds: Optional[float] = None,
    ) -> int:
        """
        Log resource usage for a tool execution.
        
        Args:
            tool_name: Name of the tool
            target_id: Optional target ID
            process_id: Optional process ID
            cpu_percent: CPU usage percentage
            memory_mb: Memory usage in MB
            disk_read_bytes: Bytes read from disk
            disk_write_bytes: Bytes written to disk
            network_bytes_sent: Bytes sent over network
            network_bytes_received: Bytes received over network
            duration_seconds: Execution duration
            
        Returns:
            ID of inserted record
        """
        if not self._enabled:
            return -1
        
        conn = await self._get_connection()
        
        cursor = await conn.execute(
            """
            INSERT INTO resource_audit 
            (tool_name, target_id, process_id, cpu_percent, memory_mb,
             disk_read_bytes, disk_write_bytes, network_bytes_sent, 
             network_bytes_received, duration_seconds)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (tool_name, target_id, process_id, cpu_percent, memory_mb,
             disk_read_bytes, disk_write_bytes, network_bytes_sent, 
             network_bytes_received, duration_seconds)
        )
        await conn.commit()
        return cursor.lastrowid or 0
    
    # File Access Auditing
    
    async def log_file_access(
        self,
        tool_name: str,
        file_path: str,
        access_type: str,
        target_id: Optional[int] = None,
        success: bool = True,
        details: Optional[Dict] = None,
    ) -> int:
        """
        Log file access.
        
        Args:
            tool_name: Name of the tool accessing the file
            file_path: Path to the file
            access_type: read, write, execute, delete
            target_id: Optional target ID
            success: Whether the access was successful
            details: Additional details
            
        Returns:
            ID of inserted record
        """
        if not self._enabled:
            return -1
        
        conn = await self._get_connection()
        details_json = json.dumps(details) if details else None
        
        cursor = await conn.execute(
            """
            INSERT INTO file_access_audit 
            (tool_name, target_id, file_path, access_type, success, details)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (tool_name, target_id, file_path, access_type, 1 if success else 0, details_json)
        )
        await conn.commit()
        return cursor.lastrowid or 0
    
    # Query Methods
    
    async def get_recent_network_activity(
        self,
        tool_name: Optional[str] = None,
        action: Optional[str] = None,
        limit: int = 100,
    ) -> List[Dict[str, Any]]:
        """Get recent network activity."""
        conn = await self._get_connection()
        
        query = "SELECT * FROM network_audit WHERE 1=1"
        params = []
        
        if tool_name:
            query += " AND tool_name = ?"
            params.append(tool_name)
        if action:
            query += " AND action = ?"
            params.append(action)
        
        query += " ORDER BY timestamp DESC LIMIT ?"
        params.append(limit)
        
        cursor = await conn.execute(query, params)
        rows = await cursor.fetchall()
        return [dict(row) for row in rows]
    
    async def get_security_events(
        self,
        threat_level: Optional[str] = None,
        event_type: Optional[str] = None,
        limit: int = 100,
    ) -> List[Dict[str, Any]]:
        """Get security events."""
        conn = await self._get_connection()
        
        query = "SELECT * FROM security_events WHERE 1=1"
        params = []
        
        if threat_level:
            query += " AND threat_level = ?"
            params.append(threat_level)
        if event_type:
            query += " AND event_type = ?"
            params.append(event_type)
        
        query += " ORDER BY timestamp DESC LIMIT ?"
        params.append(limit)
        
        cursor = await conn.execute(query, params)
        rows = await cursor.fetchall()
        return [dict(row) for row in rows]
    
    async def get_resource_usage_summary(
        self,
        tool_name: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """Get resource usage summary."""
        conn = await self._get_connection()
        
        if tool_name:
            cursor = await conn.execute(
                "SELECT * FROM resource_usage_summary WHERE tool_name = ?",
                (tool_name,)
            )
        else:
            cursor = await conn.execute("SELECT * FROM resource_usage_summary")
        
        rows = await cursor.fetchall()
        return [dict(row) for row in rows]
    
    async def get_network_activity_summary(self) -> List[Dict[str, Any]]:
        """Get network activity summary by tool."""
        conn = await self._get_connection()
        cursor = await conn.execute("SELECT * FROM network_activity_summary")
        rows = await cursor.fetchall()
        return [dict(row) for row in rows]
    
    async def get_critical_events(self, limit: int = 100) -> List[Dict[str, Any]]:
        """Get recent critical security events."""
        conn = await self._get_connection()
        cursor = await conn.execute(
            "SELECT * FROM recent_critical_events LIMIT ?",
            (limit,)
        )
        rows = await cursor.fetchall()
        return [dict(row) for row in rows]
    
    # Report Generation
    
    async def generate_audit_report(
        self,
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None,
    ) -> Dict[str, Any]:
        """
        Generate comprehensive audit report.
        
        Args:
            start_time: Start of report period
            end_time: End of report period
            
        Returns:
            Dictionary with audit statistics
        """
        conn = await self._get_connection()
        
        time_filter = ""
        params = []
        
        if start_time:
            time_filter += " AND timestamp >= ?"
            params.append(start_time.isoformat())
        if end_time:
            time_filter += " AND timestamp <= ?"
            params.append(end_time.isoformat())
        
        # Network activity stats
        cursor = await conn.execute(
            f"SELECT COUNT(*) as total, "
            f"SUM(CASE WHEN action='allowed' THEN 1 ELSE 0 END) as allowed, "
            f"SUM(CASE WHEN action='blocked' THEN 1 ELSE 0 END) as blocked "
            f"FROM network_audit WHERE 1=1 {time_filter}",
            params
        )
        row = await cursor.fetchone()
        network_stats = dict(row) if row else {}
        
        # Security events stats
        cursor = await conn.execute(
            f"SELECT COUNT(*) as total, "
            f"SUM(CASE WHEN threat_level='critical' THEN 1 ELSE 0 END) as critical, "
            f"SUM(CASE WHEN threat_level='high' THEN 1 ELSE 0 END) as high "
            f"FROM security_events WHERE 1=1 {time_filter}",
            params
        )
        row = await cursor.fetchone()
        security_stats = dict(row) if row else {}
        
        # Resource usage stats
        cursor = await conn.execute(
            f"SELECT COUNT(*) as total, "
            f"AVG(cpu_percent) as avg_cpu, "
            f"AVG(memory_mb) as avg_memory "
            f"FROM resource_audit WHERE 1=1 {time_filter}",
            params
        )
        row = await cursor.fetchone()
        resource_stats = dict(row) if row else {}
        
        return {
            "period": {
                "start": start_time.isoformat() if start_time else None,
                "end": end_time.isoformat() if end_time else None,
            },
            "network_activity": network_stats,
            "security_events": security_stats,
            "resource_usage": resource_stats,
        }


# Global audit logger instance
_audit_logger: Optional[AuditLogger] = None


async def get_audit_logger() -> AuditLogger:
    """Get or create the global audit logger instance."""
    global _audit_logger
    if _audit_logger is None:
        _audit_logger = AuditLogger()
    return _audit_logger
