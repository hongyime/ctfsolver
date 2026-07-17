-- schema/audit_enhancements.sql
-- Enhanced audit logging for CTF Toolkit
-- Run this after init_db.sql to add additional audit tables

-- Network activity audit table
CREATE TABLE IF NOT EXISTS network_audit (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    tool_name TEXT NOT NULL,
    target_id INTEGER,
    source_ip TEXT NOT NULL,
    destination_ip TEXT NOT NULL,
    destination_port INTEGER,
    protocol TEXT DEFAULT 'tcp',
    action TEXT NOT NULL,  -- allowed, blocked, rate_limited
    zone TEXT,             -- internal, lab, controlled, unrestricted
    details TEXT,          -- JSON additional details
    FOREIGN KEY (target_id) REFERENCES targets(id) ON DELETE SET NULL
);

-- Security events table
CREATE TABLE IF NOT EXISTS security_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    event_type TEXT NOT NULL,  -- command_injection, network_escape, privilege_escalation, etc.
    threat_level TEXT NOT NULL, -- low, medium, high, critical
    tool_name TEXT,
    target_id INTEGER,
    description TEXT NOT NULL,
    details TEXT,              -- JSON additional details
    action_taken TEXT,         -- logged, blocked, terminated
    FOREIGN KEY (target_id) REFERENCES targets(id) ON DELETE SET NULL
);

-- Resource usage audit table
CREATE TABLE IF NOT EXISTS resource_audit (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    tool_name TEXT NOT NULL,
    target_id INTEGER,
    process_id INTEGER,
    cpu_percent REAL,
    memory_mb REAL,
    disk_read_bytes INTEGER,
    disk_write_bytes INTEGER,
    network_bytes_sent INTEGER,
    network_bytes_received INTEGER,
    duration_seconds REAL,
    FOREIGN KEY (target_id) REFERENCES targets(id) ON DELETE SET NULL
);

-- File access audit table
CREATE TABLE IF NOT EXISTS file_access_audit (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    tool_name TEXT NOT NULL,
    target_id INTEGER,
    file_path TEXT NOT NULL,
    access_type TEXT NOT NULL,  -- read, write, execute, delete
    success BOOLEAN DEFAULT 1,
    details TEXT,               -- JSON additional details
    FOREIGN KEY (target_id) REFERENCES targets(id) ON DELETE SET NULL
);

-- Performance indexes for audit tables
CREATE INDEX IF NOT EXISTS idx_network_audit_timestamp ON network_audit(timestamp);
CREATE INDEX IF NOT EXISTS idx_network_audit_tool ON network_audit(tool_name);
CREATE INDEX IF NOT EXISTS idx_network_audit_target ON network_audit(target_id);
CREATE INDEX IF NOT EXISTS idx_network_audit_action ON network_audit(action);

CREATE INDEX IF NOT EXISTS idx_security_events_timestamp ON security_events(timestamp);
CREATE INDEX IF NOT EXISTS idx_security_events_type ON security_events(event_type);
CREATE INDEX IF NOT EXISTS idx_security_events_threat ON security_events(threat_level);
CREATE INDEX IF NOT EXISTS idx_security_events_target ON security_events(target_id);

CREATE INDEX IF NOT EXISTS idx_resource_audit_timestamp ON resource_audit(timestamp);
CREATE INDEX IF NOT EXISTS idx_resource_audit_tool ON resource_audit(tool_name);
CREATE INDEX IF NOT EXISTS idx_resource_audit_target ON resource_audit(target_id);

CREATE INDEX IF NOT EXISTS idx_file_access_timestamp ON file_access_audit(timestamp);
CREATE INDEX IF NOT EXISTS idx_file_access_tool ON file_access_audit(tool_name);
CREATE INDEX IF NOT EXISTS idx_file_access_target ON file_access_audit(target_id);

-- View for recent security events by threat level
CREATE VIEW IF NOT EXISTS recent_critical_events AS
SELECT * FROM security_events 
WHERE threat_level = 'critical' 
ORDER BY timestamp DESC 
LIMIT 100;

-- View for network activity summary by tool
CREATE VIEW IF NOT EXISTS network_activity_summary AS
SELECT 
    tool_name,
    COUNT(*) as total_connections,
    SUM(CASE WHEN action = 'allowed' THEN 1 ELSE 0 END) as allowed_count,
    SUM(CASE WHEN action = 'blocked' THEN 1 ELSE 0 END) as blocked_count,
    SUM(CASE WHEN action = 'rate_limited' THEN 1 ELSE 0 END) as rate_limited_count,
    COUNT(DISTINCT destination_ip) as unique_destinations
FROM network_audit 
GROUP BY tool_name;

-- View for resource usage by tool
CREATE VIEW IF NOT EXISTS resource_usage_summary AS
SELECT 
    tool_name,
    COUNT(*) as execution_count,
    AVG(cpu_percent) as avg_cpu,
    MAX(cpu_percent) as max_cpu,
    AVG(memory_mb) as avg_memory,
    MAX(memory_mb) as max_memory,
    AVG(duration_seconds) as avg_duration,
    SUM(duration_seconds) as total_duration
FROM resource_audit 
GROUP BY tool_name;
