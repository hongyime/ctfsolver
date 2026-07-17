-- schema/init_db.sql
-- CTF Toolkit SQLite Database Schema
-- Enables WAL mode for concurrent access and crash recovery

PRAGMA journal_mode=WAL;

-- Targets table: stores information about CTF targets
CREATE TABLE IF NOT EXISTS targets (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ip_address TEXT UNIQUE NOT NULL,
    hostname TEXT,
    os_type TEXT,
    status TEXT DEFAULT 'active',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Services table: stores discovered services on targets
CREATE TABLE IF NOT EXISTS services (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    target_id INTEGER NOT NULL,
    port INTEGER NOT NULL,
    protocol TEXT DEFAULT 'tcp',
    service_name TEXT,
    banner TEXT,
    FOREIGN KEY (target_id) REFERENCES targets(id) ON DELETE CASCADE,
    UNIQUE(target_id, port, protocol)
);

-- Web directories table: stores discovered web paths
CREATE TABLE IF NOT EXISTS web_directories (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    target_id INTEGER NOT NULL,
    path TEXT NOT NULL,
    status_code INTEGER,
    FOREIGN KEY (target_id) REFERENCES targets(id) ON DELETE CASCADE,
    UNIQUE(target_id, path)
);

-- Credentials table: stores discovered credentials
CREATE TABLE IF NOT EXISTS credentials (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    target_id INTEGER NOT NULL,
    username TEXT NOT NULL,
    password_hash TEXT,
    cleartext TEXT,
    FOREIGN KEY (target_id) REFERENCES targets(id) ON DELETE CASCADE
);

-- Exploits table: stores available exploits for targets
CREATE TABLE IF NOT EXISTS exploits (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    target_id INTEGER NOT NULL,
    cve_id TEXT,
    exploit_path TEXT NOT NULL,
    FOREIGN KEY (target_id) REFERENCES targets(id) ON DELETE CASCADE
);

-- Flags table: stores captured flags
CREATE TABLE IF NOT EXISTS flags (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    target_id INTEGER,
    flag_value TEXT NOT NULL,
    source TEXT,
    pattern TEXT,
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (target_id) REFERENCES targets(id) ON DELETE CASCADE
);

-- Action log table: audit trail for all tool executions
CREATE TABLE IF NOT EXISTS action_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    target_id INTEGER,
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    tool_used TEXT NOT NULL,
    command_string TEXT NOT NULL,
    reason TEXT,
    FOREIGN KEY (target_id) REFERENCES targets(id) ON DELETE SET NULL
);

-- Performance indexes
CREATE INDEX IF NOT EXISTS idx_services_target ON services(target_id);
CREATE INDEX IF NOT EXISTS idx_web_dirs_target ON web_directories(target_id);

-- Decisions table: stores decision history for CTF strategy
CREATE TABLE IF NOT EXISTS decisions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    target_id INTEGER,
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    decision_path TEXT NOT NULL,
    confidence_scores TEXT,
    reasoning TEXT,
    selected_action TEXT,
    FOREIGN KEY (target_id) REFERENCES targets(id) ON DELETE SET NULL
);

-- Performance indexes for decisions table
CREATE INDEX IF NOT EXISTS idx_decisions_target ON decisions(target_id);
CREATE INDEX IF NOT EXISTS idx_decisions_timestamp ON decisions(timestamp);
CREATE INDEX IF NOT EXISTS idx_creds_target ON credentials(target_id);
CREATE INDEX IF NOT EXISTS idx_action_log_target ON action_log(target_id);
CREATE INDEX IF NOT EXISTS idx_action_log_timestamp ON action_log(timestamp);

-- Challenges table: CTF challenge tracking
CREATE TABLE IF NOT EXISTS challenges (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    challenge_id TEXT UNIQUE NOT NULL,
    slug TEXT UNIQUE,
    name TEXT NOT NULL,
    category TEXT,
    description TEXT,
    difficulty TEXT,
    status TEXT DEFAULT 'active',
    flag_captured TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    solved_at TIMESTAMP
);

-- Challenge files table: files ingested for a challenge
CREATE TABLE IF NOT EXISTS challenge_files (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    challenge_id TEXT NOT NULL REFERENCES challenges(challenge_id),
    file_path TEXT NOT NULL,
    file_name TEXT NOT NULL,
    file_type TEXT,
    file_size INTEGER,
    sha256_hash TEXT,
    mime_type TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(challenge_id, file_path)
);

-- Writeups table: scraped CTF writeup metadata
CREATE TABLE IF NOT EXISTS writeups (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    challenge_name TEXT NOT NULL,
    category TEXT,
    source_url TEXT UNIQUE NOT NULL,
    title TEXT,
    author TEXT,
    content_summary TEXT,
    full_content_path TEXT,
    relevance_score REAL,
    scraped_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Reasoning log table: step-by-step execution trace
CREATE TABLE IF NOT EXISTS reasoning_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    challenge_id TEXT,
    action_id INTEGER,
    step_number INTEGER NOT NULL,
    step_description TEXT NOT NULL,
    step_output TEXT,
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (challenge_id) REFERENCES challenges(challenge_id) ON DELETE SET NULL
);

-- Token usage table: tracks LLM token consumption per tool call
CREATE TABLE IF NOT EXISTS token_usage (
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

-- Web search cache table: avoids redundant searches during a session
CREATE TABLE IF NOT EXISTS web_search_cache (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    query TEXT NOT NULL,
    search_type TEXT,
    results TEXT,
    cached_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMP,
    UNIQUE(query, search_type)
);

-- Scan jobs table: async scan handles (F3); survive client/session death
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
