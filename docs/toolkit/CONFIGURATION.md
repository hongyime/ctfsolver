# CTF Toolkit — Configuration Reference

---

## Environment variables

Copy `.env.example` to `.env` and edit it:

```bash
cp .env.example .env
```

| Variable | Default | Description |
|----------|---------|-------------|
| `CTFTOOLKIT_WORKSPACE` | `workspace` | Absolute path to the workspace directory where tool outputs are stored |
| `CTFTOOLKIT_DB_PATH` | `ctf_state.db` | Absolute path to the SQLite database file |
| `CTFTOOLKIT_TIMEOUT` | `300` | Per-tool execution timeout in seconds |
| `CTFTOOLKIT_LOG_LEVEL` | `INFO` | Log level: `DEBUG`, `INFO`, `WARNING`, `ERROR` |
| `CTFTOOLKIT_MAX_CONTAINERS` | `5` | Maximum concurrent Docker containers |
| `SHODAN_API_KEY` | _(empty)_ | Shodan API key for `run_shodan` — get one free at [account.shodan.io](https://account.shodan.io/) |

### Example .env for WSL2

```bash
CTFTOOLKIT_WORKSPACE=/home/bryan/ctftoolkit/workspace
CTFTOOLKIT_DB_PATH=/home/bryan/ctftoolkit/ctf_state.db
CTFTOOLKIT_TIMEOUT=300
CTFTOOLKIT_LOG_LEVEL=INFO
CTFTOOLKIT_MAX_CONTAINERS=5
SHODAN_API_KEY=
```

### Example .env for Windows native

```bash
CTFTOOLKIT_WORKSPACE=C:\Users\bryan\ctftoolkit\workspace
CTFTOOLKIT_DB_PATH=C:\Users\bryan\ctftoolkit\ctf_state.db
CTFTOOLKIT_TIMEOUT=300
CTFTOOLKIT_LOG_LEVEL=INFO
CTFTOOLKIT_MAX_CONTAINERS=5
```

---

## MCP configuration

The MCP config tells your AI IDE how to start the server. See [INSTALLATION.md — MCP configuration](./INSTALLATION.md#5-mcp-configuration--connecting-to-your-ai-ide) for the full guide.

Quick reference:

```json
{
  "mcpServers": {
    "ctf-toolkit": {
      "command": "uv",
      "args": ["run", "python", "-m", "ctf_core.server"],
      "cwd": "/absolute/path/to/ctftoolkit",
      "env": {
        "CTFTOOLKIT_WORKSPACE": "/absolute/path/to/ctftoolkit/workspace",
        "CTFTOOLKIT_DB_PATH": "/absolute/path/to/ctftoolkit/ctf_state.db"
      }
    }
  }
}
```

---

## Docker images

The toolkit uses 5 custom Docker images:

| Image | Tools included |
|-------|---------------|
| `ctftoolkit/ctf-tools` | nmap, masscan, sqlmap, nikto, ffuf, gobuster, searchsploit, hydra |
| `ctftoolkit/ctf-pwn` | pwntools, gdb, radare2, checksec |
| `ctftoolkit/ctf-forensics` | volatility, exiftool, tshark, binwalk |
| `ctftoolkit/ctf-re` | binwalk, strings, objdump |
| `ctftoolkit/ctf-crypto` | hashcat, john, openssl |

Rebuild all images:

```bash
docker build -t ctftoolkit/ctf-tools -f docker/ctf-tools/Dockerfile .
docker build -t ctftoolkit/ctf-pwn -f docker/ctf-pwn/Dockerfile .
docker build -t ctftoolkit/ctf-forensics -f docker/ctf-forensics/Dockerfile .
docker build -t ctftoolkit/ctf-re -f docker/ctf-re/Dockerfile .
docker build -t ctftoolkit/ctf-crypto -f docker/ctf-crypto/Dockerfile .
```

---

## Database

The toolkit uses SQLite with WAL mode. The schema has these tables:

| Table | Contents |
|-------|----------|
| `targets` | Discovered hosts |
| `services` | Open ports and services |
| `web_directories` | Discovered web paths |
| `credentials` | Found credentials |
| `exploits` | Matched exploits |
| `flags` | Auto-captured CTF flags |
| `action_log` | Audit trail of all tool runs |
| `decisions` | Planner strategy decisions |
| `network_audit` | Network activity log |
| `security_events` | Security event log |
| `resource_audit` | Resource usage log |
| `file_access_audit` | File access log |

Reinitialize the database (safe to run multiple times):

```bash
uv run python -c "from src.ctf_core.db import init_database; import asyncio; asyncio.run(init_database())"
```

---

## Security settings

### Container security

Every tool runs in a Docker container with:
- `cap_drop=["ALL"]` — all Linux capabilities dropped
- `security_opt=["no-new-privileges:true"]` — no privilege escalation
- `remove=True` — container auto-removed on exit
- nmap gets `cap_add=["NET_RAW"]` for raw socket access (only what it needs)

### Command whitelist

Only these binaries can be executed: nmap, masscan, sqlmap, nikto, ffuf, feroxbuster, gobuster, searchsploit, hydra, volatility, exiftool, hashcat, john, and a few others. Anything not on the list raises a `ValueError` before Docker is even invoked.

### Network isolation

The network guard blocks connections to private IP ranges by default. Public IPs (CTF targets) are allowed. You can adjust this in `src/ctf_core/utils/network_isolation.py`.

---

## Logging

Logs are written to `logs/ctf-toolkit.log` in JSON format:

```json
{
  "timestamp": "2026-04-07T09:43:56",
  "level": "INFO",
  "logger": "ctf_core.server",
  "message": "Docker connectivity: OK"
}
```

Monitor live:

```bash
tail -f logs/ctf-toolkit.log
```

---

## Backup

```bash
python scripts/backup.py backup
# Backups stored in backups/ directory, retained 7 days
```
