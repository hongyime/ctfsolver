# CTF Toolkit

![Version](https://img.shields.io/badge/version-0.1.0-blue.svg)
![Python](https://img.shields.io/badge/python-3.12+-green.svg)
![License](https://img.shields.io/badge/license-MIT-orange.svg)
![Status](https://img.shields.io/badge/status-production%20ready-success.svg)

An AI-powered CTF and penetration testing assistant. Describe a challenge in plain English — the toolkit categorises it, selects a strategy, runs the right security tools inside isolated Docker containers, captures flags automatically, and returns a structured report — all from inside your AI IDE chat window.

---

## How it works

```
Your AI IDE chat
      │
      │  "scan 10.10.10.10 for open ports"
      ▼
  MCP Server (server.py)
      │
      ├── AutoPrompter  → categorises the challenge
      ├── Planner       → selects attack strategy
      ├── Executor      → runs each task
      │     └── DockerRunner → isolated container per tool
      │           ├── nmap    → XML → nmap_parser    → SQLite
      │           ├── sqlmap  → raw stdout
      │           ├── feroxbuster → JSONL → ferox_parser
      │           └── searchsploit → JSON → sploit_parser
      └── FlagPatternDetector → auto-captures flags from any output
      │
      ▼
  Structured 6-section response back to your chat
```

---

## What it does

- Runs nmap, sqlmap, feroxbuster, searchsploit, nikto, hydra, masscan, and more inside isolated Docker containers
- Full autonomous pipeline: describe a challenge → strategy selected → tools execute → findings returned
- Parses tool output and stores results in a local SQLite database
- Detects CTF flags automatically in any tool output
- Exposes everything as MCP tools so your AI IDE (Kiro, Claude Desktop, Cursor, etc.) can call them directly
- Security-first: command whitelist, capability dropping, network isolation, sudo detection

---

## Quick links

- [**Quick start (5 minutes)**](#quick-start-5-minutes) — the fastest path
- [**Setup for AI agents**](docs/SETUP_FOR_AGENTS.md) — copy-paste contract for a coding agent installing this on a fresh machine
- [Setup guide](docs/INSTALLATION.md) — full step-by-step for Windows / WSL2 / Linux / macOS
- [MCP configuration](docs/INSTALLATION.md#6-mcp-configuration--connecting-to-your-ai-ide) — how to connect to your AI IDE
- [Available MCP tools](docs/INSTALLATION.md#8-available-mcp-tools) — full tool list
- [FAQ](docs/FAQ.md) — common problems and fixes

---

## Quick start (5 minutes)

> **Heads-up for AI coding agents**: read [docs/SETUP_FOR_AGENTS.md](docs/SETUP_FOR_AGENTS.md) for a terse, copy-pasteable install contract. The section below is the human version.

### 0. Prerequisites

| Tool | Version | Install |
|---|---|---|
| Python | 3.12+ | https://www.python.org/downloads/ |
| Docker | 24+ (with daemon **running**) | https://www.docker.com/products/docker-desktop |
| uv | latest | `pip install uv` or `winget install astral-sh.uv` (Windows) |
| git | any | https://git-scm.com/ |

Verify all four:

```bash
python --version    # >= 3.12
docker info         # must succeed (daemon running)
uv --version        # any
git --version       # any
```

### 1. Get the code

```bash
git clone <your-fork-or-repo-url> ctftoolkit
cd ctftoolkit
```

### 2. Install Python dependencies

```bash
uv sync
```

This creates `.venv/`, downloads everything in `pyproject.toml`, and is the only Python install step you need.

### 3. (Optional) Pre-build Docker images

Skip this step if you want — the MCP server builds any missing image on first use (lazy auto-build). To build them upfront, use **either** Docker Compose (recommended, one command) **or** the build script:

```bash
# Recommended: build all 5 core images via compose
docker compose build

# Also build the heavy lazy-only SageMath image (~2.5 GB) when you need it:
docker compose --profile heavy build ctf-sage

# Or use the cross-platform build script:
uv run python scripts/build_images.py
```

This builds the 5 core images (`ctf-tools`, `ctf-pwn`, `ctf-forensics`, `ctf-re`, `ctf-crypto`). `ctf-re` includes Ghidra (~5 GB) and `ctf-sage` (~2.5 GB) is built only on demand. Total first build: ~60–90 min, ~15 GB disk. Subsequent runs use the Docker layer cache.

Generate your MCP client config automatically (no hand-editing placeholders):

```bash
uv run python scripts/setup.py            # prints ready-to-paste MCP config
uv run python scripts/setup.py --write    # also writes mcp.local.json
uv run python scripts/setup.py --check-docker
```

Build-script flags:

```bash
uv run python scripts/build_images.py --check         # only verify which exist
uv run python scripts/build_images.py ctf-tools       # build a single image
uv run python scripts/build_images.py ctf-sage        # build the heavy Sage image
uv run python scripts/build_images.py --skip-existing # incremental
uv run python scripts/build_images.py --no-cache      # rebuild from scratch
```

**Storage & auto-prune.** Images live on your C: drive under Docker's data root. The
server can reclaim space safely: `disk_usage` reports per-image size, and `prune_images`
removes images that are BOTH idle (older than `CTFTOOLKIT_IMAGE_TTL_DAYS`, default 7) AND
unreferenced by any container or running job. Prune is a dry-run by default, never
force-removes, and never touches an image that is in use — so it can't disrupt a running
solve. Set `CTFTOOLKIT_PRUNE_ON_START=1` to prune idle images at startup.

### 4. Wire the MCP server into your AI IDE

The toolkit speaks MCP (Model Context Protocol). Add this entry to whichever client you use. **Replace `<ABS_PATH>` with the absolute path to your `ctftoolkit` checkout** (use double-backslashes on Windows JSON, e.g. `C:\\Users\\you\\ctftoolkit`).

```json
{
  "mcpServers": {
    "ctf-toolkit": {
      "command": "uv",
      "args": [
        "--directory", "<ABS_PATH>",
        "run", "python", "-m", "ctf_core.server"
      ],
      "env": {
        "CTFTOOLKIT_WORKSPACE": "<ABS_PATH>/workspace",
        "CTFTOOLKIT_DB_PATH": "<ABS_PATH>/ctf_state.db"
      }
    }
  }
}
```

> **Why `uv --directory <PATH>` and not `cwd: <PATH>`?** Several MCP clients (notably Claude Code CLI) silently strip the `cwd` field from MCP configs. Putting the path inside the `args` array works in **every** client (Claude Code, Claude Desktop, Cursor, opencode, Kiro, Windsurf).

**Per-client config file paths:**

| Client | File | Notes |
|---|---|---|
| Claude Desktop | `%APPDATA%\Claude\claude_desktop_config.json` (Win) / `~/Library/Application Support/Claude/claude_desktop_config.json` (Mac) | Restart Claude Desktop after edit |
| Cursor | `~/.cursor/mcp.json` | Restart Cursor after edit |
| Claude Code CLI | Use `claude mcp add-json -s user ctf-toolkit '<json>'` instead of editing files | Hot-reload, no restart |
| opencode | `~/.config/opencode/opencode.json` (under `mcp` key) | Hot-reload |
| Kiro / Windsurf | `<workspace>/.kiro/mcp.json` or `~/.codeium/windsurf/mcp_config.json` | Same JSON shape |

### 5. Verify the install

In your AI IDE chat:

```
health_check
```

Expected response:

```
Overall Status: HEALTHY
Components:
  [HEALTHY] database: Database connection active
  [HEALTHY] docker:   Docker runner initialized
  [HEALTHY] workspace: <ABS_PATH>/workspace
```

Then try a real run:

```
scan scanme.nmap.org with nmap
```

You should see real port results in 5–10 seconds. (Scanme is a target Nmap publishes for testing — safe and legal.)

### Troubleshooting

| Symptom | Fix |
|---|---|
| `MCP server failed to connect` | Check absolute path is correct; check `uv --version` works in your shell; check Docker Desktop is running |
| `image_not_found` error from a tool | Run `uv run python scripts/build_images.py` — or it'll auto-build on next call if `CTFTOOLKIT_AUTO_BUILD` is unset/`1` |
| `Docker daemon not reachable` | Start Docker Desktop / `dockerd` |
| Tool runs but no output | Check `latest_logs/` directory for full logs |
| Path with spaces broke something | JSON quoting handles spaces fine — confirm you used double backslashes (`\\`) on Windows JSON |

### Where things live after setup

```
ctftoolkit/
├── workspace/         # files mounted into containers (downloads, scan output, etc.)
├── ctf_state.db       # SQLite — targets, services, audit log
├── latest_logs/       # most recent run logs
├── logs/              # historical run logs
└── docker/<tool>/     # Dockerfile per image (ctf-tools, ctf-pwn, ...)
```

---

## Project structure

```
ctftoolkit/
├── src/ctf_core/
│   ├── server.py              # MCP server — all tools live here
│   ├── docker_runner.py       # Runs tools in Docker containers
│   ├── db.py                  # SQLite state management
│   ├── agents/
│   │   ├── auto_prompter.py   # Categorises challenge descriptions
│   │   ├── planner.py         # Selects attack strategy
│   │   └── executor.py        # Runs tasks from the plan
│   ├── parsers/               # Output parsers (nmap, ferox, sploit, etc.)
│   └── utils/                 # Sanitization, flag detection, security guards
├── schema/                    # SQLite schema files
├── skills/                    # Markdown skill guides per tool
├── docker/                    # Dockerfiles for each tool image
├── tests/                     # Full test suite (unit, integration, hands-on tiers 1-4)
├── docs/                      # Documentation
├── setup.sh                   # One-command setup for Linux/WSL2
├── mcp.json                   # MCP config template (Linux/WSL2)
├── mcp-windows.json           # MCP config template (Windows native)
└── .env.example               # Environment variable template
```

---

## Testing

The toolkit ships with a four-tier test suite. Most tests run offline.

| Tier | What it tests | Requirements | Run |
|------|--------------|--------------|-----|
| **Unit / Security** | All pure-Python logic — parsers, agents, sanitization, flag detection, DB, state-integrity, security guards | None | `pytest tests/unit/ tests/security/` |
| **Integration** (44 tests) | Full pipeline with mocked Docker | None | `pytest tests/integration/` |
| **Tier 1** (18 tests) | Real Docker images, DB CRUD, security guards, MCP health | Docker running | `python tests/hands_on/run_tier1.py` |
| **Tier 2** | Live nmap/sqlmap against public test sites | Internet + Docker | `python tests/hands_on/run_tier2.py` |
| **Tier 3** | DVWA + Juice Shop via Docker | Internet + Docker | `python tests/hands_on/run_tier3.py --setup` |
| **Tier 4** | Real CTF platforms (picoCTF, HTB, THM) | Human + Internet | `python tests/hands_on/run_tier4.py` |

**Tiers 2–4 require external infrastructure** (live targets, internet access, or running vulnerable Docker apps). They cannot run in an offline or CI environment.

Quick full offline check:
```
pytest tests/unit/ tests/security/ tests/integration/ -q
# → 308 passed, 2 skipped
```

> The offline suite (unit + security + integration) runs in CI on every push
> (`.github/workflows/ci.yml`). New since the 2026-05-31 remediation: async scan
> handles (`start_scan`/`poll_scan`/`get_scan_result`), `record_finding`, `format="json"`
> on scan tools, and local-artifact tools (`run_binary_analysis`, `run_gdb_script`,
> `run_pwntools`, `decode_stego`, `run_z3`). Container execution is now non-root with
> resource limits and per-tool network isolation. See `STATUS.md` for the full changelog.

Tier 1 (needs Docker running):
```
python tests/hands_on/run_tier1.py
# → 18/18 passed
```

---

## Legal notice

This tool is for authorised security testing and CTF competitions only. Only use it against systems you own or have explicit written permission to test.
