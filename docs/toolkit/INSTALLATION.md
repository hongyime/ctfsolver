# CTF Toolkit — Installation & Setup Guide

This guide walks you through setting up the CTF Toolkit from scratch on any machine. Follow the section for your operating system.

> **AI coding agent doing this install?** Read [SETUP_FOR_AGENTS.md](SETUP_FOR_AGENTS.md) instead — it's the same content compressed into a copy-pasteable contract with explicit verification gates.

---

## Express path (any OS, ~5 commands)

Skip to your OS section below if you want the full hand-holding. Otherwise:

```bash
# 1. Prereqs (install separately): Python 3.12+, Docker (running), uv, git
# 2. Clone + install
git clone <repo-url> ctftoolkit && cd ctftoolkit
uv sync

# 3. (Optional) pre-build Docker images. Skip and let lazy auto-build do it on first MCP call.
uv run python scripts/build_images.py

# 4. Wire MCP into your IDE (see section 6 for per-IDE snippet). Pattern is always:
#    "command": "uv",
#    "args": ["--directory", "<ABS_PATH>", "run", "python", "-m", "ctf_core.server"]

# 5. In your IDE chat, ask: `health_check` — should report HEALTHY.
```

Continue to the OS-specific section below if any of those steps need more detail.

---

## Table of contents

1. [What you need before you start](#1-what-you-need-before-you-start)
2. [Windows native setup (Docker Desktop)](#2-windows-native-setup-docker-desktop)
3. [Windows + WSL2 setup (alternative)](#3-windows--wsl2-setup-alternative)
4. [Linux setup](#4-linux-setup)
5. [macOS setup](#5-macos-setup)
6. [MCP configuration — connecting to your AI IDE](#6-mcp-configuration--connecting-to-your-ai-ide)
7. [Verifying the installation](#7-verifying-the-installation)
8. [Available MCP tools](#8-available-mcp-tools)
9. [Failure playbook](#9-failure-playbook)

---

## 1. What you need before you start

### Hardware minimums

| Resource | Minimum | Recommended |
|----------|---------|-------------|
| RAM | 4 GB | 8 GB |
| Disk | 15 GB free | 30 GB free |
| CPU | 2 cores | 4 cores |

### Software requirements

| Software | Version | Why |
|----------|---------|-----|
| Python | 3.12+ | Runs the MCP server |
| Docker | 24.0+ | Runs security tools in containers |
| Git | Any | Clones the repository |
| uv | Latest | Python package manager used by this project |

Check what you have:

```bash
python3 --version   # need 3.12+
docker --version    # need 24.0+
git --version       # any version
uv --version        # install if missing (see below)
```

### Install uv (required)

uv is a fast Python package manager. Install it once:

```bash
# Linux / macOS / WSL2
curl -LsSf https://astral.sh/uv/install.sh | sh
source ~/.bashrc    # or restart your terminal

# Verify
uv --version
```

---

## 2. Windows native setup (Docker Desktop)

This runs the toolkit directly on Windows — no WSL2 required. The Python server runs natively on Windows; the security tools (nmap, sqlmap, etc.) run inside Linux Docker containers managed by Docker Desktop.

### Step 1 — Install Python 3.12

Download from [python.org/downloads](https://www.python.org/downloads/).

During installation:
- Check **"Add Python to PATH"** — this is required
- Check **"Install for all users"** (optional but recommended)

Verify:

```cmd
python --version
```

Should show `Python 3.12.x`.

### Step 2 — Install Docker Desktop

Download from [docker.com/products/docker-desktop](https://www.docker.com/products/docker-desktop/).

During installation:
- Leave "Use WSL 2 based engine" checked if offered — it makes containers faster, but the toolkit works either way
- Start Docker Desktop after installation and wait for it to fully load (the whale icon in the system tray should stop animating)

Verify:

```cmd
docker --version
docker ps
```

Both should work without errors.

### Step 3 — Install Git

Download from [git-scm.com](https://git-scm.com/). Use all default options.

### Step 4 — Clone the repository

Open Command Prompt or PowerShell:

```cmd
cd C:\Users\%USERNAME%
git clone <YOUR_REPOSITORY_URL> ctftoolkit
cd ctftoolkit
```

### Step 5 — Run setup

Double-click `setup.bat` in the ctftoolkit folder, or run it from the command line:

```cmd
setup.bat
```

This will:
- Check Python and Docker are working
- Install uv (Python package manager)
- Create `workspace\`, `logs\`, `metrics\`, `backups\` directories
- Install all Python dependencies
- Initialize the SQLite database
- Build the 5 Docker tool images (takes 5–15 minutes)
- Print the MCP config for your machine

When it finishes, it prints a JSON block — copy it, you need it in Step 6.

### Step 6 — Configure environment

Copy `.env.example` to `.env`:

```cmd
copy .env.example .env
notepad .env
```

Set the paths to your actual install location:

```bash
CTFTOOLKIT_WORKSPACE=C:\Users\YourUsername\ctftoolkit\workspace
CTFTOOLKIT_DB_PATH=C:\Users\YourUsername\ctftoolkit\ctf_state.db
CTFTOOLKIT_TIMEOUT=300
CTFTOOLKIT_LOG_LEVEL=INFO
CTFTOOLKIT_MAX_CONTAINERS=5
```

Replace `YourUsername` with your actual Windows username.

### Step 7 — Connect to your AI IDE

See [Section 6 — MCP configuration](#6-mcp-configuration--connecting-to-your-ai-ide).

Use the JSON that `setup.bat` printed. It already has the correct paths for your machine.

---

## 3. Windows + WSL2 setup (alternative)

WSL2 gives you a full Linux environment inside Windows. Use this if you prefer a Linux workflow or if you run into issues with the native Windows setup.

### When to use WSL2 instead of native Windows

- You already use WSL2 for other development work
- You want to run `setup.sh` (the Linux setup script) instead of `setup.bat`
- You prefer bash over PowerShell

### Step 1 — Install WSL2

Open PowerShell as Administrator:

```powershell
wsl --install -d Ubuntu
```

Restart when prompted, then open the Ubuntu app and create a username and password.

### Step 2 — Configure WSL2 memory

On your **Windows host** (not inside WSL), create `C:\Users\<YOUR_USERNAME>\.wslconfig`:

```ini
[wsl2]
memory=8GB
processors=4
localhostForwarding=true
```

Restart WSL:

```powershell
wsl --shutdown
```

### Step 3 — Install Docker Desktop with WSL2 integration

Download [Docker Desktop](https://www.docker.com/products/docker-desktop/). After installing, go to **Settings → Resources → WSL Integration** and enable it for your Ubuntu distro.

### Step 4 — Follow the Linux setup

Inside your WSL2 Ubuntu terminal, follow [Section 4 — Linux setup](#4-linux-setup).

---

## 4. Linux setup

### Step 1 — Install prerequisites

**Ubuntu / Debian:**

```bash
sudo apt update
sudo apt install -y python3.12 python3.12-venv git sqlite3 curl

# Install Docker
sudo apt install -y docker.io
sudo systemctl start docker
sudo systemctl enable docker
sudo usermod -aG docker $USER
# Log out and back in for the group change to take effect
```

**Fedora / RHEL:**

```bash
sudo dnf install -y python3.12 git sqlite curl
sudo dnf install -y docker
sudo systemctl start docker
sudo usermod -aG docker $USER
```

**Arch Linux:**

```bash
sudo pacman -S python git sqlite curl docker
sudo systemctl start docker
sudo usermod -aG docker $USER
```

### Step 2 — Install uv

```bash
curl -LsSf https://astral.sh/uv/install.sh | sh
source ~/.bashrc
```

### Step 3 — Clone and run setup

```bash
git clone <YOUR_REPOSITORY_URL> ctftoolkit
cd ctftoolkit
chmod +x setup.sh
./setup.sh
```

### Step 4 — Configure environment

```bash
cp .env.example .env
nano .env
# Set CTFTOOLKIT_WORKSPACE and CTFTOOLKIT_DB_PATH to absolute paths
```

---

## 5. macOS setup

### Step 1 — Install prerequisites

```bash
# Install Homebrew if you don't have it
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"

# Install dependencies
brew install python@3.12 git sqlite

# Install Docker Desktop from https://www.docker.com/products/docker-desktop/
# Then start Docker Desktop from Applications
```

### Step 2 — Install uv

```bash
curl -LsSf https://astral.sh/uv/install.sh | sh
source ~/.zshrc   # or ~/.bashrc
```

### Step 3 — Clone and run setup

```bash
git clone <YOUR_REPOSITORY_URL> ctftoolkit
cd ctftoolkit
chmod +x setup.sh
./setup.sh
```

### Step 4 — Configure environment

```bash
cp .env.example .env
nano .env
# Set CTFTOOLKIT_WORKSPACE and CTFTOOLKIT_DB_PATH to absolute paths
```

---

## 6. MCP configuration — connecting to your AI IDE

### What is MCP?

MCP (Model Context Protocol) is how AI IDEs like Kiro, Claude Desktop, and Cursor talk to external tools. The CTF Toolkit runs as an MCP server — your AI IDE connects to it and can call any of the security tools directly from the chat window.

### How it works

```
Your AI IDE
    │
    │  reads mcp.json / settings
    │
    ▼
Starts the MCP server process:
    uv run python -m ctf_core.server
    │
    │  communicates over stdio (stdin/stdout)
    │  using JSON-RPC (the MCP protocol)
    ▼
Your AI IDE can now call:
    run_nmap(), run_sqlmap(), analyze_challenge(), etc.
```

The server runs as a background process. Your IDE starts it automatically when you open a chat. It communicates over standard input/output — no ports, no network, no browser needed.

### Step 1 — Get your correct MCP config

After running `setup.sh`, it prints the correct config for your machine. If you missed it, generate it manually:

```bash
# From inside the ctftoolkit directory
echo "{
  \"mcpServers\": {
    \"ctf-toolkit\": {
      \"command\": \"uv\",
      \"args\": [\"run\", \"python\", \"-m\", \"ctf_core.server\"],
      \"cwd\": \"$(pwd)\",
      \"env\": {
        \"CTFTOOLKIT_WORKSPACE\": \"$(pwd)/workspace\",
        \"CTFTOOLKIT_DB_PATH\": \"$(pwd)/ctf_state.db\"
      }
    }
  }
}"
```

### Step 2 — Add to your AI IDE

#### Kiro

1. Open Kiro
2. Press `Ctrl+Shift+P` (or `Cmd+Shift+P` on Mac) → search "Open MCP Settings"
3. Paste the JSON into the MCP settings file
4. Save and restart Kiro

#### Claude Desktop

1. Open Claude Desktop
2. Go to **Settings → Developer → Edit Config**
3. The config file is at:
   - Windows: `%APPDATA%\Claude\claude_desktop_config.json`
   - macOS: `~/Library/Application Support/Claude/claude_desktop_config.json`
   - Linux: `~/.config/Claude/claude_desktop_config.json`
4. Paste the `mcpServers` block into the config
5. Restart Claude Desktop

#### Cursor

1. Open Cursor
2. Go to **Settings → Features → MCP**
3. Click "Add new MCP server"
4. Paste the config
5. Restart Cursor

### Step 3 — Verify the connection

After restarting your IDE, open a new chat and type:

```
health_check
```

You should see a response like:

```
CTF Toolkit Health Check:

Overall Status: HEALTHY
Timestamp: 2026-04-07T...

Components:
  [HEALTHY] database: Database connection active
  [HEALTHY] docker: Docker runner initialized
  [HEALTHY] workspace: /path/to/workspace
```

If you see this, the toolkit is connected and ready.

### MCP config reference

Here is the full config with all options explained:

```json
{
  "mcpServers": {
    "ctf-toolkit": {
      "command": "uv",
      "args": [
        "--directory", "/absolute/path/to/ctftoolkit",
        "run", "python", "-m", "ctf_core.server"
      ],
      "env": {
        "CTFTOOLKIT_WORKSPACE": "/absolute/path/to/ctftoolkit/workspace",
        "CTFTOOLKIT_DB_PATH": "/absolute/path/to/ctftoolkit/ctf_state.db",
        "CTFTOOLKIT_TIMEOUT": "300",
        "CTFTOOLKIT_MAX_CONTAINERS": "5",
        "SHODAN_API_KEY": "your-key-here"
      }
    }
  }
}
```

**Important rules for paths:**
- Always use absolute paths (starting with `/` on Linux/Mac or `C:\` on Windows)
- On Windows, use double backslashes in JSON: `C:\\Users\\bryan\\ctftoolkit`
- The path passed to `uv --directory` must point to the root of the ctftoolkit directory (where `pyproject.toml` lives)

> **Why `uv --directory` instead of `cwd`?** Several MCP clients (notably **Claude Code CLI**) silently strip the `cwd` field from MCP configs, which causes `uv run` to fail because it cannot find the project. Using `uv --directory <PATH>` puts the project root in the command itself, so it works in **every** MCP client (Claude Code, Claude Desktop, Cursor, opencode, Kiro, Windsurf, etc.).

### Windows native config

If you ran `setup.bat`, it printed the correct JSON at the end. Use that directly. It looks like this:

```json
{
  "mcpServers": {
    "ctf-toolkit": {
      "command": "uv",
      "args": [
        "--directory", "C:\\Users\\YourUsername\\ctftoolkit",
        "run", "python", "-m", "ctf_core.server"
      ],
      "env": {
        "CTFTOOLKIT_WORKSPACE": "C:\\Users\\YourUsername\\ctftoolkit\\workspace",
        "CTFTOOLKIT_DB_PATH": "C:\\Users\\YourUsername\\ctftoolkit\\ctf_state.db"
      }
    }
  }
}
```

**Windows path rules:**
- Use double backslashes `\\` in JSON (JSON requires escaping backslashes)
- Always use absolute paths starting with `C:\\` (or your drive letter)
- Replace `YourUsername` with your actual Windows username
- Paths containing spaces (e.g. `C:\\Users\\You\\Projects\\ctfsolver`) work fine — JSON quoting handles them.

To find your exact path, open Command Prompt in the ctftoolkit folder and run `cd` — it prints the full path.

### Claude Code CLI shortcut

Claude Code users can install at user scope (available in every project) with one command:

```cmd
claude mcp add-json -s user ctf-toolkit "{\"command\":\"uv\",\"args\":[\"--directory\",\"C:\\\\Users\\\\YourUsername\\\\ctftoolkit\",\"run\",\"python\",\"-m\",\"ctf_core.server\"],\"env\":{\"CTFTOOLKIT_WORKSPACE\":\"C:\\\\Users\\\\YourUsername\\\\ctftoolkit\\\\workspace\",\"CTFTOOLKIT_DB_PATH\":\"C:\\\\Users\\\\YourUsername\\\\ctftoolkit\\\\ctf_state.db\"}}"
```

Verify with `claude mcp list` — you should see `ctf-toolkit: ... ✓ Connected`.

---

## 7. Verifying the installation

### Test 1 — Server starts manually

**Windows:**

```cmd
cd C:\Users\YourUsername\ctftoolkit
uv run python -m ctf_core.server
```

**Linux / macOS / WSL2:**

```bash
cd /path/to/ctftoolkit
uv run python -m ctf_core.server
```

Expected: the server starts and waits silently on stdin. Press `Ctrl+C` to stop.

If you see `ModuleNotFoundError`:

```bash
uv sync   # reinstall dependencies
```

If you see `docker.errors.DockerException`:

```bash
# Linux
sudo systemctl start docker

# WSL2 — start Docker Desktop on Windows first
```

### Test 2 — Run the tier 1 test suite

```bash
python tests/hands_on/run_tier1.py
```

Expected: 18/18 tests pass. This validates Docker, database, sanitization, flag detection, security guards, and MCP server import.

### Test 3 — Run a real scan from your IDE

In your AI IDE chat:

```
run_nmap(target="scanme.nmap.org", flags="-sV -p 80,443")
```

You should get back a formatted scan result with open ports and service versions.

---

## 8. Available MCP tools

Once connected, your AI IDE can call these tools:

| Tool | What it does | Example |
|------|-------------|---------|
| `run_nmap` | Network port scan | `run_nmap(target="10.10.10.10", flags="-sV -sC")` |
| `run_feroxbuster` | Web directory brute-force | `run_feroxbuster(url="http://10.10.10.10")` |
| `run_sqlmap` | SQL injection testing | `run_sqlmap(url="http://10.10.10.10/login?id=1")` |
| `run_searchsploit` | Exploit database search | `run_searchsploit(query="Apache 2.4.49")` |
| `run_shodan` | Shodan IP/service lookup | `run_shodan(query="10.10.10.10")` — needs `SHODAN_API_KEY` |
| `run_spiderfoot` | OSINT scan | `run_spiderfoot(target="example.com")` |
| `run_harvester` | Email/subdomain enumeration | `run_harvester(domain="example.com")` |
| `analyze_challenge` | Categorise a CTF challenge | `analyze_challenge(user_input="web challenge with login page")` |
| `run_challenge_analysis` | Full autonomous pipeline | `run_challenge_analysis(challenge_description="HTB machine, web app on port 80")` |
| `query_targets` | List stored targets | `query_targets(limit=10)` |
| `query_services` | List discovered services | `query_services(target_ip="10.10.10.10")` |
| `get_recent_actions` | View audit log | `get_recent_actions(limit=20)` |
| `health_check` | System health status | `health_check()` |
| `check_environment` | Validate setup | `check_environment()` |

### The autonomous pipeline

`run_challenge_analysis` is the most powerful tool. Give it a challenge description and it runs the full pipeline:

1. **AutoPrompter** — categorises the challenge (web, pwn, forensics, crypto, recon)
2. **Planner** — selects the best attack strategy based on the category
3. **Executor** — runs each tool in the plan via Docker
4. Returns a structured 6-section response: Understanding, Action Taken, Reason, Findings, User Input Required, Next Steps

Example:

```
run_challenge_analysis(challenge_description="HackTheBox machine at 10.10.10.10, seems to be a web challenge, login page visible")
```

---

## 9. Failure playbook

### Docker image not found

```
Error: Docker image 'ctftoolkit/ctf-tools' not found
```

This usually means you have not built the toolkit images yet. There are three ways to fix it:

**Option A — Auto-build on next call (default since v1.27).** The MCP server now lazy-builds any missing image on first use. Just call any tool again and watch the logs — the build runs once, then the tool proceeds. Disable this with `CTFTOOLKIT_AUTO_BUILD=0` if you prefer fail-fast behaviour.

**Option B — Build all images proactively.** Recommended for fresh installs:

```bash
uv run python scripts/build_images.py
```

This single command works on Windows, Linux, macOS, and WSL2. Useful flags:

```bash
uv run python scripts/build_images.py --check         # which images exist?
uv run python scripts/build_images.py ctf-tools       # build just one
uv run python scripts/build_images.py --skip-existing # incremental
uv run python scripts/build_images.py --no-cache      # force fresh rebuild
```

**Option C — From your AI IDE.** Just ask the agent to run the new MCP tool:

```
build_images
```

It calls `DockerRunner.ensure_all_images()` and reports per-image status.

**Manual fallback (if the script is missing):**

```bash
docker build -t ctftoolkit/ctf-tools     -f docker/ctf-tools/Dockerfile     .
docker build -t ctftoolkit/ctf-pwn       -f docker/ctf-pwn/Dockerfile       .
docker build -t ctftoolkit/ctf-forensics -f docker/ctf-forensics/Dockerfile .
docker build -t ctftoolkit/ctf-re        -f docker/ctf-re/Dockerfile        .
docker build -t ctftoolkit/ctf-crypto    -f docker/ctf-crypto/Dockerfile    .
```

### Database error: no such table

```bash
# Reinitialize the database
uv run python -c "from src.ctf_core.db import init_database; import asyncio; asyncio.run(init_database())"
```

### MCP server not connecting

1. Check the `cwd` in your MCP config points to the actual ctftoolkit directory
2. Check the paths in `env` are absolute and correct
3. Make sure `uv` is on your PATH: `uv --version`
4. Try starting the server manually: `uv run python -m ctf_core.server`

### Tool times out

The default timeout is 300 seconds. For slow scans, increase it:

```bash
# In .env
CTFTOOLKIT_TIMEOUT=600
```

Or pass a longer timeout in the tool call:

```
run_nmap(target="10.10.10.10", flags="-sV --max-retries 1")
```

### Orphaned Docker containers

If you see many stopped containers:

```bash
docker ps -a --filter "label=ctftoolkit-managed=true" -q | xargs docker rm -f
# Or clean all stopped containers:
docker container prune -f
```

### Shodan not working

Make sure your API key is set:

```bash
# In .env
SHODAN_API_KEY=your-actual-key-here
```

Get a free key at [account.shodan.io](https://account.shodan.io/).

---

## Uninstall

```bash
./setup.sh --uninstall
```

This removes `.venv`, `ctf_state.db`, `workspace/`, `logs/`, `backups/`, and `metrics/`. Source code and Docker images are preserved.
