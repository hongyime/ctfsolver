# CTF Toolkit — Getting Started

This is the quick-start guide. For full setup instructions see [INSTALLATION.md](./INSTALLATION.md).

---

## Prerequisites

- Python 3.12+
- Docker 24.0+
- Git
- uv (install with `curl -LsSf https://astral.sh/uv/install.sh | sh`)

---

## 5-minute setup

```bash
# 1. Clone
git clone <YOUR_REPOSITORY_URL> ctftoolkit
cd ctftoolkit

# 2. Run setup (builds Docker images, initializes DB, installs deps)
chmod +x setup.sh
./setup.sh

# 3. Configure environment
cp .env.example .env
# Edit .env — set CTFTOOLKIT_WORKSPACE and CTFTOOLKIT_DB_PATH to absolute paths

# 4. Verify it works
uv run python -m ctf_core.server
# Should start silently. Press Ctrl+C to stop.
```

---

## Connect to your AI IDE

After setup, copy the MCP config that `setup.sh` printed and paste it into your AI IDE's MCP settings. Then restart the IDE.

Full instructions: [INSTALLATION.md — MCP configuration](./INSTALLATION.md#5-mcp-configuration--connecting-to-your-ai-ide)

---

## First commands to try

In your AI IDE chat:

```
health_check
```

```
check_environment
```

```
run_nmap(target="scanme.nmap.org", flags="-sV -p 80,443")
```

```
analyze_challenge(user_input="web challenge with a login page at http://10.10.10.10")
```

---

## What each tool does

See [INSTALLATION.md — Available MCP tools](./INSTALLATION.md#7-available-mcp-tools) for the full list.

---

## Something not working?

See [INSTALLATION.md — Failure playbook](./INSTALLATION.md#8-failure-playbook) or [FAQ.md](./FAQ.md).
