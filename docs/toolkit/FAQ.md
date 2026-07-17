# CTF Toolkit — FAQ

---

## Setup

**Q: The setup.sh script fails with "Docker is not installed"**

Install Docker Engine and start it:

```bash
sudo apt-get update && sudo apt-get install -y docker.io
sudo systemctl start docker
sudo usermod -aG docker $USER
# Log out and back in, then re-run setup.sh
```

On WSL2, start Docker Desktop on Windows first, then try again.

---

**Q: setup.sh fails with "Insufficient disk space"**

The Docker images need about 4 GB. Check available space:

```bash
df -h .
```

Free up space and retry.

---

**Q: uv command not found**

Install uv:

```bash
curl -LsSf https://astral.sh/uv/install.sh | sh
source ~/.bashrc
```

---

**Q: ModuleNotFoundError when starting the server**

Reinstall dependencies:

```bash
uv sync
```

---

**Q: Database error: no such table**

Reinitialize the database:

```bash
uv run python -c "from src.ctf_core.db import init_database; import asyncio; asyncio.run(init_database())"
```

---

## MCP connection

**Q: My AI IDE shows the MCP server as disconnected**

Check these in order:

1. Is `uv` on your PATH? Run `uv --version` in a terminal.
2. Does the `cwd` in your MCP config point to the actual ctftoolkit directory?
3. Are the paths in `env` absolute (not relative)?
4. Try starting the server manually: `uv run python -m ctf_core.server` — does it start without errors?

---

**Q: The server starts but tools don't appear in my IDE**

Restart the IDE completely (not just the chat window). MCP tools are registered at startup.

---

**Q: health_check returns DEGRADED or UNHEALTHY**

Read the component status in the response. Common causes:

- `database: unhealthy` → run `uv run python -c "from src.ctf_core.db import init_database; import asyncio; asyncio.run(init_database())"`
- `docker: unhealthy` → start Docker Desktop or `sudo systemctl start docker`
- `workspace: warning` → the workspace directory will be created automatically on first use

---

## Tool execution

**Q: run_nmap returns empty results**

The nmap container may have timed out or the target was unreachable. Try:

```
run_nmap(target="scanme.nmap.org", flags="-sV -p 80,443 --max-retries 1")
```

---

**Q: run_feroxbuster returns "output file not found"**

The scan ran but produced no output. This usually means the target returned no valid HTTP responses. Check the target URL is reachable.

---

**Q: run_shodan returns "API key not configured"**

Add your Shodan API key to `.env`:

```bash
SHODAN_API_KEY=your-key-here
```

Get a free key at [account.shodan.io](https://account.shodan.io/).

---

**Q: Tool times out after 300 seconds**

Increase the timeout in `.env`:

```bash
CTFTOOLKIT_TIMEOUT=600
```

Or narrow the scan scope (fewer ports, specific targets).

---

**Q: sanitize_command raises ValueError for my tool**

The tool is not in the allowed binaries list. Only whitelisted tools can run. Check `src/ctf_core/utils/sanitize.py` for the `ALLOWED_BINARIES` set.

---

## Docker

**Q: Orphaned containers accumulating**

```bash
docker ps -a --filter "label=ctftoolkit-managed=true" -q | xargs docker rm -f
# Or clean all stopped containers:
docker container prune -f
```

---

**Q: Docker image build fails**

Make sure you have internet access and enough disk space, then rebuild:

```bash
docker build -t ctftoolkit/ctf-tools -f docker/ctf-tools/Dockerfile .
```

---

## Running tests

**Q: How do I run the test suite?**

```bash
# Unit and security tests
python -m pytest tests/unit/ tests/security/ -v

# Tier 1 hands-on tests (no internet needed)
python tests/hands_on/run_tier1.py

# Tier 2 tests (needs internet — scans scanme.nmap.org)
python tests/hands_on/run_tier2.py

# Tier 3 tests (needs DVWA and Juice Shop running locally)
python tests/hands_on/run_tier3.py
```

---

**Q: Tier 1 test T1-016 (MCP Server Import) fails**

This is a known issue with `mcp >= 1.9.0` and Pydantic 2.7.x. The fix is already applied (`structured_output=False` on all `@mcp.tool()` decorators). If you see this, make sure you have the latest code.

---

## General

**Q: How do I update the toolkit?**

```bash
git pull
uv sync
# Re-run setup if Docker images need rebuilding
./setup.sh --skip-docker   # skip Docker rebuild if images are fine
```

---

**Q: How do I uninstall?**

```bash
./setup.sh --uninstall
```

This removes `.venv`, `ctf_state.db`, `workspace/`, `logs/`, `backups/`, and `metrics/`. Source code and Docker images are preserved.
