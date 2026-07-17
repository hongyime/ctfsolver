# Setup Contract for AI Coding Agents

This file is the **authoritative install procedure** for autonomous coding agents
(Claude Code, opencode, Cursor, Codex, etc.). It is intentionally terse, has
explicit verification gates, and assumes you can run shell commands.

If you are a human, prefer [INSTALLATION.md](INSTALLATION.md). The two
documents are kept in sync — this one just compresses the same flow into a
contract you can execute mechanically.

---

## What you are installing

**CTF Toolkit** = an MCP server (`ctf_core.server`) that exposes 15+ security
tools (nmap, sqlmap, hydra, hashcat, radare2, volatility, …) to your AI IDE.
Each tool runs inside an ephemeral Docker container built from one of 5
purpose-built images.

After install, the user's chat → MCP server → ephemeral container → results.

---

## Constraints you MUST respect

- **Never** run a security tool from this toolkit against a target the user has
  not explicitly authorised. Refuse if unclear.
- **Never** disable `cap_drop`, `no-new-privileges`, or `--rm` in
  `docker_runner.py`. They are load-bearing for safety.
- **Never** commit `.env` (real Shodan keys live there).
- **Never** modify `ctf_state.db` directly — go through the DB layer in `ctf_core/db.py`.
- **Always** use `uv --directory <ABS_PATH>` in MCP configs. The `cwd` field is
  silently dropped by Claude Code CLI; clients also differ on whether they
  inherit cwd. `--directory` is the only portable form.

---

## Prerequisites (verify each before continuing)

| Tool | Minimum | Verification |
|---|---|---|
| Python | 3.12 | `python --version` exits 0 with `>= 3.12.x` |
| Docker | 24 + daemon running | `docker info` exits 0 |
| uv | any | `uv --version` exits 0 |
| git | any | `git --version` exits 0 |
| Free disk | 12 GB | sum of image sizes ≈ 10.3 GB + buffer |

If any check fails, install the missing tool **before** proceeding. Do not
attempt workarounds.

---

## Install procedure

### Step 1 — Get the code

```bash
git clone <repo-url> ctftoolkit
cd ctftoolkit
```

`<repo-url>` comes from the user. If the user already has a clone, set
`cd <their-path>` instead and skip to step 2. Compute the absolute path now and
remember it as `<ABS_PATH>`:

```bash
# Linux / macOS / WSL2
ABS_PATH="$(pwd)"
echo "$ABS_PATH"

# Windows PowerShell
$ABS_PATH = (Get-Location).Path
$ABS_PATH
```

> **Path with spaces is fine** (e.g. `C:\Users\you\Projects\ctfsolver`).
> JSON quoting handles them. Do NOT try to remove the spaces.

### Step 2 — Install Python dependencies

```bash
uv sync
```

**Verification gate:** `uv run python -c "import ctf_core.server; print('OK')"`
must print `OK`. If it errors, stop and report — do not patch deps blindly.

### Step 3 — (Optional) pre-build Docker images

You can skip this — the MCP server has lazy auto-build (default since v1.27).
But pre-building gives the user instant first-call response.

```bash
uv run python scripts/build_images.py
```

This builds 5 images (`ctftoolkit/ctf-tools`, `-pwn`, `-forensics`, `-re`,
`-crypto`). Total time ~70 min on first run, ~10.3 GB disk. Subsequent runs
hit the layer cache and are seconds-fast.

If a build fails, retry that one image only:

```bash
uv run python scripts/build_images.py <short-name> --no-cache
```

**Verification gate:**

```bash
uv run python scripts/build_images.py --check
```

Must show all 5 images as `present` with green ✓. If pre-built skipped:
expect ✗ for all 5 — that is acceptable, lazy build will fix on first call.

### Step 4 — Wire MCP into the user's IDE(s)

Build the JSON entry once:

```json
{
  "command": "uv",
  "args": [
    "--directory", "<ABS_PATH>",
    "run", "python", "-m", "ctf_core.server"
  ],
  "env": {
    "CTFTOOLKIT_WORKSPACE": "<ABS_PATH>/workspace",
    "CTFTOOLKIT_DB_PATH":    "<ABS_PATH>/ctf_state.db"
  }
}
```

Substitute `<ABS_PATH>` with the value from step 1. **Use double-backslashes on
Windows JSON** (`C:\\Users\\you\\ctftoolkit`).

Then, for each IDE the user has, add the entry under `mcpServers` (or `mcp` for
opencode) at:

| Client | File path | Restart? |
|---|---|---|
| Claude Code CLI | run `claude mcp add-json -s user ctf-toolkit '<json>'` | hot-reload |
| Claude Desktop | Win: `%APPDATA%\Claude\claude_desktop_config.json` · macOS: `~/Library/Application Support/Claude/claude_desktop_config.json` | yes |
| Cursor | `~/.cursor/mcp.json` | yes |
| opencode | `~/.config/opencode/opencode.json` (`mcp` key, also requires `"type": "local"` and `"enabled": true` keys, and `command` is an **array** not string) | hot-reload |
| Kiro / Windsurf | per-workspace `<ws>/.kiro/mcp.json` or `~/.codeium/windsurf/mcp_config.json` | yes |

Ask the user which IDE(s) to wire. Default to the one they're talking to you
through.

> **opencode shape difference** — opencode expects a slightly different JSON
> shape than every other client. Convert `command + args` into a single
> `command` array, and use `environment` instead of `env`:
> ```json
> "ctf-toolkit": {
>   "type": "local",
>   "command": ["uv", "--directory", "<ABS_PATH>", "run", "python", "-m", "ctf_core.server"],
>   "enabled": true,
>   "environment": { "CTFTOOLKIT_WORKSPACE": "...", "CTFTOOLKIT_DB_PATH": "..." }
> }
> ```

### Step 5 — Verify end-to-end

After the IDE reloads, ask the user to send (or invoke directly):

```
health_check
```

Expected:

```
Overall Status: HEALTHY
Components:
  [HEALTHY] database
  [HEALTHY] docker
  [HEALTHY] workspace
```

If `docker` reports unhealthy: Docker Desktop is not running. Tell the user to
start it, do not proceed.

Then a real run against Nmap's public test target:

```
scan scanme.nmap.org with nmap
```

Expected: real port results in 5–10s. Open ports typically include 22 and 80.

**This last step is the success gate. Do not declare done before it returns
real port output.**

---

## Common failure modes

| Symptom | Cause | Fix |
|---|---|---|
| `MCP error -32000: Connection closed` | Wrong absolute path in `--directory` arg, or `uv` not on PATH for the MCP host | Re-check `<ABS_PATH>` is absolute, JSON-escaped, and that `uv --version` works from a fresh shell |
| `image_not_found` | Image not built | Run `uv run python scripts/build_images.py <name>` or trust lazy build |
| `Docker daemon not reachable` | Docker Desktop / dockerd off | Start it. There is no software workaround |
| Path contains a space and tool fails | Quoting issue in your handcrafted JSON | Use `--directory` (this guide), not `cwd`. Verify JSON validates |
| Tool runs but returns empty stdout | Container exited silently — check `latest_logs/<tool>.log` | Read the log; do not retry blindly |
| Long delays on first call only | Lazy auto-build is running | Wait, or pre-build with `scripts/build_images.py` |

---

## Where things live (post-install)

```
<ABS_PATH>/
├── .venv/                       # uv-managed virtualenv (auto-created)
├── workspace/                   # mounted into containers; tool output lands here
├── ctf_state.db                 # SQLite — targets, services, audit log, flags
├── latest_logs/                 # most recent run per tool
├── logs/                        # historical
├── docker/<tool>/Dockerfile     # 5 images, see scripts/build_images.py
├── src/ctf_core/
│   ├── server.py                # MCP entrypoint — every @mcp.tool() lives here
│   ├── docker_runner.py         # ephemeral container runner with lazy build
│   ├── db.py                    # SQLite layer
│   ├── agents/                  # auto_prompter, planner, executor (full pipeline)
│   ├── parsers/                 # nmap_parser, ferox_parser, sploit_parser, …
│   └── utils/                   # sanitize, sudo_guard, net_guard, command_whitelist
├── scripts/build_images.py      # cross-platform image builder (created by setup)
└── docs/                        # this directory
```

---

## Environment variables you may set

| Var | Default | Effect |
|---|---|---|
| `CTFTOOLKIT_WORKSPACE` | `<ABS_PATH>/workspace` | Mount point inside containers |
| `CTFTOOLKIT_DB_PATH` | `<ABS_PATH>/ctf_state.db` | SQLite file |
| `CTFTOOLKIT_TIMEOUT` | `300` | Per-tool seconds |
| `CTFTOOLKIT_MAX_CONTAINERS` | `5` | Concurrent run cap |
| `CTFTOOLKIT_LOG_LEVEL` | `INFO` | Standard Python levels |
| `CTFTOOLKIT_AUTO_BUILD` | `1` | `0` to disable lazy image builds (fail-fast on missing image) |
| `SHODAN_API_KEY` | unset | Enables `run_shodan` tool |

These can live in `<ABS_PATH>/.env` (auto-loaded since `uv --directory` rooted
us there) or in the MCP config's `env` block.

---

## Done check (run this last)

```bash
# 1. Module imports
uv run python -c "import ctf_core.server; print('module: OK')"

# 2. Images present (or lazy-build accepted)
uv run python scripts/build_images.py --check

# 3. MCP wiring (pick the relevant client)
claude mcp list 2>&1 | grep ctf-toolkit            # Claude Code
opencode mcp list 2>&1 | grep ctf-toolkit          # opencode
# Claude Desktop / Cursor: verify in their UI

# 4. End-to-end (last gate — must produce real nmap output):
#    in IDE chat, ask: "scan scanme.nmap.org with nmap"
```

If all four pass, install is complete. Report success to the user with the
absolute path and the IDEs that were wired.

---

## When you must stop and ask the user

- The repo URL was not provided.
- Docker is not installed (do not try to install it for them — too OS-specific).
- A build fails and the error message references missing system packages
  (host kernel / WSL config issue, not something you can patch).
- The user has a non-standard IDE not listed in step 4.
- Disk space is below 12 GB free.
- The `health_check` returns degraded after step 5 and you cannot identify why
  from the output.
