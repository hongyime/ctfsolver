# Developer README

![Dashboard](./image.png)

## 1. Project Overview
This repository contains a local Streamlit dashboard and testing harness designed to bridge the gap between Capture The Flag (CTF) platforms and autonomous Large Language Model agents. It automates the extraction of challenges from multiple CTF platforms, mounts them into isolated, tool-rich Docker containers, and manages the lifecycle of AI agents (Claude Code, Codex, Kiro, or OpenCode) attempting to solve them. Telemetry, active state tracking, and parsed execution logs are rendered in the frontend dashboard.

`ctfsolver` has three user-facing modes:
- **CTFd mode**: browser dashboard for CTFd challenge import and agent runs.
- **rCTF mode**: browser dashboard for rCTF platform (used by many open-source CTFs).
- **Manual mode**: no platform API; paste in your own challenge metadata.
- **Non-CTFd mode**: stdio MCP backend server for direct tool use by Claude/Codex-compatible MCP clients.

**Orchestrator vs workspace:** The repo itself (`C:\ctfsolver` or wherever it is cloned) is the *orchestrator home* only — source code, Dockerfiles, and agent tooling. All runtime output (challenge folders, agent working files, DB, logs, downloads) lives in a **user-supplied working directory** that can be anywhere on the host or on an SMB/network share.

Internal package/env names such as `ctf_core` and `CTFTOOLKIT_*` are retained for compatibility.

## 2. Prerequisites

### Option A — Native (Windows / macOS / Linux)

| Tool | Windows | macOS | Linux |
| :--- | :--- | :--- | :--- |
| **Python ≥ 3.12** | [python.org](https://python.org) or `winget install Python.Python.3.12` | `brew install python@3.12` | `apt install python3.12` / `dnf install python3.12` |
| **Docker Engine** | Docker Desktop | Docker Desktop | Docker Engine (`apt install docker.io`) |
| **uv** | `winget install astral-sh.uv` or `irm https://astral.sh/uv/install.ps1 \| iex` | `brew install uv` | `curl -LsSf https://astral.sh/uv/install.sh \| sh` |
| **libmagic** | bundled via `python-magic-bin` (auto) | `brew install libmagic` | `apt install libmagic1` |

Make the `.sh` scripts executable after cloning (Mac/Linux only):
```bash
chmod +x start_backend.sh start_full.sh setup_mcp.sh
```

### Option B — Docker (easiest for friends / CI)

Only Docker is required. No Python, no uv, no libmagic.
```bash
# 1. Build the CTF tool images (once)
docker compose -f docker-compose.yml build

# 2. Build the ctfsolver app image (once)
docker build -t ctfsolver:latest -f Dockerfile.ctfsolver .

# 3. Set your working directory
export CTF_WORKDIR=/absolute/path/to/ctf-workdir   # Mac/Linux
# or in .env: CTF_WORKDIR=D:\CTFs\active            # Windows

# 4. Launch
docker compose -f docker-compose.ctfsolver.yml up
```
Dashboard → http://localhost:8501  |  MCP HTTP → http://localhost:8000/mcp

> **macOS Docker socket**: Docker Desktop on Mac uses `~/.docker/run/docker.sock`.
> Set `DOCKER_SOCKET=$HOME/.docker/run/docker.sock` in `.env` if the default
> `/var/run/docker.sock` mount fails.
>
> **Windows Docker socket**: Named pipes can't be bind-mounted into Linux containers.
> Run Docker Desktop with WSL2 backend (default since Docker Desktop 4.x) and use the
> WSL2 socket at `/var/run/docker.sock` inside a WSL2 terminal.

## 3. Environment Configuration
The application relies strictly on environment variables for API authentication and tooling preferences. You must copy the provided `.env.example` file to `.env` and populate the necessary rows.

| Variable | Description | Required For |
| :--- | :--- | :--- |
| `CTFD_TOKEN` | A long-lived access token generated from your CTFd instance. | Downloading CTFd challenges |
| `CTFD_COOKIE` | Fallback session cookie (if token access is unavailable). | Downloading CTFd challenges |
| `ANTHROPIC_API_KEY` | Your Anthropic platform API key. | Executing Claude |
| `ANTHROPIC_AUTH_TOKEN`| OAuth token for Claude Code CLI. | Executing Claude (OAuth mode) |
| `CLAUDE_CODE_OAUTH_TOKEN`| Alias for Anthropic Auth Token. | Executing Claude (OAuth mode) |
| `CTF_HARNESS_CLAUDE_PARTIAL_MESSAGES` | Toggles live message streaming inside the UI (defaults to 1). | Claude UI telemetry |
| `OPENAI_API_KEY` | Your OpenAI platform API key. | Executing Codex |
| `CODEX_ACCESS_TOKEN` | Direct access token for the Codex engine. | Executing Codex |
| `CTF_HARNESS_CODEX_MODEL`| Model override (defaults to `gpt-5.4`). | Executing Codex |
| `KIRO_API_KEY` | Direct API key for Kiro (Amazon), if you have one. | Executing Kiro |
| `AWS_BEARER_TOKEN_BEDROCK` | Direct Bedrock bearer token; alternative to SSO. | Executing Kiro |
| `AWS_PROFILE` / `AWS_REGION` | AWS SSO profile + region used by Kiro. | Executing Kiro |
| `CTF_HARNESS_KIRO_CONFIG_DIR` | Optional override for Kiro auth directory. Defaults to `~/.kiro`. | Executing Kiro |
| `CTF_HARNESS_KIRO_MODEL` | Model override (defaults to `claude-sonnet-4.5-v2`). | Executing Kiro |
| `OPENCODE_API_KEY` | Direct API key for OpenCode (sst/opencode). | Executing OpenCode |
| `OPENCODE_AUTH_TOKEN` | OAuth token for OpenCode. | Executing OpenCode |
| `CTF_HARNESS_OPENCODE_HOME` | Optional override for OpenCode auth directory. Defaults to `~/.local/share/opencode`. | Executing OpenCode |
| `CTF_HARNESS_OPENCODE_MODEL` | Model override (defaults to `claude-sonnet-4-5`). | Executing OpenCode |
| `CTF_HARNESS_CLAUDE_CONFIG_DIR` | Optional override for Claude Code auth directory. Defaults to `~/.claude`. | Executing Claude |
| `CTF_HARNESS_CODEX_HOME` | Optional override for Codex auth directory. Defaults to `~/.codex`. | Executing Codex |
| `CTF_HARNESS_AGENT_MCP_URL` | MCP HTTP URL handed to dashboard-launched agents. `start_full.bat` defaults it to `http://127.0.0.1:8000/mcp`. | CTFd mode backend bridge |
| `CTF_HARNESS_START_AGENT_MCP` | Set to `0` to stop `start_full.bat` from starting the host MCP HTTP backend. | CTFd mode backend bridge |

> **Note**: Do not commit the `.env` file to version control.

All four supported agents (Claude, Codex, Kiro, OpenCode) can use their normal
local CLI logins. When present, the harness copies the relevant auth files
into the per-challenge container home for the matching agent:

| Agent | Host auth file(s) copied into container `$HOME` |
| :--- | :--- |
| Claude | `~/.claude/.credentials.json` |
| Codex | `~/.codex/auth.json` |
| Kiro | `~/.kiro/secrets.json`, `~/.kiro/argv.json`, `~/.aws/sso/cache/*.json`, `~/.aws/config`, `~/.aws/credentials` |
| OpenCode | `~/.local/share/opencode/{auth,account,mcp-auth}.json`, `~/.config/opencode/*` |

If local auth is missing, users have two options:
- Sign in with the local CLI so the default auth files exist:
  `claude` (Claude Code), `codex login`, `kiro-cli login`, `opencode auth login`.
- Set API credentials in `.env`: `ANTHROPIC_API_KEY` / `ANTHROPIC_AUTH_TOKEN` for Claude,
  `OPENAI_API_KEY` / `CODEX_ACCESS_TOKEN` for Codex, `KIRO_API_KEY` / `AWS_BEARER_TOKEN_BEDROCK` /
  `AWS_PROFILE` for Kiro, or `OPENCODE_API_KEY` / `OPENCODE_AUTH_TOKEN` for OpenCode
  (OpenCode also falls back to `ANTHROPIC_API_KEY` / `OPENAI_API_KEY`).

Missing auth is shown in:
- `setup_mcp.bat` / `scripts/setup.py --auth-check`
- the dashboard sidebar auth chips and caption
- the run error if a user starts an agent without usable auth

## 4. Installation & Setup

1. **Clone the repository:**
   ```bash
   git clone <repository-url>
   cd <repository-directory>
   ```

2. **Synchronize dependencies:**
   The project uses `uv` for lightning-fast dependency resolution. Run the following command to sync the virtual environment with `pyproject.toml` and `uv.lock`:
   ```bash
   uv sync --all-groups
   ```

3. **Build the Docker Image:**
   Before running any agents, build the necessary sandboxing image containing the required CTF binaries.
   ```bash
   docker build -t ctf-ai-solver:latest -f Dockerfile.ctf-tools .
   ```

   The image bakes in four agent CLIs: `claude`, `codex`, `opencode`, and
   `kiro-cli`. The Kiro CLI is installed via Amazon's canonical installer
   (`curl -fsSL https://cli.kiro.dev/install | bash`) at build time; no extra
   build-arg is required. In-container Kiro then uses whichever host auth the
   harness copies in (see the auth table above).

   > **Kiro auth caveat.** Kiro CLI uses AWS SSO / Builder ID device flow.
   > The harness copies `~/.kiro` and `~/.aws/sso/cache` into the container,
   > but the SSO token must be **fresh** (default lifespan ~8 hours) when the
   > agent runs — Kiro CLI cannot complete a device-flow login inside a
   > headless container. Practical options:
   > 1. Sign in on the host with `kiro-cli chat` (or the Kiro IDE) shortly
   >    before running a Kiro-agent challenge; the harness copies the still-
   >    valid token into the container.
   > 2. Provide a direct Bedrock bearer token via `AWS_BEARER_TOKEN_BEDROCK`
   >    (or `KIRO_API_KEY`) in `.env` — the harness forwards these into the
   >    container and skips SSO.
   > 3. Use `AWS_PROFILE` pointing at a role/profile with static credentials
   >    (not SSO); the harness forwards `AWS_PROFILE`, `AWS_REGION`, and
   >    `AWS_DEFAULT_REGION` into the container.

4. **Environment Setup:**
   ```bash
   cp .env.example .env
   # Open .env and fill in API keys.
   ```

5. **Set your working directory:**
   All challenge files, agent workspaces, DB, and logs live *outside* the repo.
   Set `CTF_WORKDIR` to an absolute path on your machine or SMB share:
   ```bat
   rem Option A — set in .env (persists across sessions)
   rem CTF_WORKDIR=D:\CTFs\active

   rem Option B — pass on the command line
   start_full.bat --workdir "D:\CTFs\active"
   start_backend.bat --workdir "D:\CTFs\active"
   ```
   The dashboard sidebar also lets you type/change the path at runtime; it is saved
   to `~/.ctfsolver/config.json` and pre-filled on next launch.

   > **Never set `CTF_WORKDIR` to the repo directory itself.** The repo is the
   > orchestrator home (source code, Dockerfiles, tools). Keep runtime data separate.

6. **Generate your MCP config:**
   On Windows:
   ```bat
   setup_mcp.bat
   ```
   Cross-platform:
   ```bash
   uv run python scripts/setup.py --write --auth-check
   ```
   This writes `mcp.local.json` for your checkout (includes `CTF_WORKDIR`) and prints
   whether Claude/Codex local auth is available. `mcp.local.json` is ignored by git.

The dashboard sidebar shows a **Platform** selector before the URL/credential fields:

| Platform | Auth needed | Notes |
| :--- | :--- | :--- |
| **CTFd** | URL + API token | Standard CTFd instances (`/api/v1/challenges`) |
| **rCTF** | URL + team token | rCTF open-source platform (team token from the scoreboard) |
| **Manual** | None | Paste challenge metadata directly; no platform API needed |

Switching platform clears the credential fields but keeps your working directory.
The last-used platform, URL, and username are saved to `~/.ctfsolver/config.json`
and pre-filled on next launch.

> **Password/token fields are never written to `~/.ctfsolver/config.json` or `.env`.**
> Supply them at runtime via the sidebar.


### Platform Selection
## 5. Usage & Testing

### Windows Launchers
From PowerShell or Explorer:
```bat
start_backend.bat
```
Smoke-tests the backend MCP server from `src/ctf_core`. Most MCP clients should start the backend themselves from their MCP config instead of you double-clicking this file.

```bat
start_backend.bat --doctor
```
Runs local readiness checks for Python, `uv`, Docker, MCP imports, registry count, workspace permissions, MCP config files, and Claude/Codex auth.

```bat
start_backend.bat --smoke
```
Runs the lightweight non-Docker backend smoke test. This checks MCP tool inventory, registry inventory, and a temporary non-CTFd challenge workspace round trip.
It also triages a small local artifact to prove the safe offline file-analysis path works.

```bat
start_backend.bat --http --port 8000 --path /mcp
```
Starts optional streamable HTTP MCP mode for local multi-client workflows. This is opt-in; stdio remains the default. The HTTP launcher only binds to loopback hosts such as `127.0.0.1` or `localhost`.

```bat
start_full.bat --workdir "D:\CTFs\active"
```
Starts the dashboard (and the MCP HTTP backend for agents) with the given working directory.
Omit `--workdir` only if `CTF_WORKDIR` is already set in your `.env` or shell.

### Running Multiple CTFs in Parallel

Each `start_full.bat` invocation is a fully independent process with its own workdir, DB, and
MCP backend. To run two CTFs simultaneously, use different `--workdir` **and** `--port` values
so the MCP HTTP backends don't fight over the same port:

```bat
rem Terminal 1 — TISC
start_full.bat --workdir "C:\Users\bryan\OneDrive\01 CTF\2026 TISC CTF" --port 8000

rem Terminal 2 — CyberLeague (different port!)
start_full.bat --workdir "C:\Users\bryan\OneDrive\01 CTF\2026 CYBER LEAGUE MAJOR CTF" --port 8001
```

Streamlit auto-increments its own port (8501, 8502…) so the browser UIs don't collide.
Each session's MCP backend, DB, challenge folders, and agent containers are fully isolated.

| What | Session 1 | Session 2 |
| :--- | :--- | :--- |
| Working dir | `...\2026 TISC CTF` | `...\2026 CYBER LEAGUE MAJOR CTF` |
| DB | `...\2026 TISC CTF\ctf_state.db` | `...\2026 CYBER LEAGUE MAJOR CTF\ctf_state.db` |
| MCP HTTP port | 8000 | 8001 |
| Dashboard URL | http://localhost:8501 | http://localhost:8502 |
| Docker containers | scoped to TISC challenges | scoped to CyberLeague challenges |

> **Port convention**: use 8000, 8001, 8002… for as many parallel sessions as you need.
> You can also pre-set `CTF_HARNESS_AGENT_MCP_URL` in the environment to skip the auto-start
> of the embedded backend entirely, or set `CTF_HARNESS_START_AGENT_MCP=0` to disable it.
### Non-CTFd Challenges
Use non-CTFd mode when a challenge is not on CTFd. In this mode, your AI IDE/CLI is the MCP client and calls the backend tools directly.

Important: MCP uses stdio. Usually you do **not** start `start_backend.bat` yourself. Add the server config to your MCP client, then the client launches the backend process and talks to it over stdin/stdout.

Windows config (use `CTF_WORKDIR` instead of the old `CTFTOOLKIT_WORKSPACE`):

```json
{
  "mcpServers": {
    "ctfsolver": {
      "command": "uv",
      "args": [
        "--directory",
        "C:\\ctfsolver",
        "run",
        "python",
        "-m",
        "ctf_core.server"
      ],
      "env": {
        "CTF_WORKDIR": "D:\\CTFs\\active"
      }
    }
  }
}
```

Run `setup_mcp.bat` or `uv run python scripts/setup.py --write` to generate `mcp.local.json`
with your current `CTF_WORKDIR` already filled in.

Use [mcp-windows.json](./mcp-windows.json) as the ready-to-paste Windows version. Use [mcp.json](./mcp.json) as the portable template. For a clone on another machine, run `setup_mcp.bat` or `uv run python scripts/setup.py --write --auth-check` and paste the generated `mcp.local.json` instead of hand-editing paths.

Generic setup:

1. Open your AI IDE/CLI MCP settings.
2. Add the `ctfsolver` server config above.
3. Restart the AI app or reload MCP servers.
4. Confirm the `ctfsolver` tools appear in the client.
5. Set target scope before network scans with `set_target_scope`.
6. Ask the client to use `ctfsolver` on your local challenge files or target.

Recommended non-CTFd flow:

1. Run `setup_mcp.bat`.
2. Run `start_backend.bat --doctor`.
3. Run `start_backend.bat --smoke`.
4. Add the generated `mcp.local.json` server config to your AI IDE/CLI.
5. In the MCP client, call `create_challenge`.
6. For files, call `triage_artifact` first, then `suggest_next_tools`.
7. For network targets, call `set_target_scope` before `run_nmap`, `run_ffuf`, `run_nuclei`, `run_sqlmap`, SpiderFoot, or theHarvester.
8. Record important results with `record_challenge_finding`.

Prompt examples:

```text
Use ctfsolver tools to inspect C:\CTFs\event\forensics\image.png and suggest next steps.
```

```text
Use ctfsolver to run file, exiftool, binwalk, and strings against ./challenge.bin.
```

```text
Use ctfsolver web tools against http://127.0.0.1:8080. Stay scoped to this CTF target.
```

Useful MCP tools for non-CTFd mode:

- `run_backend_smoke`: prove backend inventory and workspace creation.
- `set_target_scope`, `get_target_scope`, `check_target_scope`: control authorized network targets.
- `suggest_next_tools`: rank the next likely tools from description, files, target, and findings.
- `triage_artifact`: hash a file, infer type/category, sample strings safely, log evidence, and recommend next tools.
- `select_solver_templates`, `get_solver_template`: choose mobile, reverse, pwn, crypto, number-theory, and forensics solver templates.
- `score_playbooks`, `get_best_playbook`: rank playbooks/workflows with prerequisites, expected artifacts, failure branches, and next actions.
- `get_case_resource_context`: return files, notes, findings, evidence logs, playbooks, and writeups for non-CTFd case context.
- `run_apktool`, `run_jadx`, `run_ilspycmd`, `run_pyinstxtractor`: optional lazy mobile and managed-code reverse-engineering wrappers.
- `run_katana`, `run_arjun`, `run_linkfinder`, `run_git_dumper`, `run_gitleaks`, `run_schemathesis`, `run_graphql_cop`, `run_capinfos`: crawler, parameter, secret leak, API, GraphQL, and PCAP metadata helpers used by scored workflows.
- `ctfsolver://inventory`, `ctfsolver://playbooks`, `ctfsolver://challenge-files`, `ctfsolver://notes`, `ctfsolver://findings`, `ctfsolver://evidence-logs`, `ctfsolver://writeups`, `ctfsolver://context`, `ctfsolver://skills`: read-only MCP resources for client context.

Common MCP client locations vary by app:

- Claude Desktop / Claude Code: add the `mcpServers` block to the app's MCP config.
- Cursor / Windsurf / Kiro / Roo / Cline: add a custom MCP server with the same command, args, and env.
- Your own script/tool: launch the command as a child process and speak MCP JSON-RPC over stdio.

If the backend appears to hang when run directly, that is normal. It is waiting for MCP JSON-RPC messages on stdin. Use `start_backend.bat` only to smoke-test startup/imports, not as the normal way to connect an AI client.

Backend state is kept in your **working directory** (`CTF_WORKDIR`), not in the repo:

- `<workdir>/` — challenge folders, agent working files
- `<workdir>/ctf_state.db` — challenge and case state
- `<workdir>/downloads/` — downloaded attachments
- `<repo>/logs/` — backend process logs (repo-local)

### Migrating Existing Workspace Folders

If you previously ran ctfsolver with challenge folders inside `workspace/`, migrate them
to your working directory with the included script:

```bat
uv run python scripts/migrate_workspace.py --dst "D:\CTFs\active"
```

Options:
- `--src <path>` — source directory (default: `<repo>/workspace`)
- `--dst <path>` — destination working directory (**required**)
- `--dry-run` — print what would happen without moving anything

The script is idempotent: re-running it skips folders that already exist at the destination.
Unstructured folders (no `metadata.json`) get a stub `metadata.json` so the harness can
recognise them. A `_migrated_from.txt` file is written in each destination folder for
traceability. On clean completion, a `.gitkeep` is left in the repo `workspace/` dir.


### MCP Inspector
You can validate the backend with the MCP Inspector:

```bash
npx @modelcontextprotocol/inspector uv --directory "X:\01 REPOSITORIES\ctfsolver" run python -m ctf_core.server
```

Use the generated path from `mcp.local.json` on other machines. The Inspector should show the `ctfsolver` tools, prompts, and resources.

### Running the Dashboard
To boot the Streamlit application, execute the following from the root directory:
```bash
uv run streamlit run streamlit_app.py
```
*Navigate to the local URL (typically `http://localhost:8501`) provided in your terminal.*

Prefer `start_full.bat` on Windows when you want CTFd-mode agents to use the absorbed backend tools. Direct `uv run streamlit ...` still works, but it only gives agents the MCP backend if you start `start_backend.bat --http` yourself and set `CTF_HARNESS_AGENT_MCP_URL`.

### Running the Test Suite
The repository maintains a robust local test suite encompassing utilities, API retry mechanics, and workspace state generation. To run all tests and verify the system health:
```bash
uv run pytest -v
```
If you encounter `ModuleNotFoundError` during tests, ensure `pyproject.toml` has `pythonpath = ["src"]` defined in its `pytest.ini_options` block (which is enabled by default).

Additional backend verification:

```bash
uv run python scripts/doctor.py --no-images
uv run python scripts/mcp_smoke.py --json
uv run python scripts/generate_manifest.py --write
uv lock --check
uv pip check
uv run pip-audit
```

### Absorbed Toolkit
The backend now lives in `src/ctf_core` with its Dockerfiles, skills, schemas, scripts, docs, and reference tests preserved in this repository. The active manifest currently tracks 114 MCP tools, 72 registry tools, 33 skill docs, 8 Dockerfile entries, and 2 schema files.

Troubleshooting:

- **`CTF_WORKDIR` not set**: pass `--workdir <path>` to the launcher, or set `CTF_WORKDIR` in `.env`.
- Working directory inside the repo: the launcher will refuse — move it outside the repo.
- Doctor reports `[FAIL] Working directory`: run `start_backend.bat --doctor` to see exactly what's wrong.
- Docker missing or stopped: run Docker Desktop, then `start_backend.bat --doctor`.
- Auth missing: sign in with Claude/Codex locally or set API keys in `.env`; rerun `setup_mcp.bat`.
- MCP client cannot launch: regenerate `mcp.local.json` (`setup_mcp.bat`) and paste the exact config.
- Backend appears hung: stdio MCP servers wait for JSON-RPC on stdin; validate with MCP Inspector or `start_backend.bat --smoke`.
- Need multiple local MCP clients: use `start_backend.bat --http --port 8000 --path /mcp`, then point clients at `http://127.0.0.1:8000/mcp`.
- Dashboard agent cannot reach backend MCP: use `start_full.bat`; if you started Streamlit manually, also start `start_backend.bat --http` and set `CTF_HARNESS_AGENT_MCP_URL`.
- Network scan blocked: call `set_target_scope` with the authorized CTF host, URL, IP, or CIDR first.
- Windows path problem: use absolute paths in `mcp.local.json`, keep challenge files outside OneDrive when Docker needs to mount them.
- Session config (`~/.ctfsolver/config.json`) corrupted: delete the file and re-enter the workdir/platform via the sidebar.

## License

Apache-2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE).
