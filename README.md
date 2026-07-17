# Developer README

![Dashboard](./image.png)

## 1. Project Overview
This repository contains a local Streamlit dashboard and testing harness designed to bridge the gap between Capture The Flag (CTF) platforms and autonomous Large Language Model agents. It automates the extraction of challenges from CTFd, mounts them into isolated, tool-rich Docker containers, and manages the lifecycle of AI agents (Claude Code or Codex) attempting to solve them. Telemetry, active state tracking, and parsed execution logs are rendered in the frontend dashboard.

`ctfsolver` has two modes:
- **CTFd mode**: browser dashboard for CTFd challenge import and agent runs.
- **Non-CTFd mode**: MCP backend server for direct tool use by Claude/Codex-compatible MCP clients.

Internal package/env names such as `ctf_core` and `CTFTOOLKIT_*` are retained for compatibility.

## 2. Prerequisites
Ensure the following tools are installed on the host system:
- **Python**: `>=3.12`
- **Docker Engine**: Required to build the custom `Dockerfile.ctf-tools` image and spawn per-challenge containers.
- **uv**: Python package and project manager (recommended over standard `pip` for rapid virtual environment caching).

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
| `CTF_HARNESS_CLAUDE_CONFIG_DIR` | Optional override for Claude Code auth directory. Defaults to `~/.claude`. | Executing Claude |
| `CTF_HARNESS_CODEX_HOME` | Optional override for Codex auth directory. Defaults to `~/.codex`. | Executing Codex |

> **Note**: Do not commit the `.env` file to version control.

Claude and Codex can also use their normal local CLI logins. If `~/.claude/.credentials.json`
or `~/.codex/auth.json` exists, the harness copies only the relevant auth file into the
per-challenge container home for the matching agent.

If local auth is missing, users have two options:
- Sign in with the local Claude/Codex CLI so the default auth files exist.
- Set API credentials in `.env`: `ANTHROPIC_API_KEY` / `ANTHROPIC_AUTH_TOKEN` for Claude, or `OPENAI_API_KEY` / `CODEX_ACCESS_TOKEN` for Codex.

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

4. **Environment Setup:**
   ```bash
   cp .env.example .env
   # Open .env and add your respective tokens.
   ```

5. **Generate your MCP config:**
   On Windows:
   ```bat
   setup_mcp.bat
   ```
   Cross-platform:
   ```bash
   uv run python scripts/setup.py --write --auth-check
   ```
   This writes `mcp.local.json` for your checkout and prints whether Claude/Codex local auth is available. `mcp.local.json` is ignored by git because it contains machine-specific paths.

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
start_full.bat
```
Starts the CTFd dashboard with backend paths/env wired to this repo.

### Non-CTFd Challenges
Use non-CTFd mode when a challenge is not on CTFd. In this mode, your AI IDE/CLI is the MCP client and calls the backend tools directly.

Important: MCP uses stdio. Usually you do **not** start `start_backend.bat` yourself. Add the server config to your MCP client, then the client launches the backend process and talks to it over stdin/stdout.

Windows config:

```json
{
  "mcpServers": {
    "ctfsolver": {
      "command": "uv",
      "args": [
        "--directory",
        "X:\\01 REPOSITORIES\\ctfsolver",
        "run",
        "python",
        "-m",
        "ctf_core.server"
      ],
      "env": {
        "CTFTOOLKIT_WORKSPACE": "X:\\01 REPOSITORIES\\ctfsolver\\workspace",
        "CTFTOOLKIT_DB_PATH": "X:\\01 REPOSITORIES\\ctfsolver\\ctf_state.db"
      }
    }
  }
}
```

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
- `ctfsolver://inventory`, `ctfsolver://playbooks`, `ctfsolver://skills`: read-only MCP resources for client context.

Common MCP client locations vary by app:

- Claude Desktop / Claude Code: add the `mcpServers` block to the app's MCP config.
- Cursor / Windsurf / Kiro / Roo / Cline: add a custom MCP server with the same command, args, and env.
- Your own script/tool: launch the command as a child process and speak MCP JSON-RPC over stdio.

If the backend appears to hang when run directly, that is normal. It is waiting for MCP JSON-RPC messages on stdin. Use `start_backend.bat` only to smoke-test startup/imports, not as the normal way to connect an AI client.

Backend state is kept here:

- `workspace/`
- `ctf_state.db`
- `logs/`

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
The backend now lives in `src/ctf_core` with its Dockerfiles, skills, schemas, scripts, docs, and reference tests preserved in this repository. The active manifest currently tracks 94 MCP tools, 60 registry tools, 33 skill docs, 7 Dockerfile entries, and 2 schema files.

Troubleshooting:

- Docker missing or stopped: run Docker Desktop, then `start_backend.bat --doctor`.
- Auth missing: sign in with Claude/Codex locally or set API keys in `.env`; rerun `setup_mcp.bat`.
- MCP client cannot launch: regenerate `mcp.local.json` and paste that exact config into the client.
- Backend appears hung: stdio MCP servers wait for JSON-RPC on stdin; validate with MCP Inspector or `start_backend.bat --smoke`.
- Need multiple local MCP clients: use `start_backend.bat --http --port 8000 --path /mcp`, then point clients at `http://127.0.0.1:8000/mcp`.
- Network scan blocked: call `set_target_scope` with the authorized CTF host, URL, IP, or CIDR first.
- Windows path problem: use absolute paths in `mcp.local.json`, and keep challenge files outside OneDrive when Docker needs to mount them.
