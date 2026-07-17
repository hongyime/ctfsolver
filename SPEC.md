# SPEC

## G

`ctfsolver` becomes the single flattened CTF solving repository. It keeps the existing dashboard, CTFd workflow, and agent autonomy, while absorbing the `ctftoolkit` backend so the OneDrive toolkit folder can eventually be deleted.

User-facing mode names:
- `CTFd mode`: Streamlit dashboard for CTFd challenge import and agent runs.
- `non-CTFd mode`: stdio MCP backend server for direct tool use by MCP clients.

Target shape:
- `src/ctf_harness_app`: existing solver UI, CTFd orchestration, and agent runner.
- `src/ctf_core`: absorbed toolkit backend package.
- `docker/`, `skills/`, `schema/`, `scripts/`: toolkit assets copied into the solver repo.
- `start_backend.bat`: run backend MCP mode only.
- `start_full.bat`: run the solver dashboard/full local stack entrypoint.

## C

- Preserve all toolkit features during absorption; do not intentionally drop tools, skill docs, Dockerfiles, or schemas.
- Keep the old OneDrive toolkit as reference until verification passes from this repo.
- Avoid a lift-and-shift that leaves two independent projects inside one repo; dependencies and launchers should be solver-owned.
- Do not mount Docker socket into solver agent containers.
- Do not use DinD as the default bridge.
- Keep challenge execution behind toolkit-owned Docker controls and narrow solver-to-toolkit integration points.
- Do not overwrite unrelated user changes or existing solver behavior.

## I

- Dashboard entry: `streamlit_app.py`
- Solver package: `src/ctf_harness_app`
- Toolkit backend package: `src/ctf_core`
- Backend import check: `ctf_core.server`
- Tool registry check: `ctf_core.registry`
- Launcher contract:
  - `start_backend.bat` sets `PYTHONPATH=src` and smoke-tests/runs the backend entry.
  - `start_full.bat` sets shared toolkit environment and starts the solver UI.
- MCP client config:
  - `mcp-windows.json` uses server id `ctfsolver`.
  - `mcp.json` is the portable template and uses server id `ctfsolver`.
  - `scripts/setup.py --write --auth-check` generates per-clone `mcp.local.json`.
- Agent auth discovery:
  - Claude uses explicit env auth or host `~/.claude/.credentials.json`.
  - Codex uses explicit env auth or host `~/.codex/auth.json`.

## V

- Absorbed toolkit inventory must preserve at least:
  - 71 MCP tools
  - 60 registry tools
  - 33 skill Markdown files
  - 6 Dockerfiles
  - 2 schema files
- Existing solver tests must continue to pass.
- Backend import and registry checks must pass from this repo.
- Agent containers may keep the existing CTF-oriented privileges, but must not receive host Docker socket access.
- Runtime junk stays out of git: `.venv`, caches, logs, DB files, workspaces, downloads, build output, and secrets.
- The OneDrive toolkit folder is deletion-ready only after source, launcher, and verification checks pass here.
- Claude and Codex auth must stay agent-specific: Claude containers receive only Claude auth, Codex containers receive only Codex auth.
- Default host CLI auth files may be copied into per-challenge `.agent-home`, but must not be committed or printed in logs.
- Missing agent auth must be visible during setup, in the dashboard sidebar, and in agent run errors.
- Non-CTFd challenges must go through the MCP backend server, not a dashboard manual challenge form.
- User-facing docs should call the unified product `ctfsolver`; distinguish only `CTFd mode` and `non-CTFd mode`.

## T

| id | status | task |
| --- | --- | --- |
| T1 | x | Audit and refresh vulnerable dependencies in both current codebases. |
| T2 | x | Sanitize the OneDrive-blocked LFI note enough to inspect and copy the toolkit. |
| T3 | x | Add `SPEC.md` to both repositories. |
| T4 | x | Create a solver safety branch for the absorption work. |
| T5 | x | Copy toolkit source assets into the flattened solver layout. |
| T6 | x | Merge toolkit dependencies into solver project config and lockfile. |
| T7 | x | Add backend-only and full-stack batch launchers. |
| T8 | x | Add a narrow toolkit bridge/foundation in the solver package. |
| T9 | x | Add preservation tests for imports, inventory, launchers, and Docker boundary. |
| T10 | x | Run solver-side verification and report whether the old OneDrive toolkit can be deleted. |
| T11 | x | Auto-discover default Claude and Codex CLI auth files without storing tokens in `.env`. |
| T12 | x | Remove dashboard manual challenge creation; non-CTFd mode is MCP backend only. |
| T13 | x | Document `ctfsolver` mode names and backend MCP usage. |
| T14 | x | Document non-CTFd MCP setup steps and prompt examples for future users. |
| T15 | x | Add per-clone MCP config generation and missing-auth guidance. |

## B

| id | status | bug |
| --- | --- | --- |
| B1 | x | Solver git remote contained an embedded GitHub token; remote URL sanitized. |
| B2 | x | Solver dependency audit findings existed; lockfile refreshed. |
| B3 | x | Solver currently launches powerful CTF agent containers; maintain the Docker-socket prohibition during toolkit integration. |
| B4 | . | Full solver-to-toolkit runtime broker is not complete until the bridge is exercised by tests or a real challenge workflow. |
