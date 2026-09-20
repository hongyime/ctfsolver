# SPEC

## G

`ctfsolver` is the single flattened CTF solving repository and orchestrator. It keeps the dashboard, agent autonomy, and backend tool suite, while being decoupled from any specific CTF platform and any specific host filesystem layout.

User-facing mode names:
- `CTFd mode`: Streamlit dashboard for CTFd challenge import and agent runs.
- `rCTF mode`: Streamlit dashboard for rCTF platform (used by many open-source CTFs).
- `manual mode`: no platform API; user supplies challenge metadata directly.
- `non-CTFd mode`: stdio MCP backend server for direct tool use by MCP clients.

Target shape:
- `src/ctf_harness_app`: existing solver UI, platform connectors, and agent runner.
- `src/ctf_harness_app/platforms/`: swappable platform connector layer.
- `src/ctf_core`: absorbed toolkit backend package.
- `docker/`, `skills/`, `schema/`, `scripts/`: toolkit assets.
- `start_backend.bat`: run backend MCP mode only.
- `start_full.bat`: run the solver dashboard/full local stack entrypoint.

Orchestrator vs workspace separation:
- The cloned repo (`C:\ctfsolver` or wherever) is the **orchestrator home** only.
  It holds source code, Dockerfiles, scripts, and agent tooling — nothing else.
- **All runtime output** (challenge folders, agent working files, DB, logs, downloads)
  lives in a **user-supplied working directory** that can be anywhere on the host or on
  an SMB/network share. The repo directory itself is never the workspace.
- The legacy `workspace/` folder inside the repo will be migrated out and emptied.

## C

- Preserve all toolkit features; do not drop tools, skill docs, Dockerfiles, or schemas.
- Keep the old OneDrive toolkit as reference until verification passes from this repo.
- Avoid a lift-and-shift that leaves two independent projects inside one repo.
- Do not mount Docker socket into solver agent containers.
- Do not use DinD as the default bridge.
- Keep challenge execution behind toolkit-owned Docker controls.
- Do not overwrite unrelated user changes or existing solver behavior.
- The workspace path must never be hardcoded to the repo directory or any C: path; it is always runtime-supplied.
- Platform connector credentials (URL, username, password/token) are session-scoped inputs, not static `.env` values; `.env` is only a last-resort fallback.
- The platform connector layer must be swappable: adding a new CTF platform must not require changes to workspace, agent, or harness code.
- Existing challenge folders in `workspace/` must be migrated to the user's configured working directory without data loss.
- Migration is one-shot and idempotent: re-running it must not duplicate or corrupt folders.
## I

### Paths
- Dashboard entry: `streamlit_app.py`
- Solver package: `src/ctf_harness_app`
- Toolkit backend package: `src/ctf_core`
- Backend import check: `ctf_core.server`
- Tool registry check: `ctf_core.registry`
- Platform connector package: `src/ctf_harness_app/platforms/`
  - `base.py`: abstract `PlatformConnector` interface
  - `ctfd.py`: existing CTFd implementation (refactored from `ctfd.py`)
  - `rctf.py`: rCTF connector
  - `manual.py`: no-platform connector for hand-supplied challenges
  - `registry.py`: maps `platform_id` strings to connector classes

### Working Directory Resolution (runtime, priority order)
1. CLI flag `--workdir <path>` passed to `start_full.bat` / `start_backend.bat`
2. Env var `CTF_WORKDIR` (set in `.env` or shell)
3. Dashboard sidebar input (persisted to `~/.ctfsolver/config.json` under key `workdir`)
4. Env var `CTFTOOLKIT_WORKSPACE` (existing, kept for backwards compatibility)
5. **Error** — user must supply a path; no silent fallback to repo directory

  The resolved path is stored as an absolute path. SMB paths (`\\server\share\...`)
  and Windows drive paths (`D:\CTFs\...`) are both valid. The harness normalises
  separators before passing paths to Docker mount args.

### Session Config (`~/.ctfsolver/config.json`)
- `workdir`: last-used working directory (abs path)
- `platform`: last-used platform type (`ctfd` | `rctf` | `manual`)
- `platform_url`: last-used platform base URL
- `platform_username`: last-used username (never password/token)
- Written on first successful connect; read by dashboard on next launch as pre-fill defaults.

### Platform Connector Interface (`PlatformConnector`)
```python
class PlatformConnector(ABC):
    platform_id: ClassVar[str]           # 'ctfd' | 'rctf' | 'manual'
    display_name: ClassVar[str]

    def authenticate(self, url: str, username: str, password: str) -> None: ...
    def list_challenges(self) -> list[ChallengeSummary]: ...
    def get_challenge(self, challenge_id: str | int) -> Challenge: ...
    def download_files(self, challenge: Challenge, dest: Path) -> list[Path]: ...
    def solved_ids(self) -> set[str | int]: ...
    def submit_flag(self, challenge_id: str | int, flag: str) -> SubmitResult: ...
```
- `Challenge` dataclass gains a `platform` field (`platform_id` string).
- `ChallengeSummary`: lightweight (id, name, category, value, solved) — for list views.
- `SubmitResult`: `(accepted: bool, message: str)`.
- `manual` connector: no URL/auth needed; user supplies a dict or a YAML file with challenge fields.
- The dashboard sidebar shows a platform selector (`CTFd` / `rCTF` / `Manual`) before the URL/credentials fields.
  Switching platform clears the credential fields but keeps the workdir.

### rCTF Connector Notes
- Auth: POST `/api/v1/auth/login` with `{ teamToken }` or `{ teamName, teamToken }` → returns `authToken`.
- List: GET `/api/v1/challs` (authenticated) → `data[].id/name/category/points/solves`.
- File URLs on rCTF are typically `files/<uuid>/<filename>` relative to the base URL.
- Submit: POST `/api/v1/challs/<id>/submit` with `{ flag }`.

### Launcher Contract
- `start_backend.bat` sets `PYTHONPATH=src` and smoke-tests/runs the backend entry.
- `start_full.bat` sets shared toolkit environment and starts the solver UI.
- Both accept `--workdir <path>` which sets `CTF_WORKDIR` for the session.

### MCP Client Config
- `mcp-windows.json` uses server id `ctfsolver`.
- `mcp.json` is the portable template and uses server id `ctfsolver`.
- `scripts/setup.py --write --auth-check` generates per-clone `mcp.local.json`.
- Generated config includes `CTF_WORKDIR` when a workdir is configured.

### Agent Auth Discovery
- Claude uses explicit env auth or host `~/.claude/.credentials.json`.
- Codex uses explicit env auth or host `~/.codex/auth.json`.

### Migration Script (`scripts/migrate_workspace.py`)
- Accepts `--src <path>` (default: `<repo>/workspace`) and `--dst <path>` (required).
- For each subfolder in `--src`:
  - If it has `metadata.json`: treat as a structured challenge folder; move to `--dst/<folder_name>/`.
  - If it has no `metadata.json` (e.g. `tisc-2026`, `locksmith-solve`): move as-is and write a
    stub `metadata.json` with `platform: manual`, `name: <folder_name>`, `status: migrated`.
- After each move, write `_migrated_from.txt` in the destination with source path and timestamp.
- Idempotent: if destination folder already exists and is non-empty, skip and report.
- Print a summary: N moved, N skipped (already at dst), N errors.
- On full success, remove `workspace/` from the repo (or leave an empty `.gitkeep`).

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
- User-facing docs should call the unified product `ctfsolver`; distinguish `CTFd mode`, `rCTF mode`, `manual mode`, and `non-CTFd mode`.
- Backend reliability must be provable by a local doctor command and automated MCP smoke checks.
- Backend inventory must be represented by a generated manifest so future merges can prove no tools disappeared.
- Backend tool results should converge on structured records with command, exit status, outputs, artifacts, findings, warnings, and next steps.
- Network-capable tools must have an explicit target scope model before broader autonomous use.
- Non-CTFd mode should expose challenge state, files, findings, playbooks, and reusable workflows through MCP-native tools/resources/prompts where supported.
- New tool packs should be added only with registry coverage, Docker image coverage, and a test or probe that proves the expected binary is available.
- Current generated manifest must verify at least 114 MCP tools, 72 registry tools, 33 skill Markdown files, 8 Dockerfile entries, and 2 schema files.
- CTFd-mode dashboard agents must receive backend MCP access through a host-owned HTTP MCP server/config handoff, without mounting the host Docker socket into agent containers.
- The workspace path must resolve to an absolute path outside the repo directory before any challenge folder is created.
- The dashboard must refuse to start a download/run if no working directory is configured.
- Platform connector `authenticate()` must raise a typed `AuthError` (not a generic exception) on bad credentials so the dashboard can surface a clear message.
- `scripts/migrate_workspace.py` must exit 0 with a clean summary when run against the repo's existing `workspace/` and a valid `--dst`.
- After migration, `workspace/` in the repo must contain no challenge data (only `.gitkeep` or be absent).
- `~/.ctfsolver/config.json` must not be committed or readable by Docker containers.
- The rCTF connector must pass the same smoke test suite as the CTFd connector (list, get, download stub).

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
| T16 | x | Add `ctfsolver doctor` checks for Python, uv, Docker, MCP import, registry, images, auth, env, paths, and workspace permissions. |
| T17 | x | Add backend MCP smoke tests for tool listing, health checks, environment checks, challenge creation, challenge status, and one safe offline file tool. |
| T18 | x | Add a generated preservation manifest for MCP tools, registry tools, skill docs, Dockerfiles, schemas, launchers, and copied toolkit assets. |
| T19 | x | Add a structured tool result schema and migrate high-value backend paths toward consistent JSON output. |
| T20 | x | Add evidence logging for commands, targets, file hashes, results, timestamps, container images, and challenge IDs. |
| T21 | x | Add target scope tools and scope enforcement for network-capable backend tools. |
| T22 | x | Harden workspace file path handling for traversal, Windows normalization, and artifact ingestion safety. |
| T23 | x | Add Docker image status matrix with build state, expected binaries, image digests, and stale/missing markers. |
| T24 | x | Add CI verification for tests, lock checks, dependency checks, secret scan, imports, and non-Docker MCP smoke checks. |
| T25 | x | Add `suggest_next_tools` MCP workflow routing from description, files, target, category, and prior findings. |
| T26 | x | Add `triage_artifact` to hash files, detect type, run safe first-pass checks, record findings, and recommend next steps. |
| T27 | x | Add case/session workflow tools for list, active selection, attach artifact, notes, solved status, and export. |
| T28 | x | Expose MCP resources for challenge files, notes, findings, logs, playbooks, and writeups. |
| T29 | x | Expose MCP prompts for web, pwn, reverse engineering, crypto, forensics, OSINT, mobile, and cloud workflows. |
| T30 | x | Upgrade playbooks to scored workflows with prerequisites, expected artifacts, failure handling, and branching next actions. |
| T31 | x | Add agent memory summaries per challenge with attempts, findings, failures, important files, and hypotheses. |
| T32 | x | Add final writeup generation from evidence, notes, commands, artifacts, and final flag. |
| T33 | x | Add orchestrated web recon workflow from fingerprinting through directories, params, nuclei-lite, and summary. |
| T34 | x | Improve Nuclei support with template status/update, signed-template awareness, severity filtering, rate limits, and scope enforcement. |
| T35 | x | Add crawler support for endpoint discovery before fuzzing. |
| T36 | x | Add dedicated XSS discovery support. |
| T37 | x | Add parameter discovery support. |
| T38 | x | Add secret leak checks for downloaded source, exposed git data, backups, and repo-style challenges. |
| T39 | x | Add API testing helpers for OpenAPI, JWT, GraphQL, auth, and session checks. |
| T40 | x | Add mobile and managed-code reverse engineering tools and wrappers. |
| T41 | x | Improve Ghidra automation for strings, decompile, call graph, suspicious imports, and batch summaries. |
| T42 | x | Improve pwn workflow with exploit templates, libc resolver flow, multiarch support, and debugger helpers. |
| T43 | x | Add crypto solver templates for RSA, LCG, MT19937, XOR, hash length extension, lattice, AES mode bugs, and padding mistakes. |
| T44 | x | Add number theory tooling for factoring-heavy crypto challenges. |
| T45 | x | Improve forensics coverage for network, document, archive, carving, and disk recovery challenges. |
| T46 | x | Add PCAP triage workflow with protocol summary, extracted files, credentials, objects, DNS anomalies, USB HID, and timeline. |
| T47 | x | Add stego workflow chaining metadata, strings, carving, image/audio stego, and spectrogram analysis. |
| T48 | x | Improve `setup_mcp.bat` to run doctor, generate config, show auth guidance, and print MCP client config paths. |
| T49 | x | Add backend launcher flags for doctor and smoke checks. |
| T50 | x | Add README quick paths for CTFd mode and non-CTFd MCP mode. |
| T51 | x | Add safe local example challenges for web, reverse engineering, crypto, pwn, and forensics testing. |
| T52 | x | Add MCP Inspector documentation for validating the backend server. |
| T53 | x | Add troubleshooting docs for Docker, auth, images, Windows paths, OneDrive, MCP launch, and scope blocks. |
| T54 | x | Add golden-output tests for artifact triage, crypto helpers, forensics helpers, and reverse engineering helpers. |
| T55 | x | Add health probes proving each registry binary exists in its Docker image. |
| T56 | x | Add timeout, truncation, artifact preservation, and cancellation policy for backend tools. |
| T57 | x | Add update command for images, templates, exploit-db, wordlists, and local metadata. |
| T58 | x | Add optional localhost HTTP MCP transport for multi-client workflows while keeping stdio default. |
| T59 | x | Add plugin-style optional tool packs for mobile, cloud, malware, GPU cracking, and OSINT. |
| T60 | x | Add benchmark challenges to measure whether agents can solve known local tasks through the backend. |
| T61 | - | Decouple workspace from repo: resolve working directory from `CTF_WORKDIR` / `--workdir` / sidebar / config file; error if none set; never fall back to repo dir. |
| T62 | - | Add `~/.ctfsolver/config.json` session config: persist and pre-fill `workdir`, `platform`, `platform_url`, `platform_username`. |
| T63 | - | Add `--workdir <path>` flag to `start_full.bat` and `start_backend.bat`; propagate to `CTF_WORKDIR` env. |
| T64 | - | Update `CTFTOOLKIT_WORKSPACE` and `CTFTOOLKIT_DB_PATH` resolution to use the resolved workdir, not relative repo-rooted paths. |
| T65 | - | Add platform connector abstraction: `src/ctf_harness_app/platforms/base.py` with `PlatformConnector` ABC, `ChallengeSummary`, `AuthError`, `SubmitResult`. |
| T66 | - | Refactor `ctfd.py` into `platforms/ctfd.py` implementing `PlatformConnector`; keep backwards-compatible shim in old location. |
| T67 | - | Add `platforms/rctf.py` implementing `PlatformConnector` for rCTF (login, list, get, download, submit). |
| T68 | - | Add `platforms/manual.py` implementing `PlatformConnector` for hand-supplied challenges (no URL/auth). |
| T69 | - | Add `platforms/registry.py` mapping platform IDs to connector classes; expose `get_connector(platform_id)`. |
| T70 | - | Update dashboard sidebar: add platform selector (CTFd / rCTF / Manual) before URL/credential fields; gate download button on workdir being set. |
| T71 | - | Write `scripts/migrate_workspace.py`: move existing `workspace/` subfolders to user-supplied `--dst`, writing stub `metadata.json` for unstructured folders and `_migrated_from.txt` per folder. |
| T72 | - | Run `scripts/migrate_workspace.py` against the current `workspace/` contents (tisc-2026, cyberleague-2026-a824, locksmith-solve) and verify the repo `workspace/` is empty after. |
| T73 | - | Add `.env.example` entries for `CTF_WORKDIR` and document that platform credentials should be supplied at runtime, not hardcoded. |
| T74 | - | Add doctor check for `CTF_WORKDIR`: verify it is set, is an absolute path, is writable, and is not inside the repo directory. |
| T75 | - | Add tests for working-directory resolution priority, `AuthError` typing, and platform connector registry lookup. |
| T76 | - | Update `mcp.json` / `mcp-windows.json` / `scripts/setup.py` to emit `CTF_WORKDIR` in generated configs. |
| T77 | - | Update README: document workdir setup, platform selection, migration script, and `~/.ctfsolver/config.json`. |

## B

| id | status | bug |
| --- | --- | --- |
| B1 | x | Solver git remote contained an embedded GitHub token; remote URL sanitized. |
| B2 | x | Solver dependency audit findings existed; lockfile refreshed. |
| B3 | x | Solver currently launches powerful CTF agent containers; maintain the Docker-socket prohibition during toolkit integration. |
| B4 | x | Full solver-to-toolkit runtime broker is not complete until the bridge is exercised by tests or a real challenge workflow. |
| B5 | - | `CTFTOOLKIT_WORKSPACE` defaults to the relative string `"workspace"` which resolves inside the repo; any tool writing challenge data to this path pollutes the repo checkout. Fixed by T61/T64. |
| B6 | - | `streamlit_app.py` line 217 hardcodes `DEFAULT_OUTPUT_DIR = "challenges"` as the workspace default with no error if unset; silently creates challenge folders inside the repo. Fixed by T61/T70. |
| B7 | - | `CTFdClient` is the only connector; platform type is implicit and cannot be swapped without code changes. Fixed by T65–T69. |
| B8 | - | `workspace/tisc-2026`, `workspace/cyberleague-2026-a824`, and `workspace/locksmith-solve` currently live inside the repo; these are runtime artefacts and must not be tracked by git. Fixed by T72. |
