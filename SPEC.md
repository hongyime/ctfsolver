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
- Backend reliability must be provable by a local doctor command and automated MCP smoke checks.
- Backend inventory must be represented by a generated manifest so future merges can prove no tools disappeared.
- Backend tool results should converge on structured records with command, exit status, outputs, artifacts, findings, warnings, and next steps.
- Network-capable tools must have an explicit target scope model before broader autonomous use.
- Non-CTFd mode should expose challenge state, files, findings, playbooks, and reusable workflows through MCP-native tools/resources/prompts where supported.
- New tool packs should be added only with registry coverage, Docker image coverage, and a test or probe that proves the expected binary is available.

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
| T17 | ~ | Add backend MCP smoke tests for tool listing, health checks, environment checks, challenge creation, challenge status, and one safe offline file tool. |
| T18 | x | Add a generated preservation manifest for MCP tools, registry tools, skill docs, Dockerfiles, schemas, launchers, and copied toolkit assets. |
| T19 | ~ | Add a structured tool result schema and migrate high-value backend paths toward consistent JSON output. |
| T20 | ~ | Add evidence logging for commands, targets, file hashes, results, timestamps, container images, and challenge IDs. |
| T21 | x | Add target scope tools and scope enforcement for network-capable backend tools. |
| T22 | ~ | Harden workspace file path handling for traversal, Windows normalization, and artifact ingestion safety. |
| T23 | x | Add Docker image status matrix with build state, expected binaries, image digests, and stale/missing markers. |
| T24 | x | Add CI verification for tests, lock checks, dependency checks, secret scan, imports, and non-Docker MCP smoke checks. |
| T25 | x | Add `suggest_next_tools` MCP workflow routing from description, files, target, category, and prior findings. |
| T26 | x | Add `triage_artifact` to hash files, detect type, run safe first-pass checks, record findings, and recommend next steps. |
| T27 | x | Add case/session workflow tools for list, active selection, attach artifact, notes, solved status, and export. |
| T28 | ~ | Expose MCP resources for challenge files, notes, findings, logs, playbooks, and writeups. |
| T29 | x | Expose MCP prompts for web, pwn, reverse engineering, crypto, forensics, OSINT, mobile, and cloud workflows. |
| T30 | ~ | Upgrade playbooks to scored workflows with prerequisites, expected artifacts, failure handling, and branching next actions. |
| T31 | x | Add agent memory summaries per challenge with attempts, findings, failures, important files, and hypotheses. |
| T32 | x | Add final writeup generation from evidence, notes, commands, artifacts, and final flag. |
| T33 | ~ | Add orchestrated web recon workflow from fingerprinting through directories, params, nuclei-lite, and summary. |
| T34 | ~ | Improve Nuclei support with template status/update, signed-template awareness, severity filtering, rate limits, and scope enforcement. |
| T35 | ~ | Add crawler support for endpoint discovery before fuzzing. |
| T36 | ~ | Add dedicated XSS discovery support. |
| T37 | ~ | Add parameter discovery support. |
| T38 | ~ | Add secret leak checks for downloaded source, exposed git data, backups, and repo-style challenges. |
| T39 | ~ | Add API testing helpers for OpenAPI, JWT, GraphQL, auth, and session checks. |
| T40 | . | Add mobile and managed-code reverse engineering tools and wrappers. |
| T41 | . | Improve Ghidra automation for strings, decompile, call graph, suspicious imports, and batch summaries. |
| T42 | . | Improve pwn workflow with exploit templates, libc resolver flow, multiarch support, and debugger helpers. |
| T43 | . | Add crypto solver templates for RSA, LCG, MT19937, XOR, hash length extension, lattice, AES mode bugs, and padding mistakes. |
| T44 | . | Add number theory tooling for factoring-heavy crypto challenges. |
| T45 | . | Improve forensics coverage for network, document, archive, carving, and disk recovery challenges. |
| T46 | ~ | Add PCAP triage workflow with protocol summary, extracted files, credentials, objects, DNS anomalies, USB HID, and timeline. |
| T47 | ~ | Add stego workflow chaining metadata, strings, carving, image/audio stego, and spectrogram analysis. |
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

## B

| id | status | bug |
| --- | --- | --- |
| B1 | x | Solver git remote contained an embedded GitHub token; remote URL sanitized. |
| B2 | x | Solver dependency audit findings existed; lockfile refreshed. |
| B3 | x | Solver currently launches powerful CTF agent containers; maintain the Docker-socket prohibition during toolkit integration. |
| B4 | . | Full solver-to-toolkit runtime broker is not complete until the bridge is exercised by tests or a real challenge workflow. |
