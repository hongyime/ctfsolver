# CTF Toolkit — Upgrade Plan

> Status: **PROPOSAL — awaiting sign-off. No code changed yet.**
> Author: Sisyphus (synthesized from: a 17-challenge GREYCTF live run, a full code audit,
> an Oracle architecture pressure-test, and analysis of `zeyu2001/clank-the-flag`).

---

## 0. Locked decisions (do not relitigate)

| # | Decision | Value |
|---|---|---|
| D1 | Connection model | **B = thin host launcher (default)**; A = server-in-container is an *optional local deployment style*, never a remote service |
| D2 | Current usage | **Unchanged** — FastMCP **stdio**, OpenCode launches the server as a child process |
| D3 | Distribution | Friends **clone/fork the repo and run their OWN independent local instance**. No shared/hosted server, no inter-user networking, single-user/local per instance |
| D4 | Storage | **C: drive only** — no data-root relocation, no external drive |
| D5 | Images | **Full kitchen sink**, **lazy-built** (but build-as-a-job, see R-UX) |
| D6 | Cleanup | **Auto-prune by idle-TTL** + manual `prune_images`/`disk_usage`. Two-gate safety. Never prune mid-solve |
| D7 | Phase 5 | **Codified solver playbooks/heuristics in code**, NOT a RAG/vector DB |
| D8 | Security posture | **Keep the existing hardened model** (cap_drop ALL, non-root, no-new-privileges, offline-mode). Loosen per-tool only when needed (e.g. SYS_PTRACE for gdb). Do NOT adopt clank's root/host-net/unconfined posture |

---

## 1. Architecture verdicts (from Oracle pressure-test)

- **Auto-prune ↔ jobs ↔ lifecycle:** DANGEROUS if naive. Fix = **two-gate prune** (idle-TTL AND zero-container-reference) + **never `docker rmi -f`** (untag → dangling-layer ghosts) + startup reconciliation.
- **Restart-survivable jobs:** Server is a **stdio child of OpenCode → "restart" happens every time OpenCode closes** (frequent, not rare). Fix = **tiered durability**: short jobs ephemeral (die + reconcile), long jobs explicit opt-in detached (`--rm=false`) + 24h hard cap + max-N limit.
- **Socket/Windows:** Model B uses the Windows named pipe (no socket mount) — safe. Always use the Docker SDK `volumes` dict (paths contain spaces: `01 CTF`, `2026 GREYCTF`) — never shell-construct mounts. Model A (optional) = socket mount with world-writable refusal check; never DinD.
- **TOOL_REGISTRY:** unify the 4-file registration into one declarative registry, but `security_level` is a **required** field (no permissive default) + a unit test asserting dangerous binaries can't enter the derived whitelist.
- **Large-image build UX (R-UX):** a 10–40 min Sage/Ghidra build inside a tool call WILL blow OpenCode's tool timeout. Fix = **build-as-background-job + progress polling**, plus `prebuild_all_images` + `docker compose build` for first-run.

## 2. Borrowings from clank-the-flag (validated, fit our MCP core)

| Borrow | Use | Phase |
|---|---|---|
| Persistent per-challenge **`workspace/` + `.agent-home/`** | resume with memory across runs (fixes the GREYCTF "cold restart" pain) | 2 |
| **`reconcile_stale_runs()`** (match `docker ps --name` vs state, heartbeat staleness, grace windows) | concrete impl of Oracle's startup reconciliation | 2 |
| **Heartbeat (5s) + "no-output-for-Ns" notice** | the interactive-hang guard (killed my 3d-maze agents) | 2 |
| **`mask_command()`** secret masking (`-e KEY=val` → `KEY=<set>`) | audit log + state never store secrets | 2/3 |
| **Dockerfile tool list** (`zsteg`, `one_gadget`, `seccomp-tools`, `patchelf`, `foremost`, `socat`, `nasm`, `gdbserver`, multilib) | authoritative image-contents checklist | 1 |
| **`/goal` start/continue prompt template** | autonomous pipeline + playbooks | 3/5 |
| **CTFd downloader** (metadata+files+hints+tags+connection → workspace + PROMPT.md) | optional auto-download tool (CONFIRMED WANTED) | 4 |
| **`runs[]` state model** (id/agent/status/heartbeat/returncode/log paths) | per-challenge run tracking | 2 |

**Skipped:** single fat image (conflicts D5/D6), Streamlit UI (D2), agent-inside-box as the *core* (we keep MCP; offer as optional mode later), clank's permissive root/host-net/unconfined security (D8 — ours is better).

---

## 3. Capability gap matrix (current vs target)

| Category | Have now | ADD (Phase 1) |
|---|---|---|
| Pwn | pwntools, gdb(batch), radare2, angr/ROPgadget/ropper (in image, **no MCP tool**) | expose angr/ROPgadget/ropper as tools; add **one_gadget, libc-database, seccomp-tools, patchelf, pwninit**; **GDB/MI live-debug session** (clank/pwndbg-mcp style) |
| RE | file/readelf/nm/strings, binwalk, radare2 | **Ghidra headless** (analyzeHeadless or PyGhidra), **rizin**, **capa**, **FLOSS**, **wasm** (wabt/wasm2wat) |
| Crypto | z3, `run_sage` (**STUB**) | **real SageMath**, **fpylll/flatter (LLL/BKZ)**, **RsaCtfTool**, **factordb**, sympy/pycryptodome runner |
| Forensics | exiftool/strings/steghide, volatility3, tshark | **zsteg, stegseek, foremost, USB-HID-pcap extractor, SSTV/spectrogram** |
| Web | feroxbuster*, sqlmap, searchsploit (*not in image — broken) | fix image; add **ffuf, nuclei, jwt_tool** structured tools |
| Misc | flag detector, autonomous pipeline | per-challenge solve workspace, playbooks |

---

## 4. Phased implementation — file-by-file

### PHASE 0 — Fix what's broken + portability foundation
**Goal:** every current tool actually works; repo is clone-and-run reproducible; kill host `.venv` dependence.
- `docker/ctf-tools/Dockerfile` — ADD `feroxbuster`, `httpx`, `amass`, `assetfinder`, `wfuzz`, `whatweb`, `checksec` (currently mapped-but-missing → they fail at runtime). De-dupe radare2 (built in both ctf-pwn & ctf-re).
- `docker/ctf-crypto/Dockerfile` — decide SageMath: switch base to `sagemath/sagemath` OR add a dedicated `docker/ctf-sage/Dockerfile`. Implement `run_sage` for real (remove the stub in `server.py`).
- `src/ctf_core/utils/osint_tools.py` — Dockerize `spiderfoot`/`theHarvester` (currently host subprocess → absent on most machines) OR move into ctf-tools image. Remove host-subprocess dependency.
- `src/ctf_core/server.py` — `run_feroxbuster`: unique output filename per run (`ferox_<uuid>.json`) — fix the concurrent-overwrite race (L316).
- `src/ctf_core/observability/tracing.py` — replace hardcoded `/tmp/ctf-replays` (L334) with `tempfile.gettempdir()` (cross-platform).
- `mcp.json` / `mcp-windows.json` — replace placeholder paths with a setup script (`scripts/setup.py`) that generates them from the repo location, OR document a one-liner.
- `src/ctf_core/docker_runner.py` — audit all bind-mounts use the SDK `volumes` dict (confirm L368-402 already does; ensure no shell-string mounts anywhere).
- `pyproject.toml` + pin: ensure `uv.lock` committed; pin Docker base image digests in Dockerfiles for reproducibility.
- **Thin launcher**: `pyproject.toml` `[project.scripts]` + a minimal `scripts/launch.py` so host needs only Python + `docker` SDK (not the 261MB venv). Document the slim install.
- Tests: `tests/hands_on/` — add a REAL docker E2E test (build ctf-tools, run `nmap --version`, assert).
- **DoD:** `docker compose build` from a fresh clone succeeds; every existing MCP tool runs against a built image; no host-subprocess tools; no placeholder paths.

### PHASE 1 — Category coverage (the GREYCTF gaps)
**Goal:** cover all CTF categories with real tools + MCP wrappers.
- `docker/ctf-pwn/Dockerfile` — ADD `one_gadget`, `seccomp-tools` (gems), `patchelf`, `pwninit`, `libc-database` (or wrap libc.rip API), `gdbserver`, `socat`, `nasm`, multilib. (clank list.)
- `docker/ctf-re/Dockerfile` — ADD **Ghidra + JRE** (headless), `rizin`, `capa`, `FLOSS`, `wabt`/`wasm2wat`. (Heavy → lazy-build as a job.)
- `docker/ctf-crypto/Dockerfile` — ADD `fpylll`, `flatter`, `RsaCtfTool`, `factordb-pycli`, sympy, pycryptodome.
- `docker/ctf-forensics/Dockerfile` — ADD `zsteg`, `stegseek`, `foremost`, `sstv` decoder, `sox`/spectrogram deps; a USB-HID-pcap extractor script baked in.
- `src/ctf_core/server.py` — NEW MCP tools (each via the registry, see Phase 3): `run_ghidra_headless`, `run_rizin`, `run_capa`, `run_angr`, `run_ropgadget`, `run_one_gadget`, `run_libc_lookup`, `run_seccomp_tools`, `run_lll` (fpylll/flatter), `run_rsactftool`, `run_zsteg`, `run_stegseek`, `extract_usb_hid_pcap`, `run_volatility` (structured), `run_ffuf`, `run_nuclei`, `run_jwt_tool`.
- `src/ctf_core/server.py` — NEW **GDB/MI live-debug session** tool family (`gdb_start`/`gdb_send`/`gdb_read`/`gdb_stop`) — interactive, beats the current batch `run_gdb_script`.
- `src/ctf_core/parsers/` — parsers for ghidra/capa/volatility/ffuf/nuclei outputs.
- `src/ctf_core/utils/sanitize.py` + `command_whitelist.py` — register all new binaries (subsumed by Phase 3 registry).
- **DoD:** one representative challenge per category solvable end-to-end with the new tools (regression-test against the 5 GREYCTF wins + at least Training-Shooting/Grey-Yuumi-class tasks).

### PHASE 2 — Orchestration hardening (Oracle + clank must-haves)
**Goal:** jobs survive the frequent OpenCode-close; no hung agents; per-challenge memory.
- `schema/` + `src/ctf_core/db.py` — MIGRATION (SCHEMA_VERSION→3): add to `scan_jobs`: `job_type`, `image_name`, `container_id`, `durable BOOL`, `last_active_at`, `started_at`. Add `challenge_id` FK to `flags`/`credentials`/`services`. New `challenges` write-path methods.
- `src/ctf_core/jobs.py` (NEW) — **tiered durability**: short = ephemeral asyncio task; long = detached `--rm=false` container labeled `ctftoolkit.job=true`/`job_id=...`, container-id persisted. Max-N durable (default 3), absolute 24h cap.
- `src/ctf_core/jobs.py` — **startup reconciliation** (Oracle + clank `reconcile_stale_runs`): for each `running` row → `docker inspect`: NotFound→failed, exited→collect logs+complete, running→re-attach, label-orphans→log/grace-remove. Run in the FastMCP lifespan hook BEFORE tools register.
- `src/ctf_core/docker_runner.py` — **heartbeat (5s) + no-output-for-Ns guard** (clank pattern); **interactive-hang detection** (stdin-blocked → kill at timeout); always run untrusted binaries under a hard `timeout`.
- `src/ctf_core/utils/audit_logger.py` — wire into `docker_runner._run_tool_internal()` hot path (currently unwired); add **`mask_command()`** secret masking before any log/state write.
- `src/ctf_core/challenge.py` (NEW) — per-challenge `workspace/` + `.agent-home/` (clank): `create_challenge`, `ingest_files`, `record_finding(challenge_id)`, `challenge_status`, auto-`WRITEUP.md` generation.
- Shutdown hook — cancel short tasks (auto-remove), leave durable containers running.
- **DoD:** kill the server mid-job → restart → reconciliation correctly resolves every `running` row; a stdin-blocked binary is killed at timeout (no hang); a durable job survives an OpenCode close and re-attaches.

### PHASE 3 — DX / autonomy
- `src/ctf_core/registry.py` (NEW) — single declarative `TOOL_REGISTRY` (dataclass: name, image, binary, **`security_level` REQUIRED no-default**, command_template, parser, offline?, caps). `ALLOWED_BINARIES` + `command_whitelist` **derived** from it at startup.
- `tests/unit/test_registry_security.py` (NEW) — assert a known-dangerous binary cannot enter the derived whitelist; assert every tool has an explicit security_level.
- `src/ctf_core/server.py` — register tools by iterating the registry (kills the 4-file spread).
- `src/ctf_core/agents/*` — upgrade `run_challenge_analysis` to **triage → category-route → solve → verify-flag** with the `/goal` template + new tools.
- **DoD:** adding a tool = 1 registry entry; security tests pass; pipeline solves a sample challenge end-to-end.

### PHASE 4 — Portability packaging + prune/maintenance
- `docker-compose.yml` (NEW) — build all images; `compose build` = friend's one-command first-run.
- `scripts/setup.py` (NEW) — generate `mcp.json` from repo path; verify Docker; optional `prebuild_all_images`.
- `src/ctf_core/server.py` — NEW tools: `build_image(category)` (background job + `get_build_status`), `prebuild_all_images`, **`prune_images`** (two-gate: idle-TTL AND zero-container-reference; never `-f`), **`disk_usage`**, `check_workspace_permissions`.
- `src/ctf_core/prune.py` (NEW) — idle-TTL reaper: runs at startup + scheduled, **never mid-solve**, hard-veto any image with a running/stopped container or referenced by a `running`/durable `scan_jobs` row.
- `.env.example` — add `CTFTOOLKIT_IMAGE_TTL_DAYS` (default 7), `CTFTOOLKIT_MAX_DURABLE_JOBS` (3), `CTFTOOLKIT_DURABLE_JOB_MAX_HOURS` (24); wire the currently-ignored `CTFTOOLKIT_TIMEOUT` etc.
- `README.md` — clone-and-run guide, "build images yourself", optional Model A in-container mode (with socket world-writable refusal check), storage/auto-prune explanation.
- **DoD:** fresh clone on a clean machine (Docker only) → `compose build` → working toolkit; prune reclaims idle images and NEVER touches an in-use/pinned one; lazy-build of a heavy image runs as a job (no tool-call timeout).

### PHASE 5 — Solver playbooks & heuristics (NOT RAG)
- `src/ctf_core/playbooks/` (NEW) — codified per-category solver templates + smart defaults, e.g.: `crypto_lattice.md/.py` (fpylll CVP skeleton — the caexor pattern), `pwn_rop.md` (one_gadget/libc workflow — elite-ball), `forensics_usb_hid.py` (mouse/keyboard pcap → drawing/keystrokes — Grey Yuumi), `re_wasm.md`, `crypto_rsa.md`, etc. Seeded with the **17 GREYCTF write-ups we produced**.
- `src/ctf_core/agents/planner.py` — route to the matching playbook; inject as context/templates in the pipeline.
- **DoD:** for a lattice/USB-HID/ROP-class challenge the pipeline auto-pulls the right playbook and produces a working solve skeleton.

---

## 5. Execution strategy
- **Phase-by-phase, verify each before proceeding** (NOT 6-phase big-bang).
- **Phase 0 first** (correctness + reproducibility), then 1 (coverage — highest flag ROI), then 2 (resilience), then 3, 4, 5.
- After each phase: build the affected image(s), run that phase's DoD test, report.
- Nothing destructive; migrations are additive (SCHEMA_VERSION bump). Back up `ctf_state.db` before migrating.

## 6. Resolved decisions (signed off)
1. **SageMath → separate `ctf-sage` image** (keeps `ctf-crypto` light; the ~2.5GB Sage monster is lazy-built only when a Sage tool is invoked, and prunable when idle). `ctf-crypto` stays lean: z3, openssl, RsaCtfTool, fpylll/flatter, sympy, pycryptodome.
2. **Ghidra → PyGhidra** (in-process JVM bridge, like `ghidra-docker-mcp`), with **`analyzeHeadless` as documented fallback** if JVM-lifecycle issues bite. See PyGhidra constraints below — they shape the design.
3. **Optional CTFd downloader → Phase 4** (confirmed wanted).

### 6a. PyGhidra implementation constraints (MUST follow — vetted from user reports)
PyGhidra is the official bundled bridge (Ghidra 11.x, `pip install pyghidra`), but has real sharp edges. Design around them:
- **JVM cannot be cleanly restarted in-process (JPype limitation).** Start the JVM **ONCE** and keep it WARM for the server's lifetime; route all Ghidra calls through that single persistent bridge. NEVER start/stop the JVM per tool call. Model the Ghidra tool as a persistent in-process session inside the `ctf-re` (or dedicated `ctf-ghidra`) container.
- **Cold start is expensive** (JVM boot + auto-analysis = seconds–minutes for big binaries). Warm once; treat first-import/analysis as a background job (ties into Phase 2 build-as-a-job). Cache the analyzed program handle; reuse across decompile/strings/xref calls.
- **Tight version coupling**: pin Ghidra version + JDK (Ghidra 11.x → JDK 17 or 21) + pyghidra together in the image. This is WHY it lives in a pinned container (avoids the host-breakage users report).
- **Force headless explicitly**; avoid analysis options that expect a display (headed mode is flaky per reports).
- **Raw Java API via JPype**: wrap the common ops (`decompile_function`, `list_functions`, `search_strings`, `get_xrefs`, `list_imports/exports`, `get_bytes`) into clean MCP tools; surface readable errors (Java stack traces otherwise).
- **Memory**: a warm JVM + loaded large program = hundreds of MB–GB; set an explicit `mem_limit` on the Ghidra container (higher than the default 1g for big binaries).
- **Fallback trigger**: if the warm-bridge proves unstable during implementation, switch that tool to `analyzeHeadless` (cold JVM + postScript + file output) — uglier but decade-stable. Keep the MCP tool signature identical so the swap is internal.

## 7. Implementation environment (IMPORTANT)
- **Run the implementation in an OpenCode session rooted at the `ctfsolver` repository**.
- Reason: `glob`/`grep`/`lsp_diagnostics`/`edit`/`bash` are cwd-scoped; running from the CTF folder forces absolute-path gymnastics, gives no LSP on the toolkit's Python, and risks accidental writes into the unrelated GreyCTF competition folder.
- The GreyCTF folder (`C:\Users\bryan\OneDrive\01 CTF\2026 GREYCTF`) is competition data and must NOT be touched by toolkit work.
- This `UPGRADE_PLAN.md` lives in the toolkit repo, so a fresh toolkit-rooted session picks up seamlessly: read it, then start Phase 0.
