# CTF Toolkit — Status

**Last validated:** 2026-05-31  
**Test suite:** 391 passed, 2 skipped, 0 failures (offline: unit + security + integration)

## Remediation (2026-05-31)

Large security/correctness/feature remediation. All changes verified at green checkpoints
(338 -> 391 offline tests); security hardening proven against live containers.

- **State integrity:** public DB API (no raw `_db`), `PRAGMA foreign_keys=ON`, `RETURNING`-based
  `insert_target` (TOCTOU fixed), `asyncio.Lock` on `get_database()`, versioned migration system
  (`user_version`; migrations 1-2 verified fresh + legacy), atomic `transaction()` context.
- **Security/sandbox (real-container verified):** non-root containers (uid 1000), mem/pid limits,
  per-tool network isolation (offline tools get `network_disabled`), nmap spoof/decoy flag block,
  OSINT subprocess sanitization, template-arg validation, writeup-scraper SSRF guard,
  interruptible `container.wait` (Ctrl+C kills container ~1s).
- **Accuracy:** flag-detector denoised (no more MD5/log-prefix false positives), 11 parser fixes
  (hydra service field, sqlmap ReDoS+hash, nikto, hashcat, generic, nmap/masscan XXE+int guards, etc.).
- **Pipeline + features:** `store_results` finished (pipeline persists targets/services/creds/flags);
  async scan handles (`start_scan`/`poll_scan`/`get_scan_result` + `scan_jobs` table);
  `format="json"` on parsing tools; `record_finding` write API; partial-results on interruption;
  F1 local-tool families (`run_binary_analysis`, `run_gdb_script`, `run_pwntools`, `decode_stego`,
  `run_z3`; `run_sage` enablement path documented in the ctf-crypto Dockerfile —
  needs a `sagemath/sagemath` base swap + rebuild; `run_z3` covers SMT/constraint needs meanwhile).
- **Process:** CI workflow (ruff+pytest), `.env` auto-loading, metrics wired into docker_runner,
  build-script Unicode fix, contradictory `requirements.txt` removed.

Snapshot of pre-remediation source: `backups/pre-remediation-20260530-235025/`.
Decided: `wasm_runner`/`db_optimization`/`RuntimeMonitor` STAY DELETED — removed during
remediation, retained only in the backup snapshot; superseded by the hardened Docker sandbox +
command guards (resurrecting the WASM fallback would be a security downgrade). `ty`: the entire
`src/` tree is clean — **0 diagnostics** (`uv run ty check src/` passes). The final 13 errors were
cleared via minimal, runtime-neutral fixes: `getattr` over pstats/Callable typeshed gaps (debugger),
an annotated `Callable[..., list[dict]]` dispatch list (writeup_scraper), a naive-UTC `_utcnow()`
helper (web_search), and `getattr(grp, "getgrnam")` for the Unix-only platform false-positive (linux).
README test-counts truthed-up; `run_sage` enablement documented in the ctf-crypto Dockerfile.
**Test suite:** 308 passed, 2 skipped, 0 failures (offline: unit + security + integration; verified 2026-05-31)

## What It Does

AI-assisted CTF automation toolkit. Exposes 15+ security tools (nmap, sqlmap, feroxbuster, volatility, hashcat, etc.) via:
1. **MCP Server** (`ctf_core.server`) — for AI IDE integration (Claude Desktop, Cursor, Kiro)
2. **Interactive CLI** (`start_toolkit.bat`) — rich terminal menu for manual use

Tools run in isolated Docker containers. Results are parsed and persisted to SQLite (`ctf_state.db`). An agent pipeline (AutoPrompter → Planner → Executor) can autonomously analyze a challenge description, select a strategy, run tools, and return structured findings.

## Architecture

```
start_toolkit.bat → main.py → cli.py (interactive menu)
                 → server.py (MCP stdio server, 15+ @mcp.tool functions)
                     ├── agents/ (AutoPrompter, Planner, Executor, ModeController)
                     ├── parsers/ (nmap, ferox, sploit, sqlmap, etc.)
                     ├── utils/ (sanitize, flag_detector, resilience, shodan, osint)
                     └── docker_runner.py → 5 Docker images
```

## Bugs Fixed (2026-05-13)

| # | File | Bug | Fix |
|---|------|-----|-----|
| 1 | `db.py` | `insert_flag(target_id, flag_value)` didn't match server's call `insert_flag(flag=, source=, pattern=)` | Updated signature; `target_id` now optional |
| 2 | `schema/init_db.sql` | `flags.target_id NOT NULL` blocked orphan flags | Made nullable; added `source`/`pattern` columns |
| 3 | `db.py` | `get_services()` returned no `ip_address` (not in services table) | Added `LEFT JOIN targets` |
| 4 | `executor.py` | Skill path resolved to `src/skills/` instead of project root | `parent×3 → parent×4` |
| 5 | `server.py` | `run_feroxbuster` used nmap's `generate_summary` on ferox data | Imported `ferox_generate_summary` |
| 6 | `docker_runner.py` | `whatweb` and `openssl` missing from `TOOL_IMAGES` | Added both |
| 7 | `sanitize.py` | `whatweb` missing from `ALLOWED_BINARIES` | Added |
| 8 | `resilience.py` | Socket leak in `_is_internet_available` | Context manager + per-socket timeout |
| 9 | `.env.template` | Duplicate of `.env.example`, nothing referenced it | Deleted |

## Features Verified Working

- MCP server starts and exposes tools via stdio
- `analyze_challenge` → AutoPrompter → Planner pipeline
- `health_check` → DB + Docker connectivity
- `insert_flag` with source/pattern metadata
- `get_services` returns ip_address via JOIN
- Executor loads skill files from correct path
- Feroxbuster uses correct output file path + summary format
- `whatweb` and `openssl` can be dispatched through Docker runner
- Internet check doesn't leak sockets
- 294 unit/security tests, 366 total passing

## Test Results

| Suite | Result |
|-------|--------|
| Unit (tests/unit/) | 294 passed |
| Security (tests/security/) | — included above |
| Integration (tests/integration/) | 44 passed, 2 skipped |
| **Offline total** | **338 passed, 2 skipped** |
| Tier 1 hands-on | 18/18 passed (Docker required) |
| Tier 2+ | Require internet + live targets — not run offline |

## Remaining Risks / Blockers

- **Docker images must be pre-built**: tools fail gracefully with a clear error if an image is missing. Run `setup.bat` to build.
- **Shodan API key**: `run_shodan` returns an informative error if `SHODAN_API_KEY` is unset in `.env`.
- **`run_challenge_analysis` runs real Docker tools**: needs a live target and built images.
- **Tier 2+ tests**: require internet access to external test sites (scanme.nmap.org, Acunetix demo, etc.).

## Completed (2026-05-13)

- `whatweb` confirmed in ctf-tools Dockerfile and running Docker image
- Playwright 1.59.0 installed; chromium browser installed and verified launching
- `start_toolkit.bat` sets `chcp 65001` + `PYTHONUTF8=1` (fixes Unicode banner crash on Windows)
- `run_tier1.py` sets UTF-8 stdout/stderr on Windows inline
- README updated with full test tier table and offline/online requirements
- 338 offline tests pass; 18/18 Tier 1 hands-on tests pass

## Recommended Future Improvements

1. Add a contract test between `server.py` flag calls and `db.insert_flag` signature to prevent future drift
2. Wire `run_challenge_analysis` findings back to the `challenges` table (currently logs to `action_log` only)
3. Add `playwright install chromium` step to `setup.bat` so fresh installs don't need a manual step
