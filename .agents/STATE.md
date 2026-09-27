# State — ctfsolver

**Last updated**: 2026-09-16 (baseline review, opencode/Sisyphus-Junior)
**Branch**: main (up to date with origin)

## Current Status
Baseline audit complete. No active development task in progress.

## Repo Summary
- **Purpose**: CTFd challenge solver dashboard — harnesses Claude Code or Codex to solve CTF challenges in per-challenge containers
- **Project name**: clank-the-flag
- **Stack**: Python 3.12+, Docker, MCP, Streamlit, aiosqlite, Playwright, Shodan, Pydantic, Rich
- **Key files**: `main.py`, `streamlit_app.py`, `pyproject.toml`, `docker-compose.yml`, `SPEC.md`
- **Config**: `.env.example` present; actual `.env` gitignored and not present in repo

## Open PRs / Issues
- 0 open PRs
- 0 open issues

## Security Status
- `.env` correctly gitignored; no actual `.env` committed
- `.env.example` contains empty placeholders only (ANTHROPIC_API_KEY, OPENAI_API_KEY, CTFD_TOKEN, etc.)
- Secret scan: only CTF challenge test descriptions mention "secret/password" — no hardcoded credentials

## Next Steps
- No urgent work required
- Consider adding AGENTS.md (currently missing from this repo)

2026-09-27: Added read-only first-party helper source binds for existing forensic and Ghidra tool containers. Five isolated source-mount fixture tests passed without Docker. Warm Ghidra broker changes need a new session; no image build, target execution, deployment, commit or push.

## 2026-09-27: Restore PR labeler configuration

Added the missing labels configuration referenced by the existing pull-request-target workflow. Its permissions and pinned action remain unchanged. The base-branch repair must merge before later PR runs can load the configuration.

2026-09-27: Prepared standalone app development with sync-only source delivery, Streamlit polling and explicit MCP process/session restart behavior. No Docker socket/auth mounts or real workdir are used. App publication is separate from the seven tool images; config parsing and inert smoke do not establish tool runtime. Legacy app MCP non-loopback mismatch remains documented.

## 2026-09-27 — Development usage-statistics privacy

Disable Streamlit browser usage statistics in the app development Compose dashboard.
The explicit setting needs no image rebuild; static Compose validation passes.
Runtime verification of the effective Streamlit setting remains pending.
