# Journal — ctfsolver

## 2026-09-16 — Baseline audit (opencode/Sisyphus-Junior)
- First `.agents/` setup for this repo.
- Repo is "clank-the-flag": CTFd challenge solver dashboard using Claude Code / Codex in per-challenge Docker containers.
- Stack: Python 3.12+, Docker, MCP, Streamlit, Playwright, Shodan, aiosqlite.
- No AGENTS.md present; only the synced template from sourcerepo is absent here.
- Secret scan clean: .env gitignored and absent; .env.example has empty placeholders only.
- 0 open PRs, 0 open issues. No action required.
- 2026-09-19 20:06:41 +08:00 [PRAWN-T14/claude/stop] branch=main head=6c8f631 dirty=4
- 2026-09-19 22:24:52 +08:00 [PRAWN-T14/claude/stop] branch=main head=c428282 dirty=1
- 2026-09-19 22:39:03 +08:00 [PRAWN-T14/claude/stop] branch=main head=c428282 dirty=1
- 2026-09-19 23:23:25 +08:00 [PRAWN-T14/claude/stop] branch=main head=c428282 dirty=2
- 2026-09-20 09:23:13 +08:00 [PRAWN-T14/claude/stop] branch=main head=c428282 dirty=2
- 2026-09-20 09:28:40 +08:00 [PRAWN-T14/claude/stop] branch=main head=c428282 dirty=2
- 2026-09-20 09:53:35 +08:00 [PRAWN-T14/claude/stop] branch=main head=c428282 dirty=2
- 2026-09-20 13:07:21 +08:00 [PRAWN-T14/claude/stop] branch=main head=c428282 dirty=3
- 2026-09-20 14:05:55 +08:00 [PRAWN-T14/claude/stop] branch=main head=c428282 dirty=8
- 2026-09-20 18:21:09 +08:00 [PRAWN-T14/claude/stop] branch=main head=c428282 dirty=9
- 2026-09-20 19:02:49 +08:00 [PRAWN-T14/claude/stop] branch=main head=c428282 dirty=9
- 2026-09-20 19:42:17 +08:00 [PRAWN-T14/claude/stop] branch=main head=c428282 dirty=9
- 2026-09-20 19:50:20 +08:00 [PRAWN-T14/claude/stop] branch=main head=c428282 dirty=9
- 2026-09-20 21:06:50 +08:00 [PRAWN-T14/claude/stop] branch=main head=c428282 dirty=9
- 2026-09-20 21:34:06 +08:00 [PRAWN-T14/claude/stop] branch=main head=c428282 dirty=9
- 2026-09-20 21:55:30 +08:00 [PRAWN-T14/claude/stop] branch=main head=c428282 dirty=2
- 2026-09-20 22:09:29 +08:00 [PRAWN-T14/claude/stop] branch=main head=c428282 dirty=2
- 2026-09-20 22:24:05 +08:00 [PRAWN-T14/claude/stop] branch=main head=c428282 dirty=2
- 2026-09-20 22:50:44 +08:00 [PRAWN-T14/claude/stop] branch=main head=c428282 dirty=2
- 2026-09-20 22:59:30 +08:00 [PRAWN-T14/claude/stop] branch=main head=c428282 dirty=2
- 2026-09-20 23:05:25 +08:00 [PRAWN-T14/claude/stop] branch=main head=c428282 dirty=3
- 2026-09-20 23:27:16 +08:00 [PRAWN-T14/claude/stop] branch=main head=c428282 dirty=4
- 2026-09-20 23:35:41 +08:00 [PRAWN-T14/claude/stop] branch=main head=c428282 dirty=9
- 2026-09-20 23:58:39 +08:00 [PRAWN-T14/claude/stop] branch=main head=cf5bfa0 dirty=2
- 2026-09-21 07:24:02 +08:00 [PRAWN-T14/claude/stop] branch=main head=8633fe5 dirty=2
- 2026-09-21 07:38:52 +08:00 [PRAWN-T14/claude/stop] branch=main head=60aa9fd dirty=2
- 2026-09-21 08:21:24 +08:00 [PRAWN-T14/claude/stop] branch=main head=60aa9fd dirty=2
- 2026-09-21 08:30:28 +08:00 [PRAWN-T14/claude/stop] branch=main head=24dcd50 dirty=2

2026-09-27: Added read-only first-party helper source binds for existing forensic and Ghidra tool containers. Five isolated source-mount fixture tests passed without Docker. Warm Ghidra broker changes need a new session; no image build, target execution, deployment, commit or push.

## 2026-09-27: Restore PR labeler configuration

Added the missing labels configuration referenced by the existing pull-request-target workflow. Its permissions and pinned action remain unchanged. The base-branch repair must merge before later PR runs can load the configuration.

2026-09-27: Separate app dev/publisher route preserves the MCP loopback guard through a shared dev network namespace, keeps dependencies outside source, and avoids private host-client configs in the app image. Add a Dockerfile-specific ignore file so the existing docs COPY has valid inputs without changing toolkit build ignores.

2026-09-27: Disable Streamlit browser usage statistics in the development dashboard environment; preserve MCP settings, production commands and image contents. Static parsing passes; runtime setting verification remains pending.

2026-09-27: Consolidate the three root-file watches into one allowlisted root rule to avoid duplicate Windows SMB parent watches. Keep directory rules for nested initial sync, all private exclusions, telemetry opt-out and runtime settings unchanged. Static/matcher checks pass; actual SMB runtime validation remains separate.
