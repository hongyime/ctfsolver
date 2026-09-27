# Journal — ctfsolver

## 2026-09-16 — Baseline audit (opencode/Sisyphus-Junior)
- First `.agents/` setup for this repo.
- Repo is "clank-the-flag": CTFd challenge solver dashboard using Claude Code / Codex in per-challenge Docker containers.
- Stack: Python 3.12+, Docker, MCP, Streamlit, Playwright, Shodan, aiosqlite.
- No AGENTS.md present; only the synced template from sourcerepo is absent here.
- Secret scan clean: .env gitignored and absent; .env.example has empty placeholders only.
- 0 open PRs, 0 open issues. No action required.

2026-09-27: Added read-only first-party helper source binds for existing forensic and Ghidra tool containers. Five isolated source-mount fixture tests passed without Docker. Warm Ghidra broker changes need a new session; no image build, target execution, deployment, commit or push.

## 2026-09-27: Restore PR labeler configuration

Added the missing labels configuration referenced by the existing pull-request-target workflow. Its permissions and pinned action remain unchanged. The base-branch repair must merge before later PR runs can load the configuration.

2026-09-27: Separate app dev/publisher route preserves the MCP loopback guard through a shared dev network namespace, keeps dependencies outside source, and avoids private host-client configs in the app image. Add a Dockerfile-specific ignore file so the existing docs COPY has valid inputs without changing toolkit build ignores.
