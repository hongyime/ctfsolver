from __future__ import annotations

import importlib.util
from pathlib import Path


def load_setup_module():
    script = Path(__file__).resolve().parents[1] / "scripts" / "setup.py"
    spec = importlib.util.spec_from_file_location("ctfsolver_setup", script)
    assert spec is not None
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


def test_setup_generates_ctfsolver_mcp_server() -> None:
    setup = load_setup_module()

    config = setup.build_config(windows=True)

    assert list(config["mcpServers"]) == ["ctfsolver"]
    server = config["mcpServers"]["ctfsolver"]
    assert server["command"] == "uv"
    assert server["args"][:2] == ["--directory", str(setup.PROJECT_ROOT.resolve())]
    assert server["args"][-3:] == ["python", "-m", "ctf_core.server"]
    assert "CTFTOOLKIT_WORKSPACE" in server["env"]
    assert "CTFTOOLKIT_DB_PATH" in server["env"]


def test_setup_auth_status_reports_missing_without_values(tmp_path, monkeypatch) -> None:
    setup = load_setup_module()
    claude_home = tmp_path / "claude"
    codex_home = tmp_path / "codex"
    claude_home.mkdir()
    codex_home.mkdir()

    for name in (
        "ANTHROPIC_API_KEY",
        "ANTHROPIC_AUTH_TOKEN",
        "CLAUDE_CODE_OAUTH_TOKEN",
        "OPENAI_API_KEY",
        "CODEX_ACCESS_TOKEN",
        "OPENAI_OAUTH_TOKEN",
        "CODEX_OAUTH_TOKEN",
    ):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("CTF_HARNESS_CLAUDE_CONFIG_DIR", str(claude_home))
    monkeypatch.setenv("CTF_HARNESS_CODEX_HOME", str(codex_home))

    statuses = setup.auth_status()

    assert statuses == [
        (
            "Claude",
            False,
            "missing; sign in with Claude Code or set ANTHROPIC_API_KEY / ANTHROPIC_AUTH_TOKEN in .env",
        ),
        (
            "Codex",
            False,
            "missing; sign in with Codex or set OPENAI_API_KEY / CODEX_ACCESS_TOKEN in .env",
        ),
    ]
