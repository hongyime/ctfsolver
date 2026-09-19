from __future__ import annotations

from ctf_harness_app import agents


def test_claude_default_credentials_count_as_auth(tmp_path, monkeypatch) -> None:
    claude_home = tmp_path / ".claude"
    claude_home.mkdir()
    (claude_home / ".credentials.json").write_text('{"ok": true}', encoding="utf-8")

    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    monkeypatch.delenv("ANTHROPIC_AUTH_TOKEN", raising=False)
    monkeypatch.delenv("CLAUDE_CODE_OAUTH_TOKEN", raising=False)
    monkeypatch.setenv("CTF_HARNESS_CLAUDE_CONFIG_DIR", str(claude_home))

    assert agents.host_claude_credentials_path() == claude_home / ".credentials.json"
    assert agents.has_claude_auth() is True
    assert agents.claude_env_summary() == "host Claude .credentials.json is available"


def test_codex_default_auth_json_count_as_auth(tmp_path, monkeypatch) -> None:
    codex_home = tmp_path / ".codex"
    codex_home.mkdir()
    (codex_home / "auth.json").write_text('{"ok": true}', encoding="utf-8")

    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    monkeypatch.delenv("CODEX_ACCESS_TOKEN", raising=False)
    monkeypatch.delenv("OPENAI_OAUTH_TOKEN", raising=False)
    monkeypatch.delenv("CODEX_OAUTH_TOKEN", raising=False)
    monkeypatch.setenv("CTF_HARNESS_CODEX_HOME", str(codex_home))

    assert agents.host_codex_auth_path() == codex_home / "auth.json"
    assert agents.has_codex_auth() is True
    assert agents.codex_env_summary() == "host Codex OAuth auth.json is available"


def test_docker_command_copies_agent_auth_files(tmp_path, monkeypatch) -> None:
    claude_home = tmp_path / "host-claude"
    codex_home = tmp_path / "host-codex"
    claude_home.mkdir()
    codex_home.mkdir()
    (claude_home / ".credentials.json").write_text('{"claude": true}', encoding="utf-8")
    (codex_home / "auth.json").write_text('{"codex": true}', encoding="utf-8")
    challenge_dir = tmp_path / "challenge"
    challenge_dir.mkdir()

    monkeypatch.setenv("CTF_HARNESS_CLAUDE_CONFIG_DIR", str(claude_home))
    monkeypatch.setenv("CTF_HARNESS_CODEX_HOME", str(codex_home))

    agents.docker_command(challenge_dir, ["true"], agent="claude")
    agents.docker_command(challenge_dir, ["true"], agent="codex")

    home = challenge_dir / ".agent-home"
    assert (home / ".claude" / ".credentials.json").read_text(encoding="utf-8") == '{"claude": true}'
    assert (home / ".codex" / "auth.json").read_text(encoding="utf-8") == '{"codex": true}'


def test_docker_command_does_not_mount_host_auth_dirs(tmp_path, monkeypatch) -> None:
    claude_home = tmp_path / "host-claude"
    claude_home.mkdir()
    (claude_home / ".credentials.json").write_text('{"claude": true}', encoding="utf-8")
    challenge_dir = tmp_path / "challenge"
    challenge_dir.mkdir()

    monkeypatch.setenv("CTF_HARNESS_CLAUDE_CONFIG_DIR", str(claude_home))

    command = agents.docker_command(challenge_dir, ["true"], agent="claude")
    command_text = " ".join(command)

    assert str(claude_home) not in command_text
    assert ".agent-home" in command_text


def test_claude_inner_command_uses_agent_mcp_http_config(monkeypatch) -> None:
    monkeypatch.setenv("CTF_HARNESS_AGENT_MCP_URL", "http://127.0.0.1:8000/mcp")

    command = agents.claude_inner_command("start")
    command_text = " ".join(command)

    assert "--strict-mcp-config" in command_text
    assert "--mcp-config" in command_text
    assert '"ctfsolver"' in command_text
    assert '"type":"http"' in command_text
    assert '"url":"http://127.0.0.1:8000/mcp"' in command_text
    assert "mcp__ctfsolver__*" in command_text


def test_claude_inner_command_keeps_empty_mcp_config_without_url(monkeypatch) -> None:
    monkeypatch.delenv("CTF_HARNESS_AGENT_MCP_URL", raising=False)

    command = agents.claude_inner_command("start")
    command_text = " ".join(command)

    assert "'{\"mcpServers\":{}}'" in command_text
    assert "mcp__ctfsolver__*" not in command_text


def test_docker_command_writes_codex_agent_mcp_config(tmp_path, monkeypatch) -> None:
    challenge_dir = tmp_path / "challenge"
    challenge_dir.mkdir()
    monkeypatch.setenv("CTF_HARNESS_AGENT_MCP_URL", "http://127.0.0.1:8000/mcp")

    agents.docker_command(challenge_dir, ["true"], agent="codex")

    config = challenge_dir / ".agent-home" / ".codex" / "config.toml"
    assert config.read_text(encoding="utf-8") == (
        "[mcp_servers.ctfsolver]\n"
        'url = "http://127.0.0.1:8000/mcp"\n'
    )




def test_kiro_default_secrets_count_as_auth(tmp_path, monkeypatch) -> None:
    kiro_home = tmp_path / ".kiro"
    kiro_home.mkdir()
    (kiro_home / "secrets.json").write_text('{"ok": true}', encoding="utf-8")

    for var in ("KIRO_API_KEY", "AWS_BEARER_TOKEN_BEDROCK", "AWS_PROFILE"):
        monkeypatch.delenv(var, raising=False)
    monkeypatch.setenv("CTF_HARNESS_KIRO_CONFIG_DIR", str(kiro_home))
    # Force data.sqlite3 lookup at a non-existent tmp path so the older
    # secrets.json-only path is exercised (data.sqlite3 takes precedence when present).
    monkeypatch.setenv("CTF_HARNESS_KIRO_DATA_DIR", str(tmp_path / "no-such-kiro-data"))
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("USERPROFILE", str(tmp_path))

    assert agents.host_kiro_secrets_path() == kiro_home / "secrets.json"
    assert agents.has_kiro_auth() is True
    summary = agents.kiro_env_summary()
    assert "secrets.json" in summary and "MCP-only" in summary


def test_kiro_data_sqlite_takes_precedence(tmp_path, monkeypatch) -> None:
    """When data.sqlite3 exists, it is the primary auth signal (not secrets.json)."""
    kiro_data = tmp_path / "kiro-data"
    kiro_data.mkdir()
    (kiro_data / "data.sqlite3").write_bytes(b"SQLite format 3\x00")

    for var in ("KIRO_API_KEY", "AWS_BEARER_TOKEN_BEDROCK", "AWS_PROFILE"):
        monkeypatch.delenv(var, raising=False)
    monkeypatch.setenv("CTF_HARNESS_KIRO_DATA_DIR", str(kiro_data))
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("USERPROFILE", str(tmp_path))

    assert agents.host_kiro_data_sqlite_path() == kiro_data / "data.sqlite3"
    assert agents.has_kiro_auth() is True
    summary = agents.kiro_env_summary()
    assert "data.sqlite3" in summary


def test_docker_command_copies_kiro_data_sqlite(tmp_path, monkeypatch) -> None:
    """docker_command must copy data.sqlite3 into container home (this is the real auth store)."""
    kiro_data = tmp_path / "host-kiro-data"
    kiro_data.mkdir()
    (kiro_data / "data.sqlite3").write_bytes(b"SQLite format 3\x00-fake-token-store")

    challenge_dir = tmp_path / "challenge"
    challenge_dir.mkdir()

    monkeypatch.setenv("CTF_HARNESS_KIRO_DATA_DIR", str(kiro_data))
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("USERPROFILE", str(tmp_path))

    agents.docker_command(challenge_dir, ["true"], agent="kiro")

    copied = challenge_dir / ".agent-home" / ".local" / "share" / "kiro-cli" / "data.sqlite3"
    assert copied.exists(), f"data.sqlite3 not copied to {copied}"
    assert copied.read_bytes() == b"SQLite format 3\x00-fake-token-store"


def test_opencode_default_auth_json_count_as_auth(tmp_path, monkeypatch) -> None:
    opencode_home = tmp_path / "opencode-share"
    opencode_home.mkdir()
    (opencode_home / "auth.json").write_text('{"ok": true}', encoding="utf-8")

    for var in ("OPENCODE_API_KEY", "OPENCODE_AUTH_TOKEN", "OPENCODE_OAUTH_TOKEN",
                "ANTHROPIC_API_KEY", "OPENAI_API_KEY"):
        monkeypatch.delenv(var, raising=False)
    monkeypatch.setenv("CTF_HARNESS_OPENCODE_HOME", str(opencode_home))

    assert agents.host_opencode_auth_path() == opencode_home / "auth.json"
    assert agents.has_opencode_auth() is True
    assert agents.opencode_env_summary() == "host OpenCode auth.json is available"


def test_docker_command_copies_kiro_and_opencode_auth(tmp_path, monkeypatch) -> None:
    kiro_home = tmp_path / "host-kiro"
    aws_home = tmp_path / "host-aws"
    opencode_share = tmp_path / "host-opencode-share"
    opencode_cfg = tmp_path / "host-opencode-cfg"
    for d in (kiro_home, aws_home / "sso" / "cache", opencode_share, opencode_cfg):
        d.mkdir(parents=True)
    (kiro_home / "secrets.json").write_text('{"kiro": true}', encoding="utf-8")
    (kiro_home / "argv.json").write_text('{"kiro-argv": true}', encoding="utf-8")
    (aws_home / "sso" / "cache" / "sample.json").write_text('{"aws-sso": true}', encoding="utf-8")
    (aws_home / "config").write_text("[default]\nregion=us-east-1\n", encoding="utf-8")
    (opencode_share / "auth.json").write_text('{"opencode": true}', encoding="utf-8")
    (opencode_share / "mcp-auth.json").write_text('{"opencode-mcp": true}', encoding="utf-8")
    (opencode_cfg / "opencode.json").write_text('{"cfg": true}', encoding="utf-8")

    challenge_dir = tmp_path / "challenge"
    challenge_dir.mkdir()

    monkeypatch.setenv("CTF_HARNESS_KIRO_CONFIG_DIR", str(kiro_home))
    monkeypatch.setenv("HOME", str(aws_home.parent))
    monkeypatch.setenv("USERPROFILE", str(aws_home.parent))
    monkeypatch.setenv("CTF_HARNESS_OPENCODE_HOME", str(opencode_share))

    # Point Path.home() at aws_home.parent so host_aws_dir() picks up our fixture.
    # (agents.host_aws_dir uses Path.home() / ".aws" — copy fixture accordingly.)
    real_aws = tmp_path / ".aws"
    (real_aws / "sso" / "cache").mkdir(parents=True)
    (real_aws / "sso" / "cache" / "sample.json").write_text('{"aws-sso": true}', encoding="utf-8")
    (real_aws / "config").write_text("[default]\nregion=us-east-1\n", encoding="utf-8")
    # opencode config dir uses Path.home()/.config/opencode
    real_opencode_cfg = tmp_path / ".config" / "opencode"
    real_opencode_cfg.mkdir(parents=True)
    (real_opencode_cfg / "opencode.json").write_text('{"cfg": true}', encoding="utf-8")

    agents.docker_command(challenge_dir, ["true"], agent="kiro")
    agents.docker_command(challenge_dir, ["true"], agent="opencode")

    home = challenge_dir / ".agent-home"
    assert (home / ".kiro" / "secrets.json").read_text(encoding="utf-8") == '{"kiro": true}'
    assert (home / ".kiro" / "argv.json").read_text(encoding="utf-8") == '{"kiro-argv": true}'
    assert (home / ".aws" / "sso" / "cache" / "sample.json").read_text(encoding="utf-8") == '{"aws-sso": true}'
    assert (home / ".aws" / "config").read_text(encoding="utf-8").startswith("[default]")
    assert (home / ".local" / "share" / "opencode" / "auth.json").read_text(encoding="utf-8") == '{"opencode": true}'
    assert (home / ".local" / "share" / "opencode" / "mcp-auth.json").read_text(encoding="utf-8") == '{"opencode-mcp": true}'
    assert (home / ".config" / "opencode" / "opencode.json").read_text(encoding="utf-8") == '{"cfg": true}'


def test_kiro_inner_command_probes_for_binary() -> None:
    command = agents.kiro_inner_command("start")
    joined = " ".join(command)
    assert "kiro-cli" in joined
    assert "command -v kiro-cli" in joined
    assert "chat" in joined
    assert "--no-interactive" in joined


def test_opencode_inner_command_probes_for_binary() -> None:
    command = agents.opencode_inner_command("start")
    joined = " ".join(command)
    assert "opencode" in joined
    assert "command -v opencode" in joined
    assert "run" in joined
