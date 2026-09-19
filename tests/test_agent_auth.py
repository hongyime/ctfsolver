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




# ---- Agent fallback + IAM key pool tests ----


def test_resolve_available_agent_honours_preference(tmp_path, monkeypatch) -> None:
    """When preferred agent has auth, it wins over the fallback order."""
    for var in ("OPENAI_API_KEY", "CODEX_ACCESS_TOKEN", "KIRO_API_KEY",
                "AWS_BEARER_TOKEN_BEDROCK", "AWS_PROFILE",
                "OPENCODE_API_KEY", "OPENCODE_AUTH_TOKEN",
                "ANTHROPIC_API_KEY", "ANTHROPIC_AUTH_TOKEN", "CLAUDE_CODE_OAUTH_TOKEN"):
        monkeypatch.delenv(var, raising=False)
    # Only claude authed
    claude = tmp_path / ".claude"; claude.mkdir()
    (claude / ".credentials.json").write_text("{}", encoding="utf-8")
    monkeypatch.setenv("CTF_HARNESS_CLAUDE_CONFIG_DIR", str(claude))
    monkeypatch.setenv("CTF_HARNESS_KIRO_DATA_DIR", str(tmp_path / "no-kiro-data"))
    monkeypatch.setenv("CTF_HARNESS_KIRO_CONFIG_DIR", str(tmp_path / "no-kiro"))
    monkeypatch.setenv("CTF_HARNESS_OPENCODE_HOME", str(tmp_path / "no-opencode"))
    monkeypatch.setenv("CTF_HARNESS_CODEX_HOME", str(tmp_path / "no-codex"))
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("USERPROFILE", str(tmp_path))

    assert agents.resolve_available_agent(preferred="claude") == "claude"
    # Fallback path: no preference, still gets claude
    assert agents.resolve_available_agent(preferred=None) == "claude"


def test_resolve_available_agent_walks_fallback(tmp_path, monkeypatch) -> None:
    """When preferred is unavailable, walk AGENT_FALLBACK_ORDER."""
    for var in ("OPENAI_API_KEY", "CODEX_ACCESS_TOKEN", "KIRO_API_KEY",
                "AWS_BEARER_TOKEN_BEDROCK", "AWS_PROFILE",
                "OPENCODE_API_KEY", "OPENCODE_AUTH_TOKEN",
                "ANTHROPIC_API_KEY", "ANTHROPIC_AUTH_TOKEN", "CLAUDE_CODE_OAUTH_TOKEN",
                "CTF_HARNESS_AGENT_FALLBACK_ORDER"):
        monkeypatch.delenv(var, raising=False)
    codex_home = tmp_path / ".codex"; codex_home.mkdir()
    (codex_home / "auth.json").write_text("{}", encoding="utf-8")
    monkeypatch.setenv("CTF_HARNESS_CODEX_HOME", str(codex_home))
    monkeypatch.setenv("CTF_HARNESS_KIRO_DATA_DIR", str(tmp_path / "no-kiro-data"))
    monkeypatch.setenv("CTF_HARNESS_KIRO_CONFIG_DIR", str(tmp_path / "no-kiro"))
    monkeypatch.setenv("CTF_HARNESS_OPENCODE_HOME", str(tmp_path / "no-opencode"))
    monkeypatch.setenv("CTF_HARNESS_CLAUDE_CONFIG_DIR", str(tmp_path / "no-claude"))
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("USERPROFILE", str(tmp_path))

    # Prefer kiro but kiro/opencode/claude are all unavailable → fall back to codex
    assert agents.resolve_available_agent(preferred="kiro") == "codex"


def test_resolve_available_agent_raises_when_nothing_authed(tmp_path, monkeypatch) -> None:
    from ctf_harness_app.util import HarnessError
    for var in ("OPENAI_API_KEY", "CODEX_ACCESS_TOKEN", "KIRO_API_KEY",
                "AWS_BEARER_TOKEN_BEDROCK", "AWS_PROFILE",
                "OPENCODE_API_KEY", "OPENCODE_AUTH_TOKEN",
                "ANTHROPIC_API_KEY", "ANTHROPIC_AUTH_TOKEN", "CLAUDE_CODE_OAUTH_TOKEN"):
        monkeypatch.delenv(var, raising=False)
    for var in ("CTF_HARNESS_CLAUDE_CONFIG_DIR", "CTF_HARNESS_CODEX_HOME",
                "CTF_HARNESS_KIRO_CONFIG_DIR", "CTF_HARNESS_KIRO_DATA_DIR",
                "CTF_HARNESS_OPENCODE_HOME"):
        monkeypatch.setenv(var, str(tmp_path / f"no-{var}"))
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("USERPROFILE", str(tmp_path))

    import pytest
    with pytest.raises(HarnessError):
        agents.resolve_available_agent(preferred=None)


def test_iam_key_pool_selection_is_deterministic(tmp_path, monkeypatch) -> None:
    """Same (challenge, agent) always picks the same key; different pairs distribute."""
    import json
    from ctf_harness_app.iam_key_pool import load_pool, select_key_for
    pool_file = tmp_path / "pool.json"
    pool_file.write_text(json.dumps({
        "region": "ap-southeast-1",
        "keys": [
            {"label": f"key-{i}", "access_key_id": f"AKIA{i:016d}", "secret_access_key": f"s{i}",
             "account": "111", "arn": f"arn:...user/key-{i}", "bedrock_ok": True}
            for i in range(4)
        ],
    }), encoding="utf-8")
    monkeypatch.setenv("CTF_HARNESS_IAM_KEY_POOL", str(pool_file))
    keys = load_pool()
    assert len(keys) == 4

    a1 = select_key_for("0001-web-flag", "opencode", keys)
    a2 = select_key_for("0001-web-flag", "opencode", keys)
    assert a1 == a2  # deterministic

    # Different challenges spread (statistically — with 20 slugs across 4 keys they should hit multiple)
    picks = {select_key_for(f"chal-{i}", "opencode", keys).label for i in range(20)}
    assert len(picks) >= 2, f"pool distribution too narrow: {picks}"


def test_iam_pool_env_args_only_for_bedrock_agents(tmp_path, monkeypatch) -> None:
    """iam_pool_env_args returns empty for claude/codex, entries for opencode/kiro."""
    import json
    pool_file = tmp_path / "pool.json"
    pool_file.write_text(json.dumps({
        "region": "ap-southeast-1",
        "keys": [{"label": "k1", "access_key_id": "AKIA_TESTKEY", "secret_access_key": "SECRET",
                  "account": "111", "arn": "arn:...user/k1", "bedrock_ok": True}],
    }), encoding="utf-8")
    monkeypatch.setenv("CTF_HARNESS_IAM_KEY_POOL", str(pool_file))

    # Bedrock agents: get keys forwarded
    args, picked = agents.iam_pool_env_args("chal-1", "opencode")
    assert picked is not None and picked.label == "k1"
    args_str = " ".join(args)
    assert "AWS_ACCESS_KEY_ID=AKIA_TESTKEY" in args_str
    assert "AWS_SECRET_ACCESS_KEY=SECRET" in args_str
    assert "AWS_REGION=ap-southeast-1" in args_str

    args, picked = agents.iam_pool_env_args("chal-1", "kiro")
    assert picked is not None

    # Non-Bedrock agents: no pool args
    args, picked = agents.iam_pool_env_args("chal-1", "claude")
    assert args == [] and picked is None
    args, picked = agents.iam_pool_env_args("chal-1", "codex")
    assert args == [] and picked is None


def test_docker_command_layers_pool_keys_over_env(tmp_path, monkeypatch) -> None:
    """docker_command must append pool-selected AWS creds after docker_env_args
    so the pool key wins (last-write-wins on -e)."""
    import json
    pool_file = tmp_path / "pool.json"
    pool_file.write_text(json.dumps({
        "region": "ap-southeast-1",
        "keys": [{"label": "k1", "access_key_id": "AKIA_POOL", "secret_access_key": "POOLSECRET",
                  "account": "111", "arn": "arn:...user/k1", "bedrock_ok": True}],
    }), encoding="utf-8")
    monkeypatch.setenv("CTF_HARNESS_IAM_KEY_POOL", str(pool_file))
    # Host has different creds set
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "AKIA_HOST")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "HOSTSECRET")

    challenge_dir = tmp_path / "chal"
    challenge_dir.mkdir()
    cmd = agents.docker_command(challenge_dir, ["true"], agent="opencode")

    # Find last -e AWS_ACCESS_KEY_ID=... occurrence
    aws_positions = [i for i, a in enumerate(cmd) if isinstance(a, str) and a.startswith("AWS_ACCESS_KEY_ID=")]
    assert len(aws_positions) >= 1
    last = cmd[aws_positions[-1]]
    assert last == "AWS_ACCESS_KEY_ID=AKIA_POOL", f"pool key must be last, got: {last}"




# ---- run_streaming_agent threading-based reader (Windows-safe) ----


def test_run_streaming_agent_captures_stdout_via_thread(tmp_path, monkeypatch) -> None:
    """The threading-based reader should capture all stdout regardless of platform."""
    import sys as _sys, textwrap as _tw
    from ctf_harness_app.ctfd import Challenge
    from ctf_harness_app.workspace import ensure_state
    import json as _json

    challenge_dir = tmp_path / "chal"
    challenge_dir.mkdir()
    challenge = Challenge(
        id=1, name="stream-test", category="test", value=1, description="",
        connection_info=None, files=[], tags=[], hints=[], raw={},
    )
    (challenge_dir / "metadata.json").write_text(_json.dumps({
        "id": 1, "name": "stream-test", "category": "test", "description": "",
        "value": 1, "tags": [], "hints": [], "files": [], "connection_info": None,
        "slug": challenge.slug, "downloaded_files": [],
    }), encoding="utf-8")
    ensure_state(challenge_dir, challenge, [])

    # Command that emits several lines then exits — no docker, just python.
    inner = [_sys.executable, "-u", "-c",
             "import sys, time\nfor i in range(3):\n    print(f'chunk-{i}', flush=True)\n    time.sleep(0.05)"]
    rc = agents.run_streaming_agent(
        challenge_dir=challenge_dir, agent="test", action="start",
        prompt="fixture prompt", command=inner,
        env_summary="fixture env", log_filename="test.log", last_filename="test-last.txt",
    )
    assert rc == 0
    log_text = (challenge_dir / "test.log").read_text(encoding="utf-8", errors="replace")
    for i in range(3):
        assert f"chunk-{i}" in log_text, f"missing chunk-{i} in log; got: {log_text!r}"
    last_text = (challenge_dir / "test-last.txt").read_text(encoding="utf-8", errors="replace")
    assert "chunk-2" in last_text


def test_run_streaming_agent_nonzero_exit_propagates(tmp_path) -> None:
    from ctf_harness_app.ctfd import Challenge
    from ctf_harness_app.workspace import ensure_state
    import sys as _sys, json as _json

    challenge_dir = tmp_path / "chal"
    challenge_dir.mkdir()
    challenge = Challenge(
        id=2, name="exit-test", category="test", value=1, description="",
        connection_info=None, files=[], tags=[], hints=[], raw={},
    )
    (challenge_dir / "metadata.json").write_text(_json.dumps({
        "id": 2, "name": "exit-test", "category": "test", "description": "",
        "value": 1, "tags": [], "hints": [], "files": [], "connection_info": None,
        "slug": challenge.slug, "downloaded_files": [],
    }), encoding="utf-8")
    ensure_state(challenge_dir, challenge, [])

    inner = [_sys.executable, "-c", "import sys; sys.stdout.write('bye\\n'); sys.exit(7)"]
    rc = agents.run_streaming_agent(
        challenge_dir=challenge_dir, agent="test", action="start",
        prompt="p", command=inner, env_summary="e",
        log_filename="test.log", last_filename="test-last.txt",
    )
    assert rc == 7
    assert "bye" in (challenge_dir / "test.log").read_text(encoding="utf-8")




# ---- run_auto_with_fallback (retry on infra failure) ----


def test_log_indicates_infra_failure_detects_signals(tmp_path):
    (tmp_path / "kiro.log").write_text(
        "some stuff\n[ctf-harness] kiro-cli not found in ctf-ai-solver image\ndone",
        encoding="utf-8",
    )
    is_infra, signal = agents._log_indicates_infra_failure(tmp_path, "kiro")
    assert is_infra is True
    assert "kiro-cli not found" in signal


def test_log_indicates_infra_failure_ignores_challenge_errors(tmp_path):
    (tmp_path / "claude.log").write_text(
        "I tried to reverse-engineer the binary but couldn't find the flag.\n"
        "Multiple approaches failed. Giving up for now.\n",
        encoding="utf-8",
    )
    is_infra, signal = agents._log_indicates_infra_failure(tmp_path, "claude")
    assert is_infra is False


def test_log_indicates_infra_failure_no_log(tmp_path):
    is_infra, signal = agents._log_indicates_infra_failure(tmp_path, "opencode")
    assert is_infra is False
    assert signal == ""


def test_run_auto_with_fallback_skips_unavailable(tmp_path, monkeypatch):
    """When kiro is unavailable, fallback should try opencode next without
    invoking kiro at all."""
    calls: list[str] = []

    def fake_kiro(*a, **kw):
        calls.append("kiro"); return 0
    def fake_opencode(*a, **kw):
        calls.append("opencode"); return 0

    monkeypatch.setattr(agents, "agent_availability", lambda: {
        "claude": False, "codex": False, "kiro": False, "opencode": True,
    })
    monkeypatch.setitem(agents.AGENT_DISPATCH, "kiro", fake_kiro)
    monkeypatch.setitem(agents.AGENT_DISPATCH, "opencode", fake_opencode)

    final_agent, rc, attempts = agents.run_auto_with_fallback(tmp_path, "start")
    assert final_agent == "opencode"
    assert rc == 0
    assert "kiro" not in calls
    assert "opencode" in calls
    # Kiro was skipped due to unavailable, opencode succeeded
    assert any(a for a, _, _ in attempts if a == "kiro" and "unavailable" in _.split(":")[0].lower() or "unavailable" in _)


def test_run_auto_with_fallback_retries_on_infra_signal(tmp_path, monkeypatch):
    """If kiro fails with an infra signal in its log, we retry with the next."""
    challenge_dir = tmp_path / "chal"
    challenge_dir.mkdir()

    def fake_kiro(cd, *a, **kw):
        # Simulate kiro failing with CLI-missing signal
        (cd / "kiro.log").write_text("[ctf-harness] kiro-cli not found\n", encoding="utf-8")
        return 127
    def fake_opencode(cd, *a, **kw):
        return 0

    monkeypatch.setattr(agents, "agent_availability", lambda: {
        "claude": False, "codex": False, "kiro": True, "opencode": True,
    })
    monkeypatch.setitem(agents.AGENT_DISPATCH, "kiro", fake_kiro)
    monkeypatch.setitem(agents.AGENT_DISPATCH, "opencode", fake_opencode)

    final_agent, rc, attempts = agents.run_auto_with_fallback(challenge_dir, "start")
    assert final_agent == "opencode"
    assert rc == 0
    labels = [a for a, _, _ in attempts]
    assert labels[0] == "kiro"
    assert labels[1] == "opencode"
    assert "infra" in attempts[0][2]


def test_run_auto_with_fallback_does_not_retry_on_agent_failure(tmp_path, monkeypatch):
    """If the agent runs and just can't solve, don't burn other agents' time."""
    challenge_dir = tmp_path / "chal"
    challenge_dir.mkdir()

    def fake_claude(cd, *a, **kw):
        # Real content of the CTF attempt; no infra signal
        (cd / "claude.log").write_text(
            "I tried several exploits but could not find the flag.\n",
            encoding="utf-8",
        )
        return 1
    other_called = []
    def fake_codex(cd, *a, **kw):
        other_called.append("codex"); return 0

    monkeypatch.setattr(agents, "agent_availability", lambda: {
        "claude": True, "codex": True, "kiro": False, "opencode": False,
    })
    monkeypatch.setitem(agents.AGENT_DISPATCH, "claude", fake_claude)
    monkeypatch.setitem(agents.AGENT_DISPATCH, "codex", fake_codex)

    final_agent, rc, attempts = agents.run_auto_with_fallback(
        challenge_dir, "start", preferred="claude",
    )
    assert final_agent == "claude"
    assert rc == 1
    # Codex should NOT have been called
    assert other_called == []
