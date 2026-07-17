from __future__ import annotations

from pathlib import Path

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
