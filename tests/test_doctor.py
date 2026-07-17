from __future__ import annotations

import json
import subprocess
from pathlib import Path
from typing import Sequence

from ctf_core import doctor


AUTH_ENV_VARS = (
    "ANTHROPIC_API_KEY",
    "ANTHROPIC_AUTH_TOKEN",
    "CLAUDE_CODE_OAUTH_TOKEN",
    "OPENAI_API_KEY",
    "CODEX_ACCESS_TOKEN",
    "OPENAI_OAUTH_TOKEN",
    "CODEX_OAUTH_TOKEN",
)


def _write_mcp_config(path: Path, root: Path) -> None:
    config = {
        "mcpServers": {
            "ctfsolver": {
                "command": "uv",
                "args": [
                    "--directory",
                    str(root),
                    "run",
                    "python",
                    "-m",
                    "ctf_core.server",
                ],
                "env": {
                    "CTFTOOLKIT_WORKSPACE": str(root / "workspace"),
                    "CTFTOOLKIT_DB_PATH": str(root / "ctf_state.db"),
                },
            }
        }
    }
    path.write_text(json.dumps(config), encoding="utf-8")


def _make_project_root(tmp_path: Path) -> Path:
    root = tmp_path / "repo"
    (root / "src" / "ctf_core").mkdir(parents=True)
    (root / "src" / "ctf_core" / "server.py").write_text("# test fixture\n", encoding="utf-8")
    (root / "docker-compose.yml").write_text("services: {}\n", encoding="utf-8")
    for name in ("ctf-tools", "ctf-pwn", "ctf-forensics", "ctf-re", "ctf-crypto", "ctf-sage"):
        docker_dir = root / "docker" / name
        docker_dir.mkdir(parents=True)
        (docker_dir / "Dockerfile").write_text("FROM scratch\n", encoding="utf-8")
    _write_mcp_config(root / "mcp.json", root)
    _write_mcp_config(root / "mcp-windows.json", root)
    return root


def _clear_auth(monkeypatch, tmp_path: Path) -> None:
    for name in AUTH_ENV_VARS:
        monkeypatch.delenv(name, raising=False)
    claude_home = tmp_path / "claude"
    codex_home = tmp_path / "codex"
    claude_home.mkdir()
    codex_home.mkdir()
    monkeypatch.setenv("CTF_HARNESS_CLAUDE_CONFIG_DIR", str(claude_home))
    monkeypatch.setenv("CTF_HARNESS_CODEX_HOME", str(codex_home))


def _set_env_auth(monkeypatch) -> None:
    monkeypatch.setenv("ANTHROPIC_API_KEY", "test-claude")
    monkeypatch.setenv("OPENAI_API_KEY", "test-codex")


def _fake_tooling(monkeypatch, *, docker_available: bool = True, image_returncode: int = 0) -> list[tuple[str, ...]]:
    calls: list[tuple[str, ...]] = []

    def fake_which(command: str) -> str | None:
        if command == "uv":
            return "uv"
        if command == "docker" and docker_available:
            return "docker"
        return None

    def fake_run(args: Sequence[str], *, timeout: int = 10) -> subprocess.CompletedProcess[str]:
        del timeout
        argv = tuple(str(arg) for arg in args)
        calls.append(argv)
        if argv == ("uv", "--version"):
            return subprocess.CompletedProcess(argv, 0, "uv 0.8.0\n", "")
        if argv == ("docker", "info", "--format", "{{.ServerVersion}}"):
            return subprocess.CompletedProcess(argv, 0, "27.5.0\n", "")
        if argv == ("docker", "compose", "version"):
            return subprocess.CompletedProcess(argv, 0, "Docker Compose version v2.32.0\n", "")
        if len(argv) == 4 and argv[:3] == ("docker", "image", "inspect"):
            stderr = "" if image_returncode == 0 else "missing"
            return subprocess.CompletedProcess(argv, image_returncode, "", stderr)
        return subprocess.CompletedProcess(argv, 1, "", "unexpected command")

    monkeypatch.setattr(doctor, "_which", fake_which)
    monkeypatch.setattr(doctor, "_run_command", fake_run)
    return calls


def _result(report: doctor.DoctorReport, name: str) -> doctor.CheckResult:
    matches = [check for check in report.checks if check.name == name]
    assert matches, f"missing doctor result {name!r}"
    return matches[0]


def test_missing_agent_auth_is_warning_only(tmp_path, monkeypatch) -> None:
    root = _make_project_root(tmp_path)
    _clear_auth(monkeypatch, tmp_path)
    _fake_tooling(monkeypatch)

    report = doctor.run_doctor(project_root=root, workspace=root / "workspace")

    assert report.exit_code == 0
    assert _result(report, "Claude auth").status == doctor.STATUS_WARN
    assert _result(report, "Codex auth").status == doctor.STATUS_WARN
    assert _result(report, "Docker images").status == doctor.STATUS_PASS


def test_docker_unavailable_skips_image_probe(tmp_path, monkeypatch) -> None:
    root = _make_project_root(tmp_path)
    _clear_auth(monkeypatch, tmp_path)
    _set_env_auth(monkeypatch)
    calls = _fake_tooling(monkeypatch, docker_available=False)

    report = doctor.run_doctor(project_root=root, workspace=root / "workspace")

    assert report.exit_code == 1
    assert _result(report, "Docker daemon").status == doctor.STATUS_FAIL
    assert _result(report, "Docker Compose").status == doctor.STATUS_FAIL
    assert _result(report, "Docker images").status == doctor.STATUS_SKIP
    assert not any(call[:3] == ("docker", "image", "inspect") for call in calls)


def test_invalid_mcp_template_is_a_hard_failure(tmp_path, monkeypatch) -> None:
    root = _make_project_root(tmp_path)
    (root / "mcp.json").write_text("{}", encoding="utf-8")
    _clear_auth(monkeypatch, tmp_path)
    _set_env_auth(monkeypatch)
    _fake_tooling(monkeypatch)

    report = doctor.run_doctor(project_root=root, workspace=root / "workspace")

    assert report.exit_code == 1
    assert _result(report, "MCP config templates").status == doctor.STATUS_FAIL


def test_launcher_batches_wire_doctor() -> None:
    root = Path(__file__).resolve().parents[1]
    backend = (root / "start_backend.bat").read_text(encoding="utf-8")
    setup_mcp = (root / "setup_mcp.bat").read_text(encoding="utf-8")

    assert "--doctor" in backend
    assert "--smoke" in backend
    assert "scripts\\doctor.py" in backend
    assert "scripts\\setup.py --write --auth-check" in setup_mcp
    assert "scripts\\doctor.py" in setup_mcp
