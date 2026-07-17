from __future__ import annotations

import os

from ctf_core.registry import TOOL_REGISTRY
from ctf_harness_app.toolkit import repo_root, toolkit_env, toolkit_status_snapshot


def test_toolkit_inventory_absorbed() -> None:
    status = toolkit_status_snapshot()

    assert status["ok"] is True
    assert status["mcp_tools"] >= 114
    assert status["registry_tools"] == 72
    assert len(TOOL_REGISTRY) == 72
    assert status["skill_files"] == 33
    assert status["dockerfiles"] == 7
    assert status["schema_files"] == 2


def test_toolkit_env_points_at_flattened_solver_repo() -> None:
    root = repo_root()
    env = toolkit_env({})

    assert env["PYTHONPATH"].split(os.pathsep)[0] == str(root / "src")
    assert env["CTFTOOLKIT_WORKSPACE"] == str(root / "workspace")
    assert env["CTFTOOLKIT_DB_PATH"] == str(root / "ctf_state.db")
    assert env["CTFTOOLKIT_DOWNLOADS"] == str(root / "downloads")


def test_launchers_run_backend_and_full_stack() -> None:
    root = repo_root()
    backend = (root / "start_backend.bat").read_text(encoding="utf-8")
    full = (root / "start_full.bat").read_text(encoding="utf-8")

    assert "%ROOT%src" in backend
    assert "python -m ctf_core.server" in backend
    assert "scripts\\mcp_smoke.py" in backend
    assert "scripts\\mcp_http.py" in backend
    assert "CTF_HARNESS_AGENT_MCP_URL" in full
    assert "start_backend.bat\" --http" in full
    assert "streamlit run" in full
    assert "streamlit_app.py" in full
    assert "OneDrive" not in backend + full
    assert "01 TOOLKITS" not in backend + full


def test_solver_agents_do_not_receive_host_docker_socket() -> None:
    agents = (repo_root() / "src" / "ctf_harness_app" / "agents.py").read_text(
        encoding="utf-8"
    )

    assert "docker.sock" not in agents
    assert "/var/run/docker" not in agents
    assert "--privileged" not in agents


def test_toolkit_docker_runner_hardening_is_preserved() -> None:
    root = repo_root()
    hardening_sources = [
        root / "src" / "ctf_core" / "docker_runner.py",
        root / "src" / "ctf_core" / "jobs.py",
        root / "src" / "ctf_core" / "gdb_session.py",
        root / "src" / "ctf_core" / "ghidra_session.py",
    ]
    text = "\n".join(path.read_text(encoding="utf-8") for path in hardening_sources)

    assert 'cap_drop' in text
    assert '["ALL"]' in text
    assert "no-new-privileges:true" in text
    assert "1000:1000" in text
    assert "mem_limit" in text


def test_toolkit_reference_tests_were_preserved_but_not_active() -> None:
    reference_tests = list((repo_root() / "tests" / "toolkit_reference").rglob("*.py"))
    pyproject = (repo_root() / "pyproject.toml").read_text(encoding="utf-8")

    assert len(reference_tests) == 66
    assert 'norecursedirs = ["toolkit_reference"]' in pyproject
