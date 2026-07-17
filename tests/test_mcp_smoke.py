from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

from ctf_core.smoke import count_mcp_tool_decorators, registry_count, run_smoke


def test_smoke_inventory_counts_are_preserved() -> None:
    assert count_mcp_tool_decorators() >= 71
    assert registry_count() >= 60


@pytest.mark.asyncio
async def test_smoke_challenge_roundtrip_uses_temp_runtime(tmp_path, monkeypatch) -> None:
    workspace = tmp_path / "workspace"
    db_path = tmp_path / "ctf_state.db"
    monkeypatch.setenv("CTFTOOLKIT_WORKSPACE", str(workspace))
    monkeypatch.setenv("CTFTOOLKIT_DB_PATH", str(db_path))

    report = await run_smoke(workspace=workspace, db_path=db_path)

    assert report.ok is True
    assert {check.name for check in report.checks} == {
        "mcp_tool_inventory",
        "registry_inventory",
        "mcp_surface",
        "challenge_roundtrip",
        "artifact_triage",
        "structured_result",
    }
    assert (workspace / "challenges" / "smoke-local-challenge" / "WRITEUP.md").is_file()
    assert db_path.is_file()


def test_mcp_smoke_script_outputs_json(tmp_path) -> None:
    script = Path(__file__).resolve().parents[1] / "scripts" / "mcp_smoke.py"

    result = subprocess.run(
        [
            sys.executable,
            str(script),
            "--json",
            "--workspace",
            str(tmp_path / "workspace"),
            "--db-path",
            str(tmp_path / "ctf_state.db"),
        ],
        check=True,
        capture_output=True,
        text=True,
    )

    payload = json.loads(result.stdout)
    assert payload["ok"] is True
    assert {check["name"] for check in payload["checks"]} == {
        "mcp_tool_inventory",
        "registry_inventory",
        "mcp_surface",
        "challenge_roundtrip",
        "artifact_triage",
        "structured_result",
    }
