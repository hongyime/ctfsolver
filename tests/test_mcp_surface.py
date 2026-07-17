from __future__ import annotations

import json
from pathlib import Path

import pytest

from ctf_core import server


def test_inventory_resource_reports_backend_counts() -> None:
    payload = json.loads(server.resource_inventory())
    counts = payload["counts"]

    assert counts["mcp_tools"] >= 77
    assert counts["registry_tools"] >= 60
    assert counts["skill_docs"] >= 33
    assert counts["dockerfiles"] >= 6
    assert counts["schemas"] >= 2
    assert "run_backend_smoke" in payload["inventory"]["mcp_tools"]
    assert "set_target_scope" in payload["inventory"]["mcp_tools"]
    assert "suggest_next_tools" in payload["inventory"]["mcp_tools"]
    assert "triage_artifact" in payload["inventory"]["mcp_tools"]


def test_playbook_and_skill_resources_are_available() -> None:
    playbooks = json.loads(server.resource_playbooks())
    skills = json.loads(server.resource_skills())

    assert isinstance(playbooks, list)
    assert len(playbooks) >= 1
    assert skills["count"] >= 33
    assert "skills/web/ctf-web-sqli.md" in skills["paths"]


def test_category_prompts_include_operational_guidance() -> None:
    prompt = server.prompt_web(
        challenge="login bypass",
        target="https://example.invalid",
        files="source.zip",
    )

    assert "web CTF challenge" in prompt
    assert "create" in prompt
    assert "record findings" in prompt
    assert "https://example.invalid" in prompt
    assert "source.zip" in prompt


@pytest.mark.asyncio
async def test_target_scope_tools_use_workspace_state(tmp_path, monkeypatch) -> None:
    monkeypatch.setattr(server, "_workspace_root", lambda: Path(tmp_path))

    saved = json.loads(
        await server.set_target_scope(
            "https://Example.COM:8443/login, 10.20.0.0/24",
            notes="authorized challenge",
        )
    )
    loaded = json.loads(await server.get_target_scope())
    allowed = json.loads(await server.check_target_scope("https://sub.example.com/admin"))
    denied = json.loads(await server.check_target_scope("https://example.org/admin"))

    assert saved["allowed_targets"] == ["example.com", "10.20.0.0/24"]
    assert loaded["metadata"]["notes"] == "authorized challenge"
    assert allowed["allowed"] is True
    assert denied["allowed"] is False


@pytest.mark.asyncio
async def test_network_tools_block_out_of_scope_before_docker(tmp_path, monkeypatch) -> None:
    monkeypatch.setattr(server, "_workspace_root", lambda: Path(tmp_path))
    monkeypatch.setattr(server, "docker_runner", None)

    nmap_result = await server.run_nmap("scanme.example")
    scan_result = await server.start_scan("nmap", "-sV scanme.example")
    spiderfoot_result = await server.run_spiderfoot("scanme.example")
    harvester_result = await server.run_harvester("scanme.example")

    assert "Target out of scope" in nmap_result
    assert "Target out of scope" in scan_result
    assert "Target out of scope" in spiderfoot_result
    assert "Target out of scope" in harvester_result
    assert server.docker_runner is None


@pytest.mark.asyncio
async def test_challenge_tools_write_evidence_events(tmp_path, monkeypatch) -> None:
    from ctf_core import db as db_module
    from ctf_core import docker_runner as docker_runner_module

    workspace = tmp_path / "workspace"
    db_path = tmp_path / "ctf_state.db"
    db_module.DEFAULT_DB_PATH = db_path
    docker_runner_module.WORKSPACE_PATH = workspace
    monkeypatch.setenv("CTFTOOLKIT_WORKSPACE", str(workspace))
    monkeypatch.setenv("CTFTOOLKIT_DB_PATH", str(db_path))
    monkeypatch.setattr(server, "_workspace_root", lambda: workspace)
    await db_module.close_database()
    await db_module.init_database(db_path)
    await db_module.migrate_database(db_path)

    sample = tmp_path / "sample.txt"
    sample.write_text("flag{demo}\n", encoding="utf-8")
    created = await server.create_challenge("evidence demo", category="misc")
    challenge_id = created.splitlines()[0].split("=", 1)[1]

    await server.ingest_challenge_file(challenge_id, str(sample))
    await server.record_challenge_finding(challenge_id, "flag", "flag{demo}", notes="unit test")

    events_path = workspace / "evidence" / "events.jsonl"
    events = [json.loads(line) for line in events_path.read_text(encoding="utf-8").splitlines()]

    assert [event["event_type"] for event in events] == [
        "artifact_ingested",
        "finding_recorded",
    ]
    assert events[0]["challenge_id"] == challenge_id
    assert events[1]["metadata"]["notes"] == "unit test"

    await db_module.close_database()


@pytest.mark.asyncio
async def test_suggest_next_tools_mcp_wrapper_returns_ranked_json() -> None:
    payload = json.loads(
        await server.suggest_next_tools(
            description="JWT cookie and SQL injection in login form",
            category="web",
            target="https://challenge.local",
            files="app.py, routes.py",
            findings="union select, token",
            limit=5,
        )
    )

    tools = [item["tool"] for item in payload]
    assert "run_sqlmap" in tools
    assert "run_jwt_tool" in tools


@pytest.mark.asyncio
async def test_triage_artifact_mcp_wrapper_records_evidence(tmp_path, monkeypatch) -> None:
    workspace = tmp_path / "workspace"
    sample = workspace / "files" / "image.png"
    sample.parent.mkdir(parents=True)
    sample.write_bytes(b"\x89PNG\r\n\x1a\nhidden CTF{demo}\x00")
    monkeypatch.setattr(server, "_workspace_root", lambda: workspace)

    payload = json.loads(await server.triage_artifact("files/image.png", challenge_id="demo"))
    blocked = await server.triage_artifact("../escape.txt")

    assert payload["suffix"] == ".png"
    assert "png image" in payload["type_hints"]
    assert payload["recommended_next_tools"]
    assert "path escapes workspace" in blocked

    events_path = workspace / "evidence" / "events.jsonl"
    events = [json.loads(line) for line in events_path.read_text(encoding="utf-8").splitlines()]
    assert events[0]["event_type"] == "artifact_triaged"
    assert events[0]["challenge_id"] == "demo"
