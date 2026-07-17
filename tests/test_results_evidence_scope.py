import hashlib
import json
from pathlib import Path

from ctf_core.evidence import append_evidence_event, collect_file_hashes, evidence_log_path
from ctf_core.results import ToolResult
from ctf_core.scope import (
    is_target_allowed,
    load_allowed_targets,
    normalize_target,
    save_allowed_targets,
    scope_state_path,
)


def test_tool_result_serializes_to_dict_json_and_markdown():
    result = ToolResult.success(
        "strings",
        ["strings", "sample.bin"],
        stdout="flag{demo}\n",
        artifacts=[{"path": Path("out.txt"), "kind": "text"}],
        findings=["flag{demo}"],
        warnings=["truncated output"],
        next_steps=["verify flag format"],
        metadata={"workspace": Path("workspace/chal")},
    )

    data = result.to_dict()
    assert data["ok"] is True
    assert data["command"] == ["strings", "sample.bin"]
    assert data["artifacts"][0]["path"] == "out.txt"
    assert data["metadata"]["workspace"] == "workspace/chal"

    decoded = json.loads(result.to_json())
    assert decoded == data

    markdown = result.to_markdown()
    assert "### strings" in markdown
    assert "- Status: ok" in markdown
    assert "`strings sample.bin`" in markdown
    assert "flag{demo}" in markdown


def test_evidence_event_append_creates_jsonl_path(tmp_path):
    workspace = tmp_path / "missing" / "workspace"
    result = ToolResult.failure(
        "nmap",
        ["nmap", "-sV", "example.com"],
        exit_code=1,
        stderr="host down",
        warnings=["offline fixture"],
    )

    event = append_evidence_event(
        workspace,
        "tool_run",
        challenge_id="demo-chal",
        tool=result.tool,
        command=result.command,
        target="https://example.com/login",
        file_hashes=[{"path": "manual.txt", "sha256": "abc123"}],
        result=result,
        artifacts=["scan.json"],
        metadata={"container_image": "ctftoolkit/ctf-web:test"},
    )

    log_path = evidence_log_path(workspace)
    assert log_path.exists()
    lines = log_path.read_text(encoding="utf-8").splitlines()
    assert len(lines) == 1

    written = json.loads(lines[0])
    assert written == event
    assert written["event_type"] == "tool_run"
    assert written["challenge_id"] == "demo-chal"
    assert written["result_summary"]["ok"] is False
    assert written["result_summary"]["exit_code"] == 1
    assert written["file_hashes"] == [{"path": "manual.txt", "sha256": "abc123"}]
    assert written["metadata"]["container_image"] == "ctftoolkit/ctf-web:test"


def test_collect_file_hashes_records_sha256(tmp_path):
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    sample = workspace / "sample.txt"
    sample_bytes = b"ctf evidence\n"
    sample.write_bytes(sample_bytes)

    records = collect_file_hashes(["sample.txt"], workspace=workspace)

    assert records == [
        {
            "path": "sample.txt",
            "sha256": hashlib.sha256(sample_bytes).hexdigest(),
            "size": len(sample_bytes),
        }
    ]


def test_scope_save_load_and_allow_deny_behavior(tmp_path):
    workspace = tmp_path / "workspace"
    state = save_allowed_targets(
        workspace,
        ["HTTPS://Example.COM:8443/login", "10.10.0.0/24", "*.ctf.local"],
        metadata={"challenge_id": "demo-chal"},
    )

    assert scope_state_path(workspace).exists()
    assert state["allowed_targets"] == ["example.com", "10.10.0.0/24", "*.ctf.local"]
    assert load_allowed_targets(workspace) == state["allowed_targets"]

    assert normalize_target("https://Sub.Example.com/admin") == "sub.example.com"
    assert normalize_target("10.10.0.5") == "10.10.0.5"
    assert is_target_allowed("https://sub.example.com/admin", workspace=workspace)
    assert is_target_allowed("10.10.0.42", workspace=workspace)
    assert is_target_allowed("api.ctf.local", workspace=workspace)

    assert not is_target_allowed("https://example.org", workspace=workspace)
    assert not is_target_allowed("10.10.1.42", workspace=workspace)
    assert not is_target_allowed("ctf.local", workspace=workspace)
