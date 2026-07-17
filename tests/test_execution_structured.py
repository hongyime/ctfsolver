import hashlib
import json

import pytest

from ctf_core.evidence import evidence_log_path
from ctf_core.execution import (
    WorkspacePathError,
    log_execution_result,
    normalize_docker_result,
    resolve_workspace_path,
    simulate_read_only_tool_call,
)
from ctf_core.results import ToolResult


def test_resolve_workspace_path_normalizes_relative_and_container_paths(tmp_path):
    workspace = tmp_path / "workspace"
    sample = workspace / "files" / "sample.txt"
    sample.parent.mkdir(parents=True)
    sample.write_text("ctf\n", encoding="utf-8")

    assert resolve_workspace_path("files\\sample.txt", workspace) == sample.resolve()
    assert resolve_workspace_path("/workspace/files/sample.txt", workspace) == sample.resolve()

    with pytest.raises(WorkspacePathError, match="outside workspace"):
        resolve_workspace_path("../escape.txt", workspace)

    with pytest.raises(WorkspacePathError, match="outside workspace"):
        resolve_workspace_path("/workspace/../escape.txt", workspace)


def test_resolve_workspace_path_requires_opt_in_for_absolute_host_paths(tmp_path):
    workspace = tmp_path / "workspace"
    outside = (tmp_path / "outside.txt").resolve()
    outside.write_text("external\n", encoding="utf-8")

    with pytest.raises(WorkspacePathError, match="absolute host path"):
        resolve_workspace_path(outside, workspace)

    assert (
        resolve_workspace_path(outside, workspace, allow_absolute_host_paths=True)
        == outside
    )

    with pytest.raises(WorkspacePathError, match="drive-relative"):
        resolve_workspace_path("C:relative.txt", workspace)


def test_normalize_docker_result_applies_policy_and_preserves_context():
    result = normalize_docker_result(
        {
            "stdout": "A" * 160,
            "stderr": "partial error",
            "exit_code": -1,
            "duration": 2.5,
            "timed_out": True,
            "network_error": "dns lookup failed",
        },
        tool="nmap",
        args=["-sV", "example.com"],
        image="ctftoolkit/ctf-tools",
        target="example.com",
        challenge_id="demo-chal",
        artifacts=[{"path": "scan.xml", "kind": "xml"}],
        warnings=["fixture warning"],
        metadata={"caller": "test"},
        timeout_seconds=60,
        output_limit=96,
        env={"CTFTOOLKIT_TIMEOUT": "5", "CTFTOOLKIT_MAX_TIMEOUT": "30"},
    )

    assert isinstance(result, ToolResult)
    assert result.ok is False
    assert result.tool == "nmap"
    assert result.command == ["nmap", "-sV", "example.com"]
    assert result.exit_code == -1
    assert len(result.stdout) <= 96
    assert result.artifacts == [{"path": "scan.xml", "kind": "xml"}]
    assert "fixture warning" in result.warnings
    assert any("TRUNCATED" in warning for warning in result.warnings)
    assert any("timeout capped at 30s" == warning for warning in result.warnings)
    assert any("network issue detected" in warning for warning in result.warnings)
    assert result.metadata["container_image"] == "ctftoolkit/ctf-tools"
    assert result.metadata["target"] == "example.com"
    assert result.metadata["challenge_id"] == "demo-chal"
    assert result.metadata["duration"] == 2.5
    assert result.metadata["timed_out"] is True
    assert result.metadata["timeout"]["effective_seconds"] == 30
    assert result.metadata["stdout_truncation"]["truncated"] is True


def test_log_execution_result_records_evidence_status_image_and_hashes(tmp_path):
    workspace = tmp_path / "workspace"
    artifact = workspace / "artifact.txt"
    artifact.parent.mkdir(parents=True)
    artifact_bytes = b"structured evidence\n"
    artifact.write_bytes(artifact_bytes)

    result = simulate_read_only_tool_call(
        "strings",
        ["artifact.txt"],
        stdout="flag{demo}\n",
        image="ctftoolkit/ctf-tools",
        target="artifact.txt",
        challenge_id="demo-chal",
        artifacts=[{"path": "artifact.txt", "kind": "text"}],
    )

    event = log_execution_result(workspace, result, files=["artifact.txt"])

    log_path = evidence_log_path(workspace)
    assert log_path.exists()
    written = json.loads(log_path.read_text(encoding="utf-8").splitlines()[0])

    assert written == event
    assert written["event_type"] == "tool_result"
    assert written["challenge_id"] == "demo-chal"
    assert written["command"] == ["strings", "artifact.txt"]
    assert written["target"] == "artifact.txt"
    assert written["result_summary"]["ok"] is True
    assert written["artifacts"] == [{"path": "artifact.txt", "kind": "text"}]
    assert written["metadata"]["status"] == "ok"
    assert written["metadata"]["container_image"] == "ctftoolkit/ctf-tools"
    assert written["file_hashes"] == [
        {
            "path": "artifact.txt",
            "sha256": hashlib.sha256(artifact_bytes).hexdigest(),
            "size": len(artifact_bytes),
        }
    ]


def test_simulate_read_only_tool_call_returns_structured_schema_without_docker():
    result = simulate_read_only_tool_call(
        "file",
        ["sample.bin"],
        stdout="sample.bin: data\n",
        target="sample.bin",
        challenge_id="demo-chal",
    )

    data = result.to_dict()
    assert data["ok"] is True
    assert data["tool"] == "file"
    assert data["command"] == ["file", "sample.bin"]
    assert data["stdout"] == "sample.bin: data\n"
    assert data["metadata"]["simulated"] is True
    assert data["metadata"]["read_only"] is True
    assert data["metadata"]["target"] == "sample.bin"
    assert data["metadata"]["challenge_id"] == "demo-chal"
    assert any("Docker was not invoked" in warning for warning in data["warnings"])
