from __future__ import annotations

import importlib.util
import io
import json
import subprocess
import sys
from pathlib import Path
from typing import Sequence

from ctf_core import docker_status
from ctf_core import tool_policy


PROJECT_ROOT = Path(__file__).resolve().parents[1]


def load_update_tools_module():
    script = PROJECT_ROOT / "scripts" / "update_tools.py"
    spec = importlib.util.spec_from_file_location("ctfsolver_update_tools", script)
    assert spec is not None
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def test_discover_image_definitions_groups_registry_binaries() -> None:
    definitions = docker_status.discover_image_definitions(PROJECT_ROOT)
    by_image = {definition.image: definition for definition in definitions}

    assert "ctftoolkit/ctf-tools" in by_image
    assert "ctftoolkit/ctf-sage" in by_image
    assert by_image["ctftoolkit/ctf-tools"].dockerfile == "docker/ctf-tools/Dockerfile"
    assert by_image["ctftoolkit/ctf-tools"].service == "ctf-tools"
    assert "nmap" in by_image["ctftoolkit/ctf-tools"].expected_binaries
    assert "nuclei" in by_image["ctftoolkit/ctf-tools"].expected_binaries
    assert by_image["ctftoolkit/ctf-sage"].lazy is True


def test_status_matrix_warns_when_docker_is_missing(monkeypatch) -> None:
    monkeypatch.setattr(docker_status, "_which", lambda command: None)

    matrix = docker_status.build_status_matrix(PROJECT_ROOT)

    assert matrix.docker_available is False
    assert matrix.warnings == ("docker executable was not found; local image state is unknown",)
    assert matrix.images
    assert all(row.exists is None for row in matrix.images)
    assert all(row.missing is None for row in matrix.images)


def test_status_matrix_uses_fake_docker_inspect_and_marks_missing_stale(monkeypatch) -> None:
    def fake_which(command: str) -> str | None:
        return "docker" if command == "docker" else None

    def fake_run(args: Sequence[str], *, timeout: int) -> subprocess.CompletedProcess[str]:
        del timeout
        argv = tuple(str(arg) for arg in args)
        if argv == ("docker", "info", "--format", "{{.ServerVersion}}"):
            return subprocess.CompletedProcess(argv, 0, "27.5.0\n", "")
        if len(argv) == 4 and argv[:3] == ("docker", "image", "inspect"):
            image = argv[3]
            if image == "ctftoolkit/ctf-sage":
                return subprocess.CompletedProcess(argv, 1, "", "No such image: ctftoolkit/ctf-sage")
            payload = [
                {
                    "Id": "sha256:" + ("a" * 64),
                    "RepoTags": [f"{image}:latest"],
                    "RepoDigests": [f"{image}@sha256:{'b' * 64}"],
                    "Created": "2020-01-01T00:00:00.000000000Z",
                }
            ]
            return subprocess.CompletedProcess(argv, 0, json.dumps(payload), "")
        return subprocess.CompletedProcess(argv, 1, "", "unexpected command")

    monkeypatch.setattr(docker_status, "_which", fake_which)
    monkeypatch.setattr(docker_status, "_run_command", fake_run)

    matrix = docker_status.build_status_matrix(PROJECT_ROOT)
    by_image = {status.image: status for status in matrix.images}

    assert matrix.docker_available is True
    assert by_image["ctftoolkit/ctf-tools"].exists is True
    assert by_image["ctftoolkit/ctf-tools"].digest == "sha256:" + ("b" * 64)
    assert by_image["ctftoolkit/ctf-tools"].stale is True
    assert "changed after local image was created" in by_image["ctftoolkit/ctf-tools"].stale_reason
    assert by_image["ctftoolkit/ctf-sage"].exists is False
    assert by_image["ctftoolkit/ctf-sage"].missing is True


def test_health_probe_commands_are_planned_without_running_docker() -> None:
    probes = docker_status.expected_binary_probe_commands(
        PROJECT_ROOT,
        image="ctftoolkit/ctf-tools",
    )
    nmap = [probe for probe in probes if probe.binary == "nmap"]

    assert nmap
    assert nmap[0].status == "planned"
    assert nmap[0].ok is None
    assert nmap[0].command == ("docker", "run", "--rm", "ctftoolkit/ctf-tools", "which", "nmap")


def test_health_probes_only_run_when_requested(monkeypatch) -> None:
    calls: list[tuple[str, ...]] = []

    def fake_run(args: Sequence[str], *, timeout: int) -> subprocess.CompletedProcess[str]:
        del timeout
        argv = tuple(str(arg) for arg in args)
        calls.append(argv)
        return subprocess.CompletedProcess(argv, 0, "/usr/bin/sage\n", "")

    monkeypatch.setattr(docker_status, "_which", lambda command: "docker.exe" if command == "docker" else None)
    monkeypatch.setattr(docker_status, "_run_command", fake_run)

    planned = docker_status.run_binary_probes(PROJECT_ROOT, image="ctftoolkit/ctf-sage")
    executed = docker_status.run_binary_probes(PROJECT_ROOT, image="ctftoolkit/ctf-sage", run=True)

    assert calls == [("docker.exe", "run", "--rm", "ctftoolkit/ctf-sage", "which", "sage")]
    assert planned[0].status == "planned"
    assert executed[0].status == "pass"
    assert executed[0].ok is True


def test_tool_policy_caps_timeout_and_truncates_output() -> None:
    env = {
        "CTFTOOLKIT_TIMEOUT": "900",
        "CTFTOOLKIT_MAX_TIMEOUT": "1200",
        "CTFTOOLKIT_OUTPUT_LIMIT_CHARS": "25",
        "CTFTOOLKIT_PRESERVE_ARTIFACTS": "false",
        "CTFTOOLKIT_ARTIFACT_RETENTION_DAYS": "120",
    }

    policy = tool_policy.load_policy(env)
    decision = tool_policy.resolve_timeout(5000, env=env)
    truncated = tool_policy.truncate_output("abcdefghijklmnopqrstuvwxyz", env=env)
    settings = tool_policy.artifact_preservation_settings(env)

    assert policy.default_timeout_seconds == 900
    assert policy.max_timeout_seconds == 1200
    assert policy.artifact_retention_days == tool_policy.MAX_ARTIFACT_RETENTION_DAYS
    assert decision.effective_seconds == 1200
    assert decision.capped is True
    assert truncated.truncated is True
    assert len(truncated.output) <= 25
    assert "TRUNCATED" in truncated.note
    assert settings["preserve_artifacts"] is False
    assert settings["preserve_partial_output"] is True


def test_update_plan_is_dry_run_by_default_and_does_not_execute() -> None:
    update_tools = load_update_tools_module()
    calls: list[tuple[str, ...]] = []

    plan = update_tools.build_update_plan()
    output = io.StringIO()
    code = update_tools.run_plan(
        plan,
        executor=lambda command: calls.append(tuple(command)),  # type: ignore[arg-type,return-value]
        out=output,
    )

    assert code == 0
    assert plan.dry_run is True
    assert calls == []
    assert "Mode: dry-run" in output.getvalue()
    assert "Dry run only" in output.getvalue()
    assert all("ctf-sage" not in step.command for step in plan.steps)
    assert {"images", "nuclei-templates", "exploit-db", "wordlists", "local-metadata"} <= {
        step.component for step in plan.steps
    }


def test_update_plan_apply_executes_injected_executor() -> None:
    update_tools = load_update_tools_module()
    calls: list[tuple[str, ...]] = []

    def fake_executor(command: Sequence[str]) -> subprocess.CompletedProcess[str]:
        argv = tuple(str(arg) for arg in command)
        calls.append(argv)
        return subprocess.CompletedProcess(argv, 0, "ok\n", "")

    plan = update_tools.build_update_plan(components=["local-metadata"], dry_run=False)
    output = io.StringIO()
    code = update_tools.run_plan(plan, executor=fake_executor, out=output)

    assert code == 0
    assert calls == [plan.steps[0].command]
    assert plan.steps[0].command[-2:] == ("scripts/generate_manifest.py", "--write")
    assert "Mode: apply" in output.getvalue()
    assert "ok" in output.getvalue()
