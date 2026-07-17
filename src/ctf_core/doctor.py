"""Local environment doctor checks for the ctfsolver backend."""

from __future__ import annotations

import argparse
import importlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Sequence


STATUS_PASS = "PASS"
STATUS_WARN = "WARN"
STATUS_FAIL = "FAIL"
STATUS_SKIP = "SKIP"

MIN_PYTHON = (3, 12)
EXPECTED_REGISTRY_TOOLS = 60
EXPECTED_DOCKERFILES = 6
SERVER_ID = "ctfsolver"
PROJECT_ROOT = Path(__file__).resolve().parents[2]


@dataclass(frozen=True)
class CheckResult:
    name: str
    status: str
    message: str
    details: tuple[str, ...] = ()

    @property
    def is_failure(self) -> bool:
        return self.status == STATUS_FAIL

    @property
    def is_warning(self) -> bool:
        return self.status == STATUS_WARN


@dataclass(frozen=True)
class DoctorReport:
    checks: tuple[CheckResult, ...]

    @property
    def hard_failures(self) -> tuple[CheckResult, ...]:
        return tuple(check for check in self.checks if check.is_failure)

    @property
    def warnings(self) -> tuple[CheckResult, ...]:
        return tuple(check for check in self.checks if check.is_warning)

    @property
    def ok(self) -> bool:
        return not self.hard_failures

    @property
    def exit_code(self) -> int:
        return 0 if self.ok else 1


def _run_command(args: Sequence[str], *, timeout: int = 10) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        list(args),
        capture_output=True,
        text=True,
        timeout=timeout,
        check=False,
    )


def _which(command: str) -> str | None:
    return shutil.which(command)


def _command_text(result: subprocess.CompletedProcess[str]) -> str:
    output = (result.stdout or result.stderr or "").strip()
    return output.splitlines()[0] if output else ""


def _check_python() -> CheckResult:
    version = sys.version_info
    current = f"{version.major}.{version.minor}.{version.micro}"
    required = ".".join(str(part) for part in MIN_PYTHON)
    if version >= MIN_PYTHON:
        return CheckResult("Python", STATUS_PASS, f"{current} meets >= {required}")
    return CheckResult("Python", STATUS_FAIL, f"{current} is below required >= {required}")


def _check_uv() -> CheckResult:
    uv = _which("uv")
    if not uv:
        return CheckResult("uv", STATUS_FAIL, "uv executable was not found on PATH")

    try:
        result = _run_command([uv, "--version"])
    except Exception as exc:  # noqa: BLE001 - report the local tool failure.
        return CheckResult("uv", STATUS_FAIL, f"uv could not be executed: {exc}")

    if result.returncode == 0:
        detail = _command_text(result)
        message = detail if detail else "uv is available"
        return CheckResult("uv", STATUS_PASS, message, (f"path: {uv}",))

    detail = _command_text(result)
    return CheckResult("uv", STATUS_FAIL, "uv returned a nonzero exit code", (detail,))


def _check_docker() -> tuple[CheckResult, bool]:
    docker = _which("docker")
    if not docker:
        return CheckResult("Docker daemon", STATUS_FAIL, "docker executable was not found on PATH"), False

    try:
        result = _run_command([docker, "info", "--format", "{{.ServerVersion}}"], timeout=15)
    except Exception as exc:  # noqa: BLE001 - surface daemon startup/socket failures.
        return CheckResult("Docker daemon", STATUS_FAIL, f"docker info failed: {exc}", (f"path: {docker}",)), False

    if result.returncode == 0:
        version = _command_text(result) or "running"
        return CheckResult("Docker daemon", STATUS_PASS, f"running ({version})", (f"path: {docker}",)), True

    detail = _command_text(result)
    return CheckResult(
        "Docker daemon",
        STATUS_FAIL,
        "docker is installed but the daemon is not reachable",
        tuple(filter(None, (detail, f"path: {docker}"))),
    ), False


def _check_docker_compose() -> CheckResult:
    docker = _which("docker")
    if docker:
        try:
            result = _run_command([docker, "compose", "version"], timeout=10)
        except Exception as exc:  # noqa: BLE001
            result = subprocess.CompletedProcess([docker, "compose", "version"], 1, "", str(exc))
        if result.returncode == 0:
            return CheckResult("Docker Compose", STATUS_PASS, _command_text(result) or "docker compose is available")

    docker_compose = _which("docker-compose")
    if docker_compose:
        try:
            result = _run_command([docker_compose, "version"], timeout=10)
        except Exception as exc:  # noqa: BLE001
            return CheckResult("Docker Compose", STATUS_FAIL, f"docker-compose failed: {exc}")
        if result.returncode == 0:
            return CheckResult("Docker Compose", STATUS_PASS, _command_text(result) or "docker-compose is available")
        return CheckResult("Docker Compose", STATUS_FAIL, "docker-compose returned a nonzero exit code", (_command_text(result),))

    return CheckResult("Docker Compose", STATUS_FAIL, "Docker Compose was not found")


def _check_server_import() -> CheckResult:
    try:
        importlib.import_module("ctf_core.server")
    except Exception as exc:  # noqa: BLE001 - import diagnostics are the point of this check.
        return CheckResult("MCP server import", STATUS_FAIL, "ctf_core.server import failed", (f"{type(exc).__name__}: {exc}",))
    return CheckResult("MCP server import", STATUS_PASS, "ctf_core.server imports successfully")


def _check_registry_count() -> CheckResult:
    try:
        registry = importlib.import_module("ctf_core.registry")
        tool_registry = getattr(registry, "TOOL_REGISTRY")
        count = len(tool_registry)
    except Exception as exc:  # noqa: BLE001
        return CheckResult("Registry", STATUS_FAIL, "ctf_core.registry could not be inspected", (f"{type(exc).__name__}: {exc}",))

    if count >= EXPECTED_REGISTRY_TOOLS:
        return CheckResult("Registry", STATUS_PASS, f"{count} tools registered")
    return CheckResult("Registry", STATUS_FAIL, f"{count} tools registered; expected at least {EXPECTED_REGISTRY_TOOLS}")


def _check_project_paths(project_root: Path) -> CheckResult:
    required = [
        project_root / "src" / "ctf_core" / "server.py",
        project_root / "docker-compose.yml",
        project_root / "docker",
    ]
    missing = [str(path) for path in required if not path.exists()]
    dockerfiles = list((project_root / "docker").glob("*/Dockerfile"))

    details = [
        f"project root: {project_root}",
        f"dockerfiles: {len(dockerfiles)}",
        f"CTFTOOLKIT_WORKSPACE: {os.environ.get('CTFTOOLKIT_WORKSPACE', '<default>')}",
        f"CTFTOOLKIT_DB_PATH: {os.environ.get('CTFTOOLKIT_DB_PATH', '<default>')}",
        f"CTFTOOLKIT_DOWNLOADS: {os.environ.get('CTFTOOLKIT_DOWNLOADS', '<default>')}",
    ]

    if missing:
        return CheckResult("Project paths", STATUS_FAIL, "required project paths are missing", tuple(missing + details))
    if len(dockerfiles) < EXPECTED_DOCKERFILES:
        return CheckResult(
            "Project paths",
            STATUS_FAIL,
            f"{len(dockerfiles)} Dockerfiles found; expected at least {EXPECTED_DOCKERFILES}",
            tuple(details),
        )
    return CheckResult("Project paths", STATUS_PASS, "required paths are present", tuple(details))


def _workspace_path(project_root: Path, workspace: Path | None) -> Path:
    if workspace is not None:
        return workspace
    return Path(os.environ.get("CTFTOOLKIT_WORKSPACE") or project_root / "workspace")


def _check_workspace_permissions(project_root: Path, workspace: Path | None = None) -> CheckResult:
    path = _workspace_path(project_root, workspace)
    try:
        path.mkdir(parents=True, exist_ok=True)
        if not path.is_dir():
            return CheckResult("Workspace permissions", STATUS_FAIL, f"workspace is not a directory: {path}")
        fd, tmp_name = tempfile.mkstemp(prefix=".doctor-", dir=path)
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                handle.write("ok")
            Path(tmp_name).read_text(encoding="utf-8")
        finally:
            Path(tmp_name).unlink(missing_ok=True)
    except Exception as exc:  # noqa: BLE001
        return CheckResult("Workspace permissions", STATUS_FAIL, "workspace is not writable", (f"{path}", f"{type(exc).__name__}: {exc}"))

    return CheckResult("Workspace permissions", STATUS_PASS, "workspace is writable", (str(path),))


def _validate_mcp_config(path: Path) -> list[str]:
    errors: list[str] = []
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:  # noqa: BLE001
        return [f"{path.name}: invalid JSON ({exc})"]

    server = data.get("mcpServers", {}).get(SERVER_ID)
    if not isinstance(server, dict):
        return [f"{path.name}: missing mcpServers.{SERVER_ID}"]

    if server.get("command") != "uv":
        errors.append(f"{path.name}: command should be uv")
    args = server.get("args")
    if not isinstance(args, list) or "-m" not in args or "ctf_core.server" not in args:
        errors.append(f"{path.name}: args should launch python -m ctf_core.server")
    env = server.get("env")
    if not isinstance(env, dict):
        errors.append(f"{path.name}: env should be an object")
    else:
        for key in ("CTFTOOLKIT_WORKSPACE", "CTFTOOLKIT_DB_PATH"):
            if key not in env:
                errors.append(f"{path.name}: env missing {key}")
    return errors


def _check_mcp_templates(project_root: Path) -> CheckResult:
    template_names = ("mcp.json", "mcp-windows.json")
    errors: list[str] = []
    details: list[str] = []

    for name in template_names:
        path = project_root / name
        if not path.is_file():
            errors.append(f"{name}: missing")
            continue
        errors.extend(_validate_mcp_config(path))
        details.append(f"{name}: present")

    local_config = project_root / "mcp.local.json"
    if local_config.exists():
        local_errors = _validate_mcp_config(local_config)
        errors.extend(local_errors)
        details.append("mcp.local.json: present")
    else:
        details.append("mcp.local.json: not generated yet")

    if errors:
        return CheckResult("MCP config templates", STATUS_FAIL, "MCP config validation failed", tuple(errors + details))
    return CheckResult("MCP config templates", STATUS_PASS, "MCP config templates are valid", tuple(details))


def _auth_check(name: str, env_vars: Sequence[str], file_path: Path, guidance: str) -> CheckResult:
    for env_var in env_vars:
        if os.environ.get(env_var):
            return CheckResult(f"{name} auth", STATUS_PASS, "environment auth is present", (f"source: {env_var}",))
    if file_path.exists():
        return CheckResult(f"{name} auth", STATUS_PASS, "host CLI auth file is present", (str(file_path),))
    return CheckResult(f"{name} auth", STATUS_WARN, guidance, (f"checked: {file_path}",))


def _check_claude_auth() -> CheckResult:
    auth_dir = Path(os.environ.get("CTF_HARNESS_CLAUDE_CONFIG_DIR") or Path.home() / ".claude")
    return _auth_check(
        "Claude",
        ("ANTHROPIC_API_KEY", "ANTHROPIC_AUTH_TOKEN", "CLAUDE_CODE_OAUTH_TOKEN"),
        auth_dir / ".credentials.json",
        "missing; sign in with Claude Code or set ANTHROPIC_API_KEY / ANTHROPIC_AUTH_TOKEN",
    )


def _check_codex_auth() -> CheckResult:
    auth_dir = Path(os.environ.get("CTF_HARNESS_CODEX_HOME") or Path.home() / ".codex")
    return _auth_check(
        "Codex",
        ("OPENAI_API_KEY", "CODEX_ACCESS_TOKEN", "OPENAI_OAUTH_TOKEN", "CODEX_OAUTH_TOKEN"),
        auth_dir / "auth.json",
        "missing; sign in with Codex or set OPENAI_API_KEY / CODEX_ACCESS_TOKEN",
    )


def _registry_images() -> list[str]:
    registry = importlib.import_module("ctf_core.registry")
    return sorted({entry.image for entry in getattr(registry, "TOOL_REGISTRY") if entry.image})


def _check_docker_images(*, docker_available: bool) -> CheckResult:
    if not docker_available:
        return CheckResult("Docker images", STATUS_SKIP, "skipped because Docker is not reachable")

    docker = _which("docker")
    if not docker:
        return CheckResult("Docker images", STATUS_SKIP, "skipped because docker executable was not found")

    try:
        images = _registry_images()
    except Exception as exc:  # noqa: BLE001
        return CheckResult("Docker images", STATUS_WARN, "could not list registry images", (f"{type(exc).__name__}: {exc}",))

    missing: list[str] = []
    present: list[str] = []
    for image in images:
        try:
            result = _run_command([docker, "image", "inspect", image], timeout=10)
        except Exception as exc:  # noqa: BLE001
            missing.append(f"{image} ({exc})")
            continue
        if result.returncode == 0:
            present.append(image)
        else:
            missing.append(image)

    if missing:
        details = [f"present: {len(present)}", "missing: " + ", ".join(missing)]
        return CheckResult("Docker images", STATUS_WARN, f"{len(missing)} image(s) missing locally", tuple(details))
    return CheckResult("Docker images", STATUS_PASS, f"all {len(present)} registry image(s) are present")


def run_doctor(
    *,
    project_root: Path | None = None,
    workspace: Path | None = None,
    include_images: bool = True,
) -> DoctorReport:
    root = (project_root or PROJECT_ROOT).resolve()
    docker_result, docker_available = _check_docker()
    checks = [
        _check_python(),
        _check_uv(),
        docker_result,
        _check_docker_compose(),
        _check_server_import(),
        _check_registry_count(),
        _check_project_paths(root),
        _check_workspace_permissions(root, workspace),
        _check_mcp_templates(root),
        _check_claude_auth(),
        _check_codex_auth(),
    ]
    if include_images:
        checks.append(_check_docker_images(docker_available=docker_available))
    return DoctorReport(tuple(checks))


def format_report(report: DoctorReport) -> str:
    lines = ["ctfsolver doctor", ""]
    for check in report.checks:
        lines.append(f"[{check.status}] {check.name}: {check.message}")
        for detail in check.details:
            if detail:
                lines.append(f"  - {detail}")

    lines.append("")
    if report.ok:
        if report.warnings:
            lines.append(f"Doctor completed with {len(report.warnings)} warning(s).")
        else:
            lines.append("Doctor passed.")
    else:
        lines.append(f"Doctor found {len(report.hard_failures)} hard failure(s).")
    return "\n".join(lines)


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Check local ctfsolver backend prerequisites.")
    parser.add_argument("--project-root", type=Path, default=None, help=argparse.SUPPRESS)
    parser.add_argument("--workspace", type=Path, default=None, help=argparse.SUPPRESS)
    parser.add_argument("--no-images", action="store_true", help="skip local Docker image status checks")
    args = parser.parse_args(argv)

    report = run_doctor(
        project_root=args.project_root,
        workspace=args.workspace,
        include_images=not args.no_images,
    )
    print(format_report(report))
    return report.exit_code


if __name__ == "__main__":
    raise SystemExit(main())
