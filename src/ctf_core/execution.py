"""Structured execution helpers shared by Docker and smoke paths."""

from __future__ import annotations

from pathlib import Path, PurePosixPath, PureWindowsPath
from typing import Any, Iterable, Mapping, Sequence

from .evidence import append_evidence_event
from .results import CommandValue, ToolResult
from .tool_policy import cancellation_note, load_policy, resolve_timeout, truncate_output


class WorkspacePathError(ValueError):
    """Raised when a user-supplied path cannot be safely resolved."""


def _normalize_slashes(value: str) -> str:
    return value.replace("\\", "/")


def _is_windows_drive_relative(value: str) -> bool:
    windows_path = PureWindowsPath(value)
    return bool(windows_path.drive) and not windows_path.is_absolute()


def _is_absolute_host_path(value: str) -> bool:
    return Path(value).expanduser().is_absolute() or PureWindowsPath(value).is_absolute()


def _contained_in(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
        return True
    except ValueError:
        return False


def _container_relative_path(value: str, container_workspace: str) -> str | None:
    normalized = _normalize_slashes(value)
    container_root = _normalize_slashes(container_workspace).rstrip("/") or "/workspace"
    if normalized == container_root:
        return "."
    prefix = container_root + "/"
    if normalized.startswith(prefix):
        return normalized[len(prefix) :]
    return None


def _relative_path_from_text(value: str) -> Path:
    normalized = _normalize_slashes(value)
    pure_path = PurePosixPath(normalized)
    return Path(*pure_path.parts)


def resolve_workspace_path(
    path: str | Path,
    workspace: str | Path,
    *,
    allow_absolute_host_paths: bool = False,
    must_exist: bool = False,
    container_workspace: str = "/workspace",
) -> Path:
    """Resolve a user path while preventing accidental workspace escapes.

    Relative paths and container-visible ``/workspace/...`` paths are resolved
    under ``workspace`` and must remain contained there. Absolute host paths are
    rejected unless ``allow_absolute_host_paths`` is explicitly set.
    """

    raw = str(path).strip()
    if not raw:
        raise WorkspacePathError("path is empty")

    workspace_root = Path(workspace).expanduser().resolve(strict=False)
    if not workspace_root:
        raise WorkspacePathError("workspace path is empty")

    container_relative = _container_relative_path(raw, container_workspace)
    if container_relative is not None:
        candidate = (workspace_root / _relative_path_from_text(container_relative)).resolve(
            strict=False
        )
        if not _contained_in(candidate, workspace_root):
            raise WorkspacePathError(
                f"container path {raw!r} resolves outside workspace {workspace_root}"
            )
    elif _is_windows_drive_relative(raw):
        raise WorkspacePathError(
            f"Windows drive-relative path {raw!r} is ambiguous; use a relative "
            "workspace path or an absolute host path"
        )
    elif _is_absolute_host_path(raw):
        if not allow_absolute_host_paths:
            raise WorkspacePathError(
                f"absolute host path {raw!r} is disabled; pass "
                "allow_absolute_host_paths=True to permit it"
            )
        candidate = Path(raw).expanduser().resolve(strict=False)
    else:
        candidate = (workspace_root / _relative_path_from_text(raw)).resolve(strict=False)
        if not _contained_in(candidate, workspace_root):
            raise WorkspacePathError(
                f"relative path {raw!r} resolves outside workspace {workspace_root}"
            )

    if must_exist and not candidate.exists():
        raise WorkspacePathError(f"resolved path does not exist: {candidate}")
    return candidate


def _command_from_parts(
    tool: str,
    command: CommandValue = None,
    args: Sequence[str] | None = None,
) -> CommandValue:
    if command is not None:
        return command
    if args is not None:
        return [tool, *[str(arg) for arg in args]]
    return [tool]


def _result_status(result: ToolResult) -> str:
    return "ok" if result.ok else "failed"


def normalize_docker_result(
    docker_result: Mapping[str, Any],
    *,
    tool: str,
    command: CommandValue = None,
    args: Sequence[str] | None = None,
    image: str | None = None,
    target: str | Path | None = None,
    challenge_id: str | None = None,
    artifacts: Sequence[Any] | None = None,
    warnings: Sequence[str] | None = None,
    metadata: Mapping[str, Any] | None = None,
    timeout_seconds: int | None = None,
    output_limit: int | None = None,
    env: Mapping[str, str] | None = None,
) -> ToolResult:
    """Convert a ``docker_runner.run_tool`` dictionary into a ``ToolResult``."""

    policy = load_policy(env)
    result_warnings = [*policy.warnings, *list(warnings or [])]
    result_metadata: dict[str, Any] = dict(metadata or {})

    stdout_truncation = truncate_output(str(docker_result.get("stdout") or ""), output_limit, env=env)
    stderr_truncation = truncate_output(str(docker_result.get("stderr") or ""), output_limit, env=env)
    if stdout_truncation.truncated:
        result_warnings.append(stdout_truncation.note)
    if stderr_truncation.truncated:
        result_warnings.append(stderr_truncation.note)

    exit_code = docker_result.get("exit_code")
    timed_out = bool(docker_result.get("timed_out"))
    runner_error = docker_result.get("error")
    ok = exit_code == 0 and not runner_error and not timed_out

    if timeout_seconds is not None:
        timeout_decision = resolve_timeout(timeout_seconds, env=env)
        result_metadata["timeout"] = timeout_decision.to_dict()
        if timeout_decision.capped and timeout_decision.note:
            result_warnings.append(timeout_decision.note)
    if timed_out:
        result_warnings.append(
            cancellation_note("timeout", timeout_seconds=timeout_seconds, env=env)
        )
        result_metadata["timed_out"] = True
    if runner_error:
        result_warnings.append(f"docker runner reported error: {runner_error}")
        result_metadata["docker_error"] = runner_error

    network_error = docker_result.get("network_error")
    if network_error:
        result_warnings.append(f"network issue detected: {network_error}")
        result_metadata["network_error"] = network_error

    for key in ("duration", "missing_image", "simulated"):
        if key in docker_result:
            result_metadata[key] = docker_result[key]
    if image is not None:
        result_metadata["container_image"] = image
    if target is not None:
        result_metadata["target"] = str(target)
    if challenge_id is not None:
        result_metadata["challenge_id"] = challenge_id
    if stdout_truncation.truncated:
        result_metadata["stdout_truncation"] = stdout_truncation.to_dict()
    if stderr_truncation.truncated:
        result_metadata["stderr_truncation"] = stderr_truncation.to_dict()

    return ToolResult(
        ok=ok,
        tool=tool,
        command=_command_from_parts(tool, command, args),
        exit_code=exit_code,
        stdout=stdout_truncation.output,
        stderr=stderr_truncation.output,
        artifacts=list(artifacts or []),
        warnings=result_warnings,
        metadata=result_metadata,
    )


def log_execution_result(
    workspace: str | Path | None,
    result: ToolResult,
    *,
    event_type: str = "tool_result",
    challenge_id: str | None = None,
    target: str | Path | None = None,
    image: str | None = None,
    files: Iterable[str | Path] | None = None,
    file_hashes: Iterable[Mapping[str, Any]] | None = None,
    artifacts: Iterable[Any] | None = None,
    metadata: Mapping[str, Any] | None = None,
    log_path: str | Path | None = None,
) -> dict[str, Any]:
    """Write evidence for a normalized ``ToolResult``."""

    result_metadata = dict(result.metadata)
    event_metadata = {**result_metadata, **dict(metadata or {})}
    event_metadata["status"] = _result_status(result)

    event_challenge_id = challenge_id or result_metadata.get("challenge_id")
    event_target = target if target is not None else result_metadata.get("target")
    event_image = image or result_metadata.get("container_image")
    if event_image is not None:
        event_metadata["container_image"] = event_image

    event_artifacts = list(artifacts) if artifacts is not None else result.artifacts
    return append_evidence_event(
        workspace,
        event_type,
        challenge_id=str(event_challenge_id) if event_challenge_id is not None else None,
        tool=result.tool,
        command=result.command,
        target=str(event_target) if event_target is not None else None,
        files=files,
        file_hashes=file_hashes,
        result=result,
        artifacts=event_artifacts,
        metadata=event_metadata,
        log_path=log_path,
    )


def normalize_and_log_docker_result(
    workspace: str | Path | None,
    docker_result: Mapping[str, Any],
    *,
    tool: str,
    command: CommandValue = None,
    args: Sequence[str] | None = None,
    image: str | None = None,
    target: str | Path | None = None,
    challenge_id: str | None = None,
    artifacts: Sequence[Any] | None = None,
    warnings: Sequence[str] | None = None,
    metadata: Mapping[str, Any] | None = None,
    timeout_seconds: int | None = None,
    output_limit: int | None = None,
    env: Mapping[str, str] | None = None,
    event_type: str = "tool_result",
    files: Iterable[str | Path] | None = None,
    file_hashes: Iterable[Mapping[str, Any]] | None = None,
    log_path: str | Path | None = None,
) -> tuple[ToolResult, dict[str, Any]]:
    """Normalize a Docker result and immediately append an evidence event."""

    result = normalize_docker_result(
        docker_result,
        tool=tool,
        command=command,
        args=args,
        image=image,
        target=target,
        challenge_id=challenge_id,
        artifacts=artifacts,
        warnings=warnings,
        metadata=metadata,
        timeout_seconds=timeout_seconds,
        output_limit=output_limit,
        env=env,
    )
    event = log_execution_result(
        workspace,
        result,
        event_type=event_type,
        challenge_id=challenge_id,
        target=target,
        image=image,
        files=files,
        file_hashes=file_hashes,
        log_path=log_path,
    )
    return result, event


def simulate_read_only_tool_call(
    tool: str,
    args: Sequence[str] | None = None,
    *,
    stdout: str = "",
    stderr: str = "",
    exit_code: int = 0,
    image: str | None = None,
    target: str | Path | None = None,
    challenge_id: str | None = None,
    artifacts: Sequence[Any] | None = None,
    warnings: Sequence[str] | None = None,
    metadata: Mapping[str, Any] | None = None,
    output_limit: int | None = None,
    env: Mapping[str, str] | None = None,
) -> ToolResult:
    """Return a structured, read-only ToolResult without invoking Docker."""

    simulation_metadata = {
        "simulated": True,
        "read_only": True,
        **dict(metadata or {}),
    }
    simulation_warnings = [
        "read-only simulation; Docker was not invoked",
        *list(warnings or []),
    ]
    return normalize_docker_result(
        {
            "stdout": stdout,
            "stderr": stderr,
            "exit_code": exit_code,
            "duration": 0,
            "simulated": True,
        },
        tool=tool,
        args=args,
        image=image,
        target=target,
        challenge_id=challenge_id,
        artifacts=artifacts,
        warnings=simulation_warnings,
        metadata=simulation_metadata,
        output_limit=output_limit,
        env=env,
    )


__all__ = [
    "WorkspacePathError",
    "log_execution_result",
    "normalize_and_log_docker_result",
    "normalize_docker_result",
    "resolve_workspace_path",
    "simulate_read_only_tool_call",
]
