"""JSONL evidence logging helpers for backend tool runs."""

from __future__ import annotations

import hashlib
import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, Mapping

from .results import ToolResult, command_to_text


def utc_timestamp() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def default_workspace_path() -> Path:
    env_workspace = os.environ.get("CTFTOOLKIT_WORKSPACE")
    if env_workspace:
        return Path(env_workspace)
    try:
        from .docker_runner import WORKSPACE_PATH

        return Path(WORKSPACE_PATH)
    except Exception:
        return Path(__file__).resolve().parents[2] / "workspace"


def evidence_log_path(workspace: str | Path | None = None) -> Path:
    return Path(workspace or default_workspace_path()) / "evidence" / "events.jsonl"


def _jsonable(value: Any) -> Any:
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    if isinstance(value, Path):
        return value.as_posix()
    if isinstance(value, Mapping):
        return {str(key): _jsonable(val) for key, val in value.items()}
    if isinstance(value, (list, tuple, set)):
        return [_jsonable(item) for item in value]
    if isinstance(value, ToolResult):
        return value.to_dict()
    return str(value)


def collect_file_hashes(
    files: Iterable[str | Path] | None,
    *,
    workspace: str | Path | None = None,
) -> list[dict[str, Any]]:
    """Hash files without failing the event write if a path is missing."""
    records: list[dict[str, Any]] = []
    workspace_path = Path(workspace) if workspace is not None else None
    for raw_path in files or []:
        display_path = Path(raw_path)
        path = display_path
        if workspace_path is not None and not path.is_absolute():
            path = workspace_path / path

        record: dict[str, Any] = {"path": str(display_path)}
        try:
            hasher = hashlib.sha256()
            with path.open("rb") as handle:
                for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                    hasher.update(chunk)
            record["sha256"] = hasher.hexdigest()
            record["size"] = path.stat().st_size
        except OSError as exc:
            record["error"] = str(exc)
        records.append(record)
    return records


def summarize_result(result: ToolResult | Mapping[str, Any] | None) -> dict[str, Any]:
    if result is None:
        return {}
    if isinstance(result, ToolResult):
        data = result.to_dict()
    else:
        data = dict(result)

    stdout = str(data.get("stdout") or "")
    stderr = str(data.get("stderr") or "")
    summary = {
        "ok": data.get("ok"),
        "tool": data.get("tool"),
        "exit_code": data.get("exit_code"),
        "stdout_bytes": len(stdout.encode("utf-8")),
        "stderr_bytes": len(stderr.encode("utf-8")),
        "artifacts_count": len(data.get("artifacts") or []),
        "findings_count": len(data.get("findings") or []),
        "warnings_count": len(data.get("warnings") or []),
        "next_steps_count": len(data.get("next_steps") or []),
    }
    return {key: value for key, value in summary.items() if value is not None}


def build_evidence_event(
    event_type: str,
    *,
    challenge_id: str | None = None,
    tool: str | None = None,
    command: str | list[str] | tuple[str, ...] | None = None,
    target: str | None = None,
    files: Iterable[str | Path] | None = None,
    file_hashes: Iterable[Mapping[str, Any]] | None = None,
    result: ToolResult | Mapping[str, Any] | None = None,
    artifacts: Iterable[Any] | None = None,
    metadata: Mapping[str, Any] | None = None,
    workspace: str | Path | None = None,
) -> dict[str, Any]:
    collected_hashes = collect_file_hashes(files, workspace=workspace)
    provided_hashes = [_jsonable(item) for item in (file_hashes or [])]
    event = {
        "event_type": event_type,
        "timestamp": utc_timestamp(),
        "challenge_id": challenge_id,
        "tool": tool,
        "command": _jsonable(command),
        "command_text": command_to_text(command),
        "target": target,
        "file_hashes": [*provided_hashes, *collected_hashes],
        "result_summary": summarize_result(result),
        "artifacts": _jsonable(list(artifacts or [])),
        "metadata": _jsonable(dict(metadata or {})),
    }
    return event


def append_evidence_event(
    workspace: str | Path | None,
    event_type: str,
    *,
    challenge_id: str | None = None,
    tool: str | None = None,
    command: str | list[str] | tuple[str, ...] | None = None,
    target: str | None = None,
    files: Iterable[str | Path] | None = None,
    file_hashes: Iterable[Mapping[str, Any]] | None = None,
    result: ToolResult | Mapping[str, Any] | None = None,
    artifacts: Iterable[Any] | None = None,
    metadata: Mapping[str, Any] | None = None,
    log_path: str | Path | None = None,
) -> dict[str, Any]:
    """Append one evidence event to JSONL, creating workspace paths as needed."""
    event = build_evidence_event(
        event_type,
        challenge_id=challenge_id,
        tool=tool,
        command=command,
        target=target,
        files=files,
        file_hashes=file_hashes,
        result=result,
        artifacts=artifacts,
        metadata=metadata,
        workspace=workspace,
    )
    path = Path(log_path) if log_path is not None else evidence_log_path(workspace)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(event, sort_keys=True) + "\n")
    return event


def log_tool_result(
    workspace: str | Path | None,
    result: ToolResult,
    *,
    event_type: str = "tool_result",
    challenge_id: str | None = None,
    target: str | None = None,
    files: Iterable[str | Path] | None = None,
    file_hashes: Iterable[Mapping[str, Any]] | None = None,
    metadata: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    return append_evidence_event(
        workspace,
        event_type,
        challenge_id=challenge_id,
        tool=result.tool,
        command=result.command,
        target=target,
        files=files,
        file_hashes=file_hashes,
        result=result,
        artifacts=result.artifacts,
        metadata=metadata,
    )
