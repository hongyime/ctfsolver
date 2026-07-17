"""Structured backend tool result helpers."""

from __future__ import annotations

import json
from dataclasses import dataclass, field, is_dataclass, asdict
from pathlib import Path
from typing import Any, Mapping, Sequence


CommandValue = str | Sequence[str] | None


def _jsonable(value: Any) -> Any:
    """Return a JSON-serializable copy of common Python values."""
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    if isinstance(value, Path):
        return value.as_posix()
    if isinstance(value, Mapping):
        return {str(key): _jsonable(val) for key, val in value.items()}
    if isinstance(value, (list, tuple, set)):
        return [_jsonable(item) for item in value]
    if is_dataclass(value):
        return _jsonable(asdict(value))
    return str(value)


def command_to_text(command: CommandValue) -> str:
    """Render a command value as shell-readable text for summaries."""
    if command is None:
        return ""
    if isinstance(command, str):
        return command
    return " ".join(str(part) for part in command)


@dataclass(slots=True)
class ToolResult:
    """Portable result record for backend tool execution.

    The schema intentionally uses only standard-library types so it can be
    returned from MCP tools, written to evidence logs, or rendered for humans
    without introducing another runtime dependency.
    """

    ok: bool
    tool: str
    command: CommandValue = None
    exit_code: int | None = None
    stdout: str = ""
    stderr: str = ""
    artifacts: list[Any] = field(default_factory=list)
    findings: list[Any] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    next_steps: list[str] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def success(
        cls,
        tool: str,
        command: CommandValue = None,
        *,
        stdout: str = "",
        artifacts: Sequence[Any] | None = None,
        findings: Sequence[Any] | None = None,
        warnings: Sequence[str] | None = None,
        next_steps: Sequence[str] | None = None,
        metadata: Mapping[str, Any] | None = None,
        exit_code: int | None = 0,
    ) -> "ToolResult":
        return cls(
            ok=True,
            tool=tool,
            command=command,
            exit_code=exit_code,
            stdout=stdout,
            artifacts=list(artifacts or []),
            findings=list(findings or []),
            warnings=list(warnings or []),
            next_steps=list(next_steps or []),
            metadata=dict(metadata or {}),
        )

    @classmethod
    def failure(
        cls,
        tool: str,
        command: CommandValue = None,
        *,
        exit_code: int | None = None,
        stdout: str = "",
        stderr: str = "",
        artifacts: Sequence[Any] | None = None,
        findings: Sequence[Any] | None = None,
        warnings: Sequence[str] | None = None,
        next_steps: Sequence[str] | None = None,
        metadata: Mapping[str, Any] | None = None,
    ) -> "ToolResult":
        return cls(
            ok=False,
            tool=tool,
            command=command,
            exit_code=exit_code,
            stdout=stdout,
            stderr=stderr,
            artifacts=list(artifacts or []),
            findings=list(findings or []),
            warnings=list(warnings or []),
            next_steps=list(next_steps or []),
            metadata=dict(metadata or {}),
        )

    @classmethod
    def from_completed_process(
        cls,
        tool: str,
        completed_process: Any,
        *,
        command: CommandValue = None,
        artifacts: Sequence[Any] | None = None,
        findings: Sequence[Any] | None = None,
        warnings: Sequence[str] | None = None,
        next_steps: Sequence[str] | None = None,
        metadata: Mapping[str, Any] | None = None,
    ) -> "ToolResult":
        exit_code = getattr(completed_process, "returncode", None)
        stdout = getattr(completed_process, "stdout", "") or ""
        stderr = getattr(completed_process, "stderr", "") or ""
        if command is None:
            command = getattr(completed_process, "args", None)
        return cls(
            ok=exit_code == 0,
            tool=tool,
            command=command,
            exit_code=exit_code,
            stdout=str(stdout),
            stderr=str(stderr),
            artifacts=list(artifacts or []),
            findings=list(findings or []),
            warnings=list(warnings or []),
            next_steps=list(next_steps or []),
            metadata=dict(metadata or {}),
        )

    def to_dict(self, *, include_empty: bool = True) -> dict[str, Any]:
        data = {
            "ok": self.ok,
            "tool": self.tool,
            "command": _jsonable(self.command),
            "exit_code": self.exit_code,
            "stdout": self.stdout,
            "stderr": self.stderr,
            "artifacts": _jsonable(self.artifacts),
            "findings": _jsonable(self.findings),
            "warnings": _jsonable(self.warnings),
            "next_steps": _jsonable(self.next_steps),
            "metadata": _jsonable(self.metadata),
        }
        if include_empty:
            return data
        return {
            key: value
            for key, value in data.items()
            if value is not None and value != "" and value != [] and value != {}
        }

    def to_json(self, *, indent: int | None = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent, sort_keys=True)

    def to_markdown(self) -> str:
        lines = [
            f"### {self.tool}",
            "",
            f"- Status: {'ok' if self.ok else 'failed'}",
        ]
        if self.exit_code is not None:
            lines.append(f"- Exit code: {self.exit_code}")
        command_text = command_to_text(self.command)
        if command_text:
            lines.extend(["", "**Command**", "", f"`{command_text}`"])
        self._append_markdown_list(lines, "Artifacts", self.artifacts)
        self._append_markdown_list(lines, "Findings", self.findings)
        self._append_markdown_list(lines, "Warnings", self.warnings)
        self._append_markdown_list(lines, "Next steps", self.next_steps)
        if self.stdout:
            lines.extend(["", "**Stdout**", "", "```text", self.stdout, "```"])
        if self.stderr:
            lines.extend(["", "**Stderr**", "", "```text", self.stderr, "```"])
        if self.metadata:
            lines.extend(
                [
                    "",
                    "**Metadata**",
                    "",
                    "```json",
                    json.dumps(_jsonable(self.metadata), indent=2, sort_keys=True),
                    "```",
                ]
            )
        return "\n".join(lines).rstrip() + "\n"

    @staticmethod
    def _append_markdown_list(lines: list[str], title: str, items: Sequence[Any]) -> None:
        if not items:
            return
        lines.extend(["", f"**{title}**"])
        for item in items:
            if isinstance(item, (dict, list, tuple, set)):
                rendered = json.dumps(_jsonable(item), sort_keys=True)
            else:
                rendered = str(item)
            lines.append(f"- {rendered}")


def tool_result(
    *,
    ok: bool,
    tool: str,
    command: CommandValue = None,
    exit_code: int | None = None,
    stdout: str = "",
    stderr: str = "",
    artifacts: Sequence[Any] | None = None,
    findings: Sequence[Any] | None = None,
    warnings: Sequence[str] | None = None,
    next_steps: Sequence[str] | None = None,
    metadata: Mapping[str, Any] | None = None,
) -> ToolResult:
    """Build a ToolResult while normalizing optional sequence fields."""
    return ToolResult(
        ok=ok,
        tool=tool,
        command=command,
        exit_code=exit_code,
        stdout=stdout,
        stderr=stderr,
        artifacts=list(artifacts or []),
        findings=list(findings or []),
        warnings=list(warnings or []),
        next_steps=list(next_steps or []),
        metadata=dict(metadata or {}),
    )
