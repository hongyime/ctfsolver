"""Dependency-free timeout, truncation, and artifact preservation policy helpers."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Mapping


DEFAULT_TIMEOUT_SECONDS = 300
DEFAULT_MAX_TIMEOUT_SECONDS = 1800
HARD_TIMEOUT_CAP_SECONDS = 7200
DEFAULT_NO_OUTPUT_TIMEOUT_SECONDS = 0
DEFAULT_OUTPUT_LIMIT_CHARS = 200_000
MAX_OUTPUT_LIMIT_CHARS = 2_000_000
DEFAULT_ARTIFACT_RETENTION_DAYS = 14
MAX_ARTIFACT_RETENTION_DAYS = 90
DEFAULT_CANCELLATION_NOTE = (
    "[CANCELLED] Tool execution was stopped. Partial stdout/stderr should be "
    "kept with the run result, and generated artifacts should be preserved when enabled."
)


@dataclass(frozen=True, slots=True)
class ToolExecutionPolicy:
    default_timeout_seconds: int = DEFAULT_TIMEOUT_SECONDS
    max_timeout_seconds: int = DEFAULT_MAX_TIMEOUT_SECONDS
    no_output_timeout_seconds: int = DEFAULT_NO_OUTPUT_TIMEOUT_SECONDS
    output_limit_chars: int = DEFAULT_OUTPUT_LIMIT_CHARS
    preserve_artifacts: bool = True
    preserve_partial_output: bool = True
    artifact_retention_days: int = DEFAULT_ARTIFACT_RETENTION_DAYS
    cancellation_note: str = DEFAULT_CANCELLATION_NOTE
    warnings: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


@dataclass(frozen=True, slots=True)
class TimeoutDecision:
    requested_seconds: int | None
    effective_seconds: int
    capped: bool = False
    note: str = ""

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


@dataclass(frozen=True, slots=True)
class TruncationResult:
    output: str
    truncated: bool
    original_length: int
    limit: int
    note: str = ""

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


def _env_get(env: Mapping[str, str] | None, name: str) -> str | None:
    if env is None:
        import os

        return os.environ.get(name)
    return env.get(name)


def _int_env(
    env: Mapping[str, str] | None,
    name: str,
    default: int,
    *,
    minimum: int = 0,
    maximum: int | None = None,
    warnings: list[str] | None = None,
) -> int:
    raw = _env_get(env, name)
    if raw is None or raw == "":
        return default
    try:
        value = int(raw)
    except ValueError:
        if warnings is not None:
            warnings.append(f"{name}={raw!r} is not an integer; using {default}")
        return default
    if value < minimum:
        if warnings is not None:
            warnings.append(f"{name}={value} is below {minimum}; using {minimum}")
        return minimum
    if maximum is not None and value > maximum:
        if warnings is not None:
            warnings.append(f"{name}={value} exceeds cap {maximum}; using {maximum}")
        return maximum
    return value


def _bool_env(env: Mapping[str, str] | None, name: str, default: bool) -> bool:
    raw = _env_get(env, name)
    if raw is None or raw == "":
        return default
    return raw.strip().casefold() in {"1", "true", "yes", "on", "y"}


def load_policy(env: Mapping[str, str] | None = None) -> ToolExecutionPolicy:
    """Load policy from env-like mapping; invalid values fall back with warnings."""

    warnings: list[str] = []
    hard_timeout_cap = _int_env(
        env,
        "CTFTOOLKIT_HARD_TIMEOUT_CAP",
        HARD_TIMEOUT_CAP_SECONDS,
        minimum=1,
        maximum=HARD_TIMEOUT_CAP_SECONDS,
        warnings=warnings,
    )
    max_timeout = _int_env(
        env,
        "CTFTOOLKIT_MAX_TIMEOUT",
        DEFAULT_MAX_TIMEOUT_SECONDS,
        minimum=1,
        maximum=hard_timeout_cap,
        warnings=warnings,
    )
    default_timeout = _int_env(
        env,
        "CTFTOOLKIT_TIMEOUT",
        DEFAULT_TIMEOUT_SECONDS,
        minimum=1,
        maximum=max_timeout,
        warnings=warnings,
    )
    no_output_timeout = _int_env(
        env,
        "CTFTOOLKIT_NO_OUTPUT_TIMEOUT",
        DEFAULT_NO_OUTPUT_TIMEOUT_SECONDS,
        minimum=0,
        maximum=max_timeout,
        warnings=warnings,
    )
    output_limit = _int_env(
        env,
        "CTFTOOLKIT_OUTPUT_LIMIT_CHARS",
        DEFAULT_OUTPUT_LIMIT_CHARS,
        minimum=1,
        maximum=MAX_OUTPUT_LIMIT_CHARS,
        warnings=warnings,
    )
    retention_days = _int_env(
        env,
        "CTFTOOLKIT_ARTIFACT_RETENTION_DAYS",
        DEFAULT_ARTIFACT_RETENTION_DAYS,
        minimum=0,
        maximum=MAX_ARTIFACT_RETENTION_DAYS,
        warnings=warnings,
    )
    note = _env_get(env, "CTFTOOLKIT_CANCELLATION_NOTE") or DEFAULT_CANCELLATION_NOTE

    return ToolExecutionPolicy(
        default_timeout_seconds=default_timeout,
        max_timeout_seconds=max_timeout,
        no_output_timeout_seconds=no_output_timeout,
        output_limit_chars=output_limit,
        preserve_artifacts=_bool_env(env, "CTFTOOLKIT_PRESERVE_ARTIFACTS", True),
        preserve_partial_output=_bool_env(env, "CTFTOOLKIT_PRESERVE_PARTIAL_OUTPUT", True),
        artifact_retention_days=retention_days,
        cancellation_note=note,
        warnings=tuple(warnings),
    )


def resolve_timeout(
    requested_seconds: int | None = None,
    *,
    env: Mapping[str, str] | None = None,
) -> TimeoutDecision:
    """Resolve a requested timeout against defaults and caps."""

    policy = load_policy(env)
    if requested_seconds is None:
        return TimeoutDecision(None, policy.default_timeout_seconds)
    if requested_seconds <= 0:
        return TimeoutDecision(
            requested_seconds,
            policy.default_timeout_seconds,
            capped=True,
            note=f"non-positive timeout replaced with default {policy.default_timeout_seconds}s",
        )
    if requested_seconds > policy.max_timeout_seconds:
        return TimeoutDecision(
            requested_seconds,
            policy.max_timeout_seconds,
            capped=True,
            note=f"timeout capped at {policy.max_timeout_seconds}s",
        )
    return TimeoutDecision(requested_seconds, requested_seconds)


def cancellation_note(
    reason: str = "cancelled",
    *,
    timeout_seconds: int | None = None,
    env: Mapping[str, str] | None = None,
) -> str:
    """Return a standard cancellation note with optional reason and timeout."""

    policy = load_policy(env)
    suffix = f" Reason: {reason}."
    if timeout_seconds is not None:
        suffix += f" Timeout: {timeout_seconds}s."
    return policy.cancellation_note + suffix


def truncate_output(
    output: str,
    limit: int | None = None,
    *,
    env: Mapping[str, str] | None = None,
) -> TruncationResult:
    """Truncate output to a configured character budget and append a clear note."""

    policy = load_policy(env)
    effective_limit = policy.output_limit_chars if limit is None else max(1, limit)
    original_length = len(output)
    if original_length <= effective_limit:
        return TruncationResult(output, False, original_length, effective_limit)

    note = (
        f"[TRUNCATED: kept {effective_limit} of {original_length} characters; "
        "preserve full output as an artifact when enabled]"
    )
    if effective_limit <= len(note) + 1:
        truncated = note[:effective_limit]
    else:
        head_length = effective_limit - len(note) - 1
        truncated = output[:head_length] + "\n" + note
    return TruncationResult(truncated, True, original_length, effective_limit, note)


def truncate_text(
    output: str,
    limit: int | None = None,
    *,
    env: Mapping[str, str] | None = None,
) -> str:
    return truncate_output(output, limit, env=env).output


def artifact_preservation_settings(env: Mapping[str, str] | None = None) -> dict[str, object]:
    policy = load_policy(env)
    return {
        "preserve_artifacts": policy.preserve_artifacts,
        "preserve_partial_output": policy.preserve_partial_output,
        "artifact_retention_days": policy.artifact_retention_days,
    }


load_tool_policy = load_policy
get_tool_policy = load_policy


__all__ = [
    "ToolExecutionPolicy",
    "TimeoutDecision",
    "TruncationResult",
    "artifact_preservation_settings",
    "cancellation_note",
    "get_tool_policy",
    "load_policy",
    "load_tool_policy",
    "resolve_timeout",
    "truncate_output",
    "truncate_text",
]
