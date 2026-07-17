"""Deterministic writeup and agent-memory helpers for CTF cases."""

from __future__ import annotations

import json
import re
import sqlite3
from pathlib import Path
from typing import Any, Mapping

from .cases import default_db_path, default_workspace_path, resolve_case


FLAG_RE = re.compile(r"\b[\w.-]{2,40}\{[^{}\n]{1,200}\}")
FAILURE_WORDS = ("fail", "failed", "error", "timeout", "blocked", "no luck", "did not", "not work")
HYPOTHESIS_WORDS = ("hypothesis", "maybe", "likely", "suspect", "assume", "could be", "try ")


def summarize_agent_memory(
    selector: str,
    workspace: str | Path | None = None,
    *,
    db_path: str | Path | None = None,
    limit: int = 50,
) -> dict[str, Any]:
    """Summarize a case's reusable agent memory from disk, evidence, and DB."""

    case = resolve_case(selector, workspace, db_path=db_path)
    workspace_path = Path(workspace or default_workspace_path())
    case_path = Path(case["workspace"])
    writeup_text = _read_text(case_path / "WRITEUP.md")
    sections = _markdown_sections(writeup_text)
    events = read_case_evidence_events(case["case_id"], workspace_path, db_path=db_path)
    db_memory = _db_memory(case["case_id"], db_path)

    attempts = _dedupe(
        [
            *_attempts_from_writeup(sections),
            *_attempts_from_state(case_path),
            *_attempts_from_events(events),
            *db_memory["attempts"],
        ]
    )[:limit]
    findings = _dedupe(
        [
            *_findings_from_writeup(sections),
            *_findings_from_events(events),
            *db_memory["findings"],
        ]
    )[:limit]
    failures = _dedupe(
        [
            *_keyword_lines(writeup_text, FAILURE_WORDS),
            *_failures_from_events(events),
        ]
    )[:limit]
    hypotheses = _dedupe(
        [
            *_section_items(sections, "Hypotheses"),
            *_keyword_lines(writeup_text, HYPOTHESIS_WORDS),
        ]
    )[:limit]
    important_files = _important_files(case_path, db_memory["files"])[:limit]
    final_flag = _final_flag(case, case_path, sections, db_memory["flags"])

    return {
        "challenge": _challenge_summary(case),
        "attempts": attempts,
        "findings": findings,
        "failures": failures,
        "important_files": important_files,
        "hypotheses": hypotheses,
        "final_flag": final_flag,
        "sources": {
            "writeup": bool(writeup_text),
            "evidence_events": len(events),
            "db": db_memory["available"],
        },
    }


def generate_final_writeup(
    selector: str,
    workspace: str | Path | None = None,
    *,
    db_path: str | Path | None = None,
    final_flag: str | None = None,
) -> str:
    """Generate deterministic Markdown from case metadata, notes, evidence, and artifacts."""

    case = resolve_case(selector, workspace, db_path=db_path)
    workspace_path = Path(workspace or default_workspace_path())
    case_path = Path(case["workspace"])
    writeup_text = _read_text(case_path / "WRITEUP.md")
    sections = _markdown_sections(writeup_text)
    events = read_case_evidence_events(case["case_id"], workspace_path, db_path=db_path)
    db_memory = _db_memory(case["case_id"], db_path)
    flag = final_flag or _final_flag(case, case_path, sections, db_memory["flags"])
    files = _important_files(case_path, db_memory["files"])

    lines = [
        f"# {case.get('name') or case['case_id']}",
        "",
        f"- Challenge ID: {case['case_id']}",
        f"- Category: {case.get('category') or 'unknown'}",
        f"- Status: {case.get('status') or 'unknown'}",
        f"- Final flag: {f'`{flag}`' if flag else 'not recorded'}",
        "",
        "## Description",
        "",
        _clean_block(case.get("description") or _section_text(sections, "Description") or "No description recorded."),
        "",
        "## Notes",
        "",
    ]
    notes = _dedupe([*_section_items(sections, "Notes"), *_section_items(sections, "Findings")])
    lines.extend(_markdown_list(notes, "No notes recorded."))
    lines.extend(["", "## Evidence Timeline", ""])
    lines.extend(_markdown_list(_event_summaries(events), "No evidence events recorded."))
    lines.extend(["", "## Artifacts", ""])
    lines.extend(_artifact_lines(files))
    lines.extend(["", "## Findings", ""])
    findings = _dedupe([*_findings_from_writeup(sections), *_findings_from_events(events), *db_memory["findings"]])
    lines.extend(_markdown_list(findings, "No findings recorded."))
    lines.extend(["", "## Solution", ""])
    solution = _clean_block(_section_text(sections, "Solution"))
    lines.append(solution or "Not recorded.")
    lines.extend(["", "## Final Flag", ""])
    lines.append(f"`{flag}`" if flag else "Not recorded.")
    return "\n".join(lines).rstrip() + "\n"


def write_final_writeup(
    selector: str,
    workspace: str | Path | None = None,
    *,
    output_path: str | Path | None = None,
    db_path: str | Path | None = None,
    final_flag: str | None = None,
) -> dict[str, Any]:
    """Write ``FINAL_WRITEUP.md`` for a case and return its path."""

    case = resolve_case(selector, workspace, db_path=db_path)
    target = Path(output_path) if output_path is not None else Path(case["workspace"]) / "FINAL_WRITEUP.md"
    target.parent.mkdir(parents=True, exist_ok=True)
    markdown = generate_final_writeup(case["case_id"], workspace, db_path=db_path, final_flag=final_flag)
    target.write_text(markdown, encoding="utf-8")
    return {"case_id": case["case_id"], "writeup": str(target), "bytes": len(markdown.encode("utf-8"))}


def read_case_evidence_events(
    selector: str,
    workspace: str | Path | None = None,
    *,
    db_path: str | Path | None = None,
) -> list[dict[str, Any]]:
    """Read JSONL evidence events for a case, tolerating missing or corrupt lines."""

    case = resolve_case(selector, workspace, db_path=db_path)
    workspace_path = Path(workspace or default_workspace_path())
    case_ids = {str(case.get("case_id") or ""), str(case.get("slug") or "")}
    paths = [
        workspace_path / "evidence" / "events.jsonl",
        Path(case["workspace"]) / "evidence" / "events.jsonl",
    ]
    events: list[dict[str, Any]] = []
    seen_paths: set[Path] = set()
    for path in paths:
        normalized = path.resolve(strict=False)
        if normalized in seen_paths or not path.is_file():
            continue
        seen_paths.add(normalized)
        with path.open(encoding="utf-8") as handle:
            for index, line in enumerate(handle):
                try:
                    event = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if not isinstance(event, dict):
                    continue
                event_case = str(event.get("challenge_id") or "")
                case_local = path.parent.parent.resolve(strict=False) == Path(case["workspace"]).resolve(strict=False)
                if case_local or event_case in case_ids:
                    event["_source_line"] = index
                    events.append(event)
    return sorted(
        events,
        key=lambda event: (
            str(event.get("timestamp") or ""),
            str(event.get("event_type") or ""),
            str(event.get("tool") or ""),
            str(event.get("command_text") or ""),
            int(event.get("_source_line") or 0),
        ),
    )


def _challenge_summary(case: Mapping[str, Any]) -> dict[str, Any]:
    keys = ("case_id", "slug", "external_id", "name", "category", "status", "workspace")
    return {key: case.get(key) for key in keys if case.get(key) not in (None, "", [], {})}


def _markdown_sections(text: str) -> dict[str, list[str]]:
    sections: dict[str, list[str]] = {"": []}
    current = ""
    for line in text.splitlines():
        if line.startswith("## "):
            current = line[3:].strip()
            sections.setdefault(current, [])
            continue
        sections.setdefault(current, []).append(line)
    return sections


def _section_text(sections: Mapping[str, list[str]], name: str) -> str:
    lines = sections.get(name) or []
    return "\n".join(lines).strip()


def _section_items(sections: Mapping[str, list[str]], name: str) -> list[str]:
    return _line_items(sections.get(name) or [])


def _line_items(lines: list[str]) -> list[str]:
    items: list[str] = []
    for line in lines:
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if stripped.startswith(("- ", "* ")):
            stripped = stripped[2:].strip()
        elif re.match(r"^\d+\.\s+", stripped):
            stripped = re.sub(r"^\d+\.\s+", "", stripped)
        items.append(stripped)
    return items


def _attempts_from_writeup(sections: Mapping[str, list[str]]) -> list[str]:
    attempts: list[str] = []
    for section in ("Attempts", "Notes", "Solution"):
        attempts.extend(_section_items(sections, section))
    return attempts


def _findings_from_writeup(sections: Mapping[str, list[str]]) -> list[str]:
    findings = _section_items(sections, "Findings")
    for item in _section_items(sections, "Flag"):
        if item:
            findings.append(f"flag: {item.strip('`')}")
    return findings


def _attempts_from_state(case_path: Path) -> list[str]:
    state = _read_json(case_path / "state.json", {})
    if not isinstance(state, dict):
        return []
    attempts: list[str] = []
    for run in state.get("runs") or []:
        if not isinstance(run, dict):
            continue
        label = " ".join(
            str(part)
            for part in (run.get("agent"), run.get("action"), run.get("status"))
            if part
        )
        command = run.get("command")
        if isinstance(command, list):
            label = f"{label}: {' '.join(str(part) for part in command)}"
        if label:
            attempts.append(label)
    return attempts


def _attempts_from_events(events: list[Mapping[str, Any]]) -> list[str]:
    attempts: list[str] = []
    for event in events:
        command = event.get("command_text") or _command_text(event.get("command"))
        tool = event.get("tool") or event.get("event_type")
        if command:
            attempts.append(f"{tool}: {command}" if tool else command)
        elif tool:
            attempts.append(str(tool))
    return attempts


def _findings_from_events(events: list[Mapping[str, Any]]) -> list[str]:
    findings: list[str] = []
    for event in events:
        for item in _flatten(event.get("findings")):
            findings.append(str(item))
        result = event.get("result")
        if isinstance(result, Mapping):
            for item in _flatten(result.get("findings")):
                findings.append(str(item))
        metadata = event.get("metadata")
        if isinstance(metadata, Mapping):
            for item in _flatten(metadata.get("findings")):
                findings.append(str(item))
        for item in _flatten(event.get("artifacts")):
            if item:
                findings.append(f"artifact: {item}")
    return findings


def _failures_from_events(events: list[Mapping[str, Any]]) -> list[str]:
    failures: list[str] = []
    for event in events:
        summary = event.get("result_summary")
        ok = summary.get("ok") if isinstance(summary, Mapping) else event.get("ok")
        if ok is False:
            command = event.get("command_text") or _command_text(event.get("command"))
            tool = event.get("tool") or event.get("event_type") or "event"
            failures.append(f"{tool} failed" + (f": {command}" if command else ""))
        warnings = []
        if isinstance(summary, Mapping):
            warnings.extend(_flatten(summary.get("warnings")))
        warnings.extend(_flatten(event.get("warnings")))
        for warning in warnings:
            failures.append(f"warning: {warning}")
    return failures


def _keyword_lines(text: str, keywords: tuple[str, ...]) -> list[str]:
    matches: list[str] = []
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        lowered = stripped.casefold()
        if any(keyword in lowered for keyword in keywords):
            matches.append(stripped[2:].strip() if stripped.startswith(("- ", "* ")) else stripped)
    return matches


def _important_files(case_path: Path, db_files: list[Mapping[str, Any]]) -> list[dict[str, Any]]:
    records: dict[str, dict[str, Any]] = {}
    for dirname in ("files", "artifacts"):
        root = case_path / dirname
        if not root.is_dir():
            continue
        for path in sorted(item for item in root.rglob("*") if item.is_file()):
            relative = path.relative_to(case_path).as_posix()
            records[relative] = {
                "path": relative,
                "size": path.stat().st_size,
                "sha256": _sha256_file(path),
            }
    for row in db_files:
        name = str(row.get("file_path") or row.get("file_name") or "")
        if not name:
            continue
        relative = _workspace_relative_path(name)
        records.setdefault(
            relative,
            {
                "path": relative,
                "size": row.get("file_size"),
                "sha256": row.get("sha256_hash"),
            },
        )
    return [records[key] for key in sorted(records)]


def _final_flag(
    case: Mapping[str, Any],
    case_path: Path,
    sections: Mapping[str, list[str]],
    db_flags: list[str],
) -> str | None:
    if case.get("flag"):
        return str(case["flag"])
    state = _read_json(case_path / "state.json", {})
    if isinstance(state, dict):
        if state.get("final_flag"):
            return str(state["final_flag"])
        candidates = state.get("flag_candidates")
        if isinstance(candidates, list) and candidates:
            return str(candidates[0])
    for flag in db_flags:
        if flag:
            return str(flag)
    flag_text = _section_text(sections, "Flag")
    match = FLAG_RE.search(flag_text)
    if match:
        return match.group(0)
    return None


def _db_memory(case_id: str, db_path: str | Path | None) -> dict[str, Any]:
    path = Path(db_path) if db_path is not None else default_db_path()
    empty = {"available": False, "attempts": [], "findings": [], "files": [], "flags": []}
    if not path.exists():
        return empty
    try:
        with sqlite3.connect(path) as con:
            con.row_factory = sqlite3.Row
            memory = {"available": True, "attempts": [], "findings": [], "files": [], "flags": []}
            if _table_exists(con, "reasoning_log"):
                for row in con.execute(
                    "SELECT step_description, step_output FROM reasoning_log "
                    "WHERE challenge_id = ? ORDER BY step_number, id",
                    (case_id,),
                ):
                    if row["step_description"]:
                        memory["attempts"].append(str(row["step_description"]))
                    if row["step_output"]:
                        memory["findings"].append(str(row["step_output"]))
            if _table_exists(con, "challenge_files"):
                memory["files"] = [
                    dict(row)
                    for row in con.execute(
                        "SELECT * FROM challenge_files WHERE challenge_id = ? ORDER BY file_path",
                        (case_id,),
                    )
                ]
            if _table_exists(con, "flags"):
                columns = _table_columns(con, "flags")
                if "challenge_id" in columns:
                    rows = con.execute(
                        "SELECT flag_value FROM flags WHERE challenge_id = ? ORDER BY id",
                        (case_id,),
                    )
                else:
                    rows = con.execute("SELECT flag_value FROM flags ORDER BY id")
                memory["flags"] = [str(row["flag_value"]) for row in rows if row["flag_value"]]
            return memory
    except sqlite3.Error:
        return empty


def _event_summaries(events: list[Mapping[str, Any]]) -> list[str]:
    summaries: list[str] = []
    for event in events:
        timestamp = event.get("timestamp") or "unknown-time"
        event_type = event.get("event_type") or "event"
        tool = event.get("tool")
        command = event.get("command_text") or _command_text(event.get("command"))
        summary = event.get("result_summary")
        status = ""
        if isinstance(summary, Mapping) and summary.get("ok") is not None:
            status = " ok" if summary.get("ok") else " failed"
        parts = [str(timestamp), str(event_type)]
        if tool:
            parts.append(str(tool))
        if command:
            parts.append(f"`{command}`")
        if status:
            parts.append(status.strip())
        summaries.append(" - ".join(parts))
    return summaries


def _artifact_lines(files: list[Mapping[str, Any]]) -> list[str]:
    if not files:
        return ["- No artifacts recorded."]
    lines = []
    for item in files:
        detail = f"`{item.get('path')}`"
        if item.get("size") is not None:
            detail += f" ({item['size']} bytes)"
        if item.get("sha256"):
            detail += f" sha256:{item['sha256']}"
        lines.append(f"- {detail}")
    return lines


def _markdown_list(items: list[str], empty: str) -> list[str]:
    if not items:
        return [f"- {empty}"]
    return [f"- {item}" for item in items]


def _clean_block(value: Any) -> str:
    return str(value or "").strip()


def _dedupe(items: list[Any]) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    for item in items:
        text = str(item).strip()
        if not text or text in seen:
            continue
        seen.add(text)
        out.append(text)
    return out


def _flatten(value: Any) -> list[Any]:
    if value is None:
        return []
    if isinstance(value, (str, bytes)):
        return [value.decode() if isinstance(value, bytes) else value]
    if isinstance(value, Mapping):
        return [value]
    if isinstance(value, list | tuple | set):
        flattened: list[Any] = []
        for item in value:
            flattened.extend(_flatten(item))
        return flattened
    return [value]


def _command_text(command: Any) -> str:
    if command is None:
        return ""
    if isinstance(command, str):
        return command
    if isinstance(command, list | tuple):
        return " ".join(str(part) for part in command)
    return str(command)


def _workspace_relative_path(path: str) -> str:
    normalized = path.replace("\\", "/")
    marker = "/workspace/challenges/"
    if marker in normalized:
        return normalized.split(marker, 1)[1]
    return normalized.lstrip("/")


def _read_text(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8")
    except OSError:
        return ""


def _read_json(path: Path, default: Any) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return default


def _sha256_file(path: Path) -> str:
    import hashlib

    hasher = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            hasher.update(chunk)
    return hasher.hexdigest()


def _table_exists(con: sqlite3.Connection, table: str) -> bool:
    row = con.execute(
        "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?",
        (table,),
    ).fetchone()
    return row is not None


def _table_columns(con: sqlite3.Connection, table: str) -> set[str]:
    return {str(row[1]) for row in con.execute(f"PRAGMA table_info({table})").fetchall()}


__all__ = [
    "generate_final_writeup",
    "read_case_evidence_events",
    "summarize_agent_memory",
    "write_final_writeup",
]
