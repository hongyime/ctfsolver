"""Read-only resource builders for CTF case context.

The functions in this module return plain JSON-serializable dictionaries. They
are intentionally decoupled from FastMCP so the same read models can be used by
MCP resources, tests, CLIs, or agents without opening network connections or
mutating workspace state.
"""

from __future__ import annotations

import hashlib
import json
import sqlite3
from collections.abc import Iterable, Mapping
from pathlib import Path
from typing import Any

from .cases import CaseError, default_db_path, default_workspace_path, list_cases, resolve_case
from .tool_packs import list_tool_packs
from .workflow_chains import list_workflow_chains
from .writeups import generate_final_writeup, summarize_agent_memory


RESOURCE_DESCRIPTORS: tuple[dict[str, str], ...] = (
    {
        "name": "challenge_files",
        "uri": "ctfsolver://challenge-files",
        "mime_type": "application/json",
        "description": "Downloaded challenge files and attached artifacts.",
    },
    {
        "name": "notes",
        "uri": "ctfsolver://notes",
        "mime_type": "application/json",
        "description": "Case notes and hypotheses extracted from writeups/state.",
    },
    {
        "name": "findings",
        "uri": "ctfsolver://findings",
        "mime_type": "application/json",
        "description": "Findings merged from writeups, evidence, and optional DB memory.",
    },
    {
        "name": "evidence_logs",
        "uri": "ctfsolver://evidence-logs",
        "mime_type": "application/json",
        "description": "JSONL evidence events from workspace and case-local logs.",
    },
    {
        "name": "playbooks",
        "uri": "ctfsolver://playbooks",
        "mime_type": "application/json",
        "description": "Built-in solver playbooks.",
    },
    {
        "name": "writeups",
        "uri": "ctfsolver://writeups",
        "mime_type": "application/json",
        "description": "Current and generated case writeup context.",
    },
    {
        "name": "workflow_chains",
        "uri": "ctfsolver://workflow-chains",
        "mime_type": "application/json",
        "description": "Declarative workflow-chain metadata.",
    },
    {
        "name": "tool_packs",
        "uri": "ctfsolver://tool-packs",
        "mime_type": "application/json",
        "description": "Optional tool-pack metadata.",
    },
)


def list_resource_descriptors() -> list[dict[str, str]]:
    """Return MCP-style resource descriptors without touching workspace state."""

    return [dict(item) for item in RESOURCE_DESCRIPTORS]


def build_challenge_files_resource(
    selector: str | None = None,
    workspace: str | Path | None = None,
    *,
    db_path: str | Path | None = None,
) -> dict[str, Any]:
    """Return challenge file/artifact records from disk and optional SQLite."""

    workspace_path = _workspace_path(workspace)
    db = _db_path(db_path)
    errors: list[str] = []
    cases = _select_cases(selector, workspace_path, db, errors)
    records: list[dict[str, Any]] = []

    for case in cases:
        case_path = Path(str(case.get("workspace") or ""))
        for dirname in ("files", "artifacts"):
            root = case_path / dirname
            for path in _iter_files(root):
                records.append(_disk_file_record(case, case_path, path, dirname))

    if cases or selector is None:
        records.extend(_db_challenge_file_records(db, {str(case["case_id"]) for case in cases}, errors))
    merged = _merge_file_records(records)
    return _jsonable(
        {
            "resource": "challenge_files",
            "selector": selector,
            "workspace": str(workspace_path),
            "db_path": str(db),
            "cases": [_case_summary(case) for case in cases],
            "files": merged,
            "count": len(merged),
            "errors": errors,
        }
    )


def build_notes_resource(
    selector: str | None = None,
    workspace: str | Path | None = None,
    *,
    db_path: str | Path | None = None,
) -> dict[str, Any]:
    """Return notes and hypotheses from case writeups/state files."""

    workspace_path = _workspace_path(workspace)
    db = _db_path(db_path)
    errors: list[str] = []
    cases = _select_cases(selector, workspace_path, db, errors)
    notes: list[dict[str, Any]] = []

    for case in cases:
        case_id = str(case["case_id"])
        case_path = Path(str(case.get("workspace") or ""))
        writeup = case_path / "WRITEUP.md"
        sections = _markdown_sections(_read_text(writeup))
        for section in ("Notes", "Hypotheses"):
            for item in _section_items(sections, section):
                notes.append(
                    {
                        "case_id": case_id,
                        "section": section,
                        "text": item,
                        "source": "writeup",
                        "path": str(writeup),
                    }
                )

        state = _read_json(case_path / "state.json", {})
        if isinstance(state, Mapping):
            for item in _flatten(state.get("notes") or state.get("case_notes")):
                text = str(item).strip()
                if text:
                    notes.append(
                        {
                            "case_id": case_id,
                            "section": "state",
                            "text": text,
                            "source": "state",
                            "path": str(case_path / "state.json"),
                        }
                    )

    unique_notes = _dedupe_records(notes, ("case_id", "section", "text", "source"))
    return _jsonable(
        {
            "resource": "notes",
            "selector": selector,
            "workspace": str(workspace_path),
            "db_path": str(db),
            "cases": [_case_summary(case) for case in cases],
            "notes": unique_notes,
            "count": len(unique_notes),
            "errors": errors,
        }
    )


def build_findings_resource(
    selector: str | None = None,
    workspace: str | Path | None = None,
    *,
    db_path: str | Path | None = None,
    limit: int = 100,
) -> dict[str, Any]:
    """Return case findings merged by the existing writeup memory helper."""

    workspace_path = _workspace_path(workspace)
    db = _db_path(db_path)
    errors: list[str] = []
    cases = _select_cases(selector, workspace_path, db, errors)
    findings: list[dict[str, Any]] = []

    for case in cases:
        case_id = str(case["case_id"])
        try:
            memory = summarize_agent_memory(case_id, workspace_path, db_path=db, limit=limit)
        except Exception as exc:  # pragma: no cover - defensive around partial installs
            errors.append(f"{case_id}: {type(exc).__name__}: {exc}")
            continue

        for item in memory.get("findings") or []:
            findings.append({"case_id": case_id, "type": "finding", "text": str(item), "source": "agent_memory"})
        for item in memory.get("failures") or []:
            findings.append({"case_id": case_id, "type": "failure", "text": str(item), "source": "agent_memory"})
        for item in memory.get("hypotheses") or []:
            findings.append({"case_id": case_id, "type": "hypothesis", "text": str(item), "source": "agent_memory"})
        if memory.get("final_flag"):
            findings.append(
                {
                    "case_id": case_id,
                    "type": "flag",
                    "text": str(memory["final_flag"]),
                    "source": "agent_memory",
                }
            )

    unique = _dedupe_records(findings, ("case_id", "type", "text", "source"))
    return _jsonable(
        {
            "resource": "findings",
            "selector": selector,
            "workspace": str(workspace_path),
            "db_path": str(db),
            "cases": [_case_summary(case) for case in cases],
            "findings": unique,
            "count": len(unique),
            "errors": errors,
        }
    )


def build_evidence_logs_resource(
    selector: str | None = None,
    workspace: str | Path | None = None,
    *,
    db_path: str | Path | None = None,
) -> dict[str, Any]:
    """Return evidence JSONL events without requiring the evidence log to exist."""

    workspace_path = _workspace_path(workspace)
    db = _db_path(db_path)
    errors: list[str] = []
    cases = _select_cases(selector, workspace_path, db, errors)
    selected_ids = {str(case.get("case_id") or "") for case in cases} | {str(case.get("slug") or "") for case in cases}
    selected_ids.discard("")
    case_log_paths: dict[Path, str] = {}

    paths = [workspace_path / "evidence" / "events.jsonl"]
    for case in cases:
        case_id = str(case["case_id"])
        case_log = Path(str(case.get("workspace") or "")) / "evidence" / "events.jsonl"
        normalized = case_log.resolve(strict=False)
        case_log_paths[normalized] = case_id
        paths.append(case_log)

    events: list[dict[str, Any]] = []
    seen_paths: set[Path] = set()
    for path in paths:
        normalized = path.resolve(strict=False)
        if normalized in seen_paths:
            continue
        seen_paths.add(normalized)
        local_case_id = case_log_paths.get(normalized)
        for event in _read_jsonl_events(path, errors):
            event_case = str(event.get("challenge_id") or "")
            include = selector is None and not selected_ids
            include = include or selector is None
            include = include or event_case in selected_ids
            include = include or bool(local_case_id)
            if not include:
                continue
            if local_case_id and not event_case:
                event["challenge_id"] = local_case_id
            events.append(event)

    unique = _dedupe_events(events)
    unique.sort(
        key=lambda event: (
            str(event.get("timestamp") or ""),
            str(event.get("challenge_id") or ""),
            str(event.get("event_type") or ""),
            str(event.get("tool") or ""),
            str(event.get("_source_path") or ""),
            int(event.get("_source_line") or 0),
        )
    )
    return _jsonable(
        {
            "resource": "evidence_logs",
            "selector": selector,
            "workspace": str(workspace_path),
            "db_path": str(db),
            "cases": [_case_summary(case) for case in cases],
            "events": unique,
            "count": len(unique),
            "errors": errors,
        }
    )


def build_playbooks_resource() -> dict[str, Any]:
    """Return the full built-in playbook metadata as plain dictionaries."""

    from .playbooks import PLAYBOOKS

    playbooks = [
        {
            "id": playbook.name,
            "name": playbook.name,
            "category": playbook.category,
            "triggers": list(playbook.triggers),
            "tools": list(playbook.tools),
            "workflow": playbook.workflow,
            "skeleton": playbook.skeleton,
        }
        for playbook in PLAYBOOKS
    ]
    return _jsonable({"resource": "playbooks", "playbooks": playbooks, "count": len(playbooks), "errors": []})


def build_writeups_resource(
    selector: str | None = None,
    workspace: str | Path | None = None,
    *,
    db_path: str | Path | None = None,
    include_generated: bool = True,
) -> dict[str, Any]:
    """Return current writeup files plus optional generated final writeups."""

    workspace_path = _workspace_path(workspace)
    db = _db_path(db_path)
    errors: list[str] = []
    cases = _select_cases(selector, workspace_path, db, errors)
    writeups: list[dict[str, Any]] = []

    for case in cases:
        case_id = str(case["case_id"])
        case_path = Path(str(case.get("workspace") or ""))
        writeup_path = case_path / "WRITEUP.md"
        final_path = case_path / "FINAL_WRITEUP.md"
        current = _read_text(writeup_path)
        final = _read_text(final_path)
        record: dict[str, Any] = {
            "case": _case_summary(case),
            "writeup_path": str(writeup_path),
            "writeup_exists": writeup_path.is_file(),
            "headings": _markdown_headings(current),
            "markdown": current,
            "final_writeup_path": str(final_path),
            "final_writeup_exists": final_path.is_file(),
            "final_markdown": final,
        }
        if include_generated:
            try:
                record["generated_final_markdown"] = generate_final_writeup(case_id, workspace_path, db_path=db)
            except Exception as exc:  # pragma: no cover - defensive around partial installs
                record["generated_final_error"] = f"{type(exc).__name__}: {exc}"
        writeups.append(record)

    return _jsonable(
        {
            "resource": "writeups",
            "selector": selector,
            "workspace": str(workspace_path),
            "db_path": str(db),
            "writeups": writeups,
            "count": len(writeups),
            "errors": errors,
        }
    )


def build_workflow_chains_resource() -> dict[str, Any]:
    """Return declarative workflow chains."""

    chains = list_workflow_chains()
    return _jsonable({"resource": "workflow_chains", "workflow_chains": chains, "count": len(chains), "errors": []})


def build_tool_packs_resource() -> dict[str, Any]:
    """Return optional tool-pack metadata."""

    packs = list_tool_packs()
    return _jsonable({"resource": "tool_packs", "tool_packs": packs, "count": len(packs), "errors": []})


def build_resource_context(
    selector: str | None = None,
    workspace: str | Path | None = None,
    *,
    db_path: str | Path | None = None,
) -> dict[str, Any]:
    """Return all read models needed for an MCP resource context view."""

    return _jsonable(
        {
            "resource": "ctf_context",
            "selector": selector,
            "workspace": str(_workspace_path(workspace)),
            "db_path": str(_db_path(db_path)),
            "descriptors": list_resource_descriptors(),
            "challenge_files": build_challenge_files_resource(selector, workspace, db_path=db_path),
            "notes": build_notes_resource(selector, workspace, db_path=db_path),
            "findings": build_findings_resource(selector, workspace, db_path=db_path),
            "evidence_logs": build_evidence_logs_resource(selector, workspace, db_path=db_path),
            "playbooks": build_playbooks_resource(),
            "writeups": build_writeups_resource(selector, workspace, db_path=db_path),
            "workflow_chains": build_workflow_chains_resource(),
            "tool_packs": build_tool_packs_resource(),
        }
    )


def _workspace_path(workspace: str | Path | None) -> Path:
    return Path(workspace) if workspace is not None else default_workspace_path()


def _db_path(db_path: str | Path | None) -> Path:
    return Path(db_path) if db_path is not None else default_db_path()


def _select_cases(
    selector: str | None,
    workspace: Path,
    db_path: Path,
    errors: list[str],
) -> list[dict[str, Any]]:
    if selector:
        try:
            return [resolve_case(selector, workspace, db_path=db_path)]
        except CaseError as exc:
            errors.append(str(exc))
            return []
        except Exception as exc:  # pragma: no cover - defensive around partial installs
            errors.append(f"{type(exc).__name__}: {exc}")
            return []

    try:
        return list_cases(workspace, db_path=db_path)
    except Exception as exc:  # pragma: no cover - defensive around partial installs
        errors.append(f"{type(exc).__name__}: {exc}")
        return []


def _case_summary(case: Mapping[str, Any]) -> dict[str, Any]:
    keys = ("case_id", "slug", "external_id", "name", "category", "status", "workspace", "source")
    return {key: case.get(key) for key in keys if case.get(key) not in (None, "", [], {})}


def _disk_file_record(case: Mapping[str, Any], case_path: Path, path: Path, dirname: str) -> dict[str, Any]:
    relative = path.relative_to(case_path).as_posix()
    record = {
        "case_id": str(case["case_id"]),
        "path": relative,
        "name": path.name,
        "kind": dirname[:-1] if dirname.endswith("s") else dirname,
        "exists": path.is_file(),
        "size": None,
        "sha256": None,
        "sources": [f"workspace:{dirname}"],
    }
    try:
        stat = path.stat()
        record["size"] = stat.st_size
        record["sha256"] = _sha256_file(path)
    except OSError as exc:
        record["error"] = str(exc)
    return record


def _db_challenge_file_records(db_path: Path, case_ids: set[str], errors: list[str]) -> list[dict[str, Any]]:
    if not db_path.exists():
        return []
    try:
        with sqlite3.connect(db_path) as con:
            con.row_factory = sqlite3.Row
            if not _table_exists(con, "challenge_files"):
                return []
            columns = _table_columns(con, "challenge_files")
            where = ""
            params: list[Any] = []
            if case_ids and "challenge_id" in columns:
                placeholders = ", ".join("?" for _ in case_ids)
                where = f" WHERE challenge_id IN ({placeholders})"
                params = sorted(case_ids)
            order_columns = [name for name in ("challenge_id", "file_path", "file_name", "id") if name in columns]
            order = f" ORDER BY {', '.join(order_columns)}" if order_columns else ""
            rows = con.execute(f"SELECT * FROM challenge_files{where}{order}", params).fetchall()
    except sqlite3.Error as exc:
        errors.append(f"challenge_files db read failed: {exc}")
        return []

    records: list[dict[str, Any]] = []
    for row in rows:
        item = dict(row)
        raw_path = str(item.get("file_path") or item.get("file_name") or item.get("path") or "")
        if not raw_path:
            continue
        records.append(
            {
                "case_id": str(item.get("challenge_id") or ""),
                "path": _workspace_relative_path(raw_path),
                "name": str(item.get("file_name") or Path(raw_path).name),
                "kind": "file",
                "exists": None,
                "size": item.get("file_size") or item.get("size"),
                "sha256": item.get("sha256_hash") or item.get("sha256"),
                "sources": ["db:challenge_files"],
            }
        )
    return records


def _merge_file_records(records: Iterable[Mapping[str, Any]]) -> list[dict[str, Any]]:
    merged: dict[tuple[str, str], dict[str, Any]] = {}
    for record in records:
        case_id = str(record.get("case_id") or "")
        path = str(record.get("path") or "")
        if not path:
            continue
        key = (case_id, path)
        current = merged.setdefault(key, dict(record))
        sources = current.setdefault("sources", [])
        for source in record.get("sources") or []:
            if source not in sources:
                sources.append(source)
        for field in ("name", "kind", "exists", "size", "sha256", "error"):
            if current.get(field) in (None, "", [], {}) and record.get(field) not in (None, "", [], {}):
                current[field] = record[field]
    return [merged[key] for key in sorted(merged)]


def _read_jsonl_events(path: Path, errors: list[str]) -> list[dict[str, Any]]:
    if not path.is_file():
        return []
    events: list[dict[str, Any]] = []
    try:
        with path.open(encoding="utf-8") as handle:
            for index, line in enumerate(handle):
                try:
                    event = json.loads(line)
                except json.JSONDecodeError:
                    errors.append(f"{path}: skipped invalid JSONL line {index + 1}")
                    continue
                if not isinstance(event, dict):
                    continue
                event["_source_path"] = str(path)
                event["_source_line"] = index
                events.append(event)
    except OSError as exc:
        errors.append(f"{path}: {exc}")
    return events


def _dedupe_events(events: Iterable[Mapping[str, Any]]) -> list[dict[str, Any]]:
    seen: set[str] = set()
    unique: list[dict[str, Any]] = []
    for event in events:
        key = json.dumps(_jsonable(event), sort_keys=True)
        if key in seen:
            continue
        seen.add(key)
        unique.append(dict(event))
    return unique


def _iter_files(root: Path) -> list[Path]:
    if not root.is_dir():
        return []
    return sorted(path for path in root.rglob("*") if path.is_file())


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


def _markdown_headings(text: str) -> list[str]:
    headings: list[str] = []
    for line in text.splitlines():
        stripped = line.strip()
        if stripped.startswith("#"):
            headings.append(stripped.lstrip("#").strip())
    return headings


def _section_items(sections: Mapping[str, list[str]], section: str) -> list[str]:
    items: list[str] = []
    for line in sections.get(section) or []:
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if stripped.startswith(("- ", "* ")):
            stripped = stripped[2:].strip()
        elif len(stripped) > 2 and stripped[0].isdigit() and ". " in stripped[:4]:
            stripped = stripped.split(". ", 1)[1].strip()
        if stripped:
            items.append(stripped)
    return items


def _flatten(value: Any) -> list[Any]:
    if value is None:
        return []
    if isinstance(value, (str, bytes, Path)):
        return [value.decode() if isinstance(value, bytes) else value]
    if isinstance(value, Mapping):
        flattened: list[Any] = []
        for nested in value.values():
            flattened.extend(_flatten(nested))
        return flattened
    if isinstance(value, Iterable):
        flattened = []
        for nested in value:
            flattened.extend(_flatten(nested))
        return flattened
    return [value]


def _dedupe_records(records: Iterable[Mapping[str, Any]], fields: tuple[str, ...]) -> list[dict[str, Any]]:
    seen: set[tuple[str, ...]] = set()
    unique: list[dict[str, Any]] = []
    for record in records:
        key = tuple(str(record.get(field) or "") for field in fields)
        if key in seen:
            continue
        seen.add(key)
        unique.append(dict(record))
    return unique


def _workspace_relative_path(path: str) -> str:
    normalized = path.replace("\\", "/")
    marker = "/workspace/challenges/"
    if marker in normalized:
        return normalized.split(marker, 1)[1]
    return normalized.lstrip("/")


def _sha256_file(path: Path) -> str:
    hasher = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            hasher.update(chunk)
    return hasher.hexdigest()


def _table_exists(con: sqlite3.Connection, table: str) -> bool:
    row = con.execute("SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?", (table,)).fetchone()
    return row is not None


def _table_columns(con: sqlite3.Connection, table: str) -> set[str]:
    return {str(row[1]) for row in con.execute(f"PRAGMA table_info({table})").fetchall()}


def _jsonable(value: Any) -> Any:
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    if isinstance(value, Path):
        return str(value)
    if isinstance(value, Mapping):
        return {str(key): _jsonable(val) for key, val in value.items()}
    if isinstance(value, (list, tuple, set)):
        return [_jsonable(item) for item in value]
    return str(value)


__all__ = [
    "RESOURCE_DESCRIPTORS",
    "build_challenge_files_resource",
    "build_evidence_logs_resource",
    "build_findings_resource",
    "build_notes_resource",
    "build_playbooks_resource",
    "build_resource_context",
    "build_tool_packs_resource",
    "build_workflow_chains_resource",
    "build_writeups_resource",
    "list_resource_descriptors",
]
