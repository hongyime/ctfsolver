"""Case/session helpers for persistent CTF challenge workspaces.

The helpers in this module are deliberately server-free. They operate on the
workspace layout already used by :mod:`ctf_core.challenge` and tolerate partial
state so they can be used before the MCP surface is wired in.
"""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import sqlite3
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath
from typing import Any, Mapping


ACTIVE_CASE_FILENAME = "active_case.json"


class CaseError(RuntimeError):
    """Base error for case helper failures."""


class CaseNotFoundError(CaseError):
    """Raised when a requested case selector does not match a case."""


class CaseAmbiguousError(CaseError):
    """Raised when a selector matches more than one case."""


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
        pass
    return Path(__file__).resolve().parents[2] / "workspace"


def default_db_path() -> Path:
    env_db = os.environ.get("CTFTOOLKIT_DB_PATH")
    if env_db:
        return Path(env_db)
    try:
        from .db import DEFAULT_DB_PATH

        return Path(DEFAULT_DB_PATH)
    except Exception:
        pass
    return Path(__file__).resolve().parents[2] / "ctf_state.db"


def cases_root(workspace: str | Path | None = None) -> Path:
    return Path(workspace or default_workspace_path()) / "challenges"


def active_case_path(workspace: str | Path | None = None) -> Path:
    return Path(workspace or default_workspace_path()) / "state" / ACTIVE_CASE_FILENAME


def list_cases(
    workspace: str | Path | None = None,
    *,
    db_path: str | Path | None = None,
) -> list[dict[str, Any]]:
    """List known cases from ``workspace/challenges`` and, when present, SQLite."""

    workspace_path = Path(workspace or default_workspace_path())
    records: dict[str, dict[str, Any]] = {}

    root = cases_root(workspace_path)
    if root.exists():
        for case_path in sorted(path for path in root.iterdir() if path.is_dir()):
            record = _case_record_from_workspace(case_path)
            records[record["case_id"]] = record

    for row in _db_challenge_rows(db_path):
        record = _case_record_from_db(row, workspace_path)
        case_id = str(record["case_id"])
        existing = records.get(case_id)
        if existing is None and record.get("slug") in records:
            existing = records[str(record["slug"])]
            case_id = str(existing["case_id"])
        if existing is None:
            records[case_id] = record
        else:
            _merge_case_record(existing, record)

    return sorted(
        records.values(),
        key=lambda item: (
            str(item.get("category") or "").casefold(),
            str(item.get("name") or "").casefold(),
            str(item.get("case_id") or "").casefold(),
        ),
    )


def resolve_case(
    selector: str,
    workspace: str | Path | None = None,
    *,
    db_path: str | Path | None = None,
) -> dict[str, Any]:
    """Resolve a case by id, slug, challenge id, name, category, or substring."""

    needle = str(selector).strip().casefold()
    if not needle:
        raise CaseNotFoundError("case selector is empty")

    cases = list_cases(workspace, db_path=db_path)
    exact: list[dict[str, Any]] = []
    fuzzy: list[dict[str, Any]] = []
    for case in cases:
        fields = [
            case.get("case_id"),
            case.get("slug"),
            case.get("external_id"),
            case.get("name"),
            case.get("category"),
        ]
        normalized = [str(value).casefold() for value in fields if value not in (None, "")]
        if needle in normalized:
            exact.append(case)
            continue
        haystack = " ".join(normalized)
        if needle in haystack:
            fuzzy.append(case)

    matches = exact or fuzzy
    if not matches:
        raise CaseNotFoundError(f"No case matches {selector!r}")
    if len(matches) > 1:
        ids = ", ".join(str(item["case_id"]) for item in matches)
        raise CaseAmbiguousError(f"Selector {selector!r} matched multiple cases: {ids}")
    return dict(matches[0])


def set_active_case(
    selector: str,
    workspace: str | Path | None = None,
    *,
    db_path: str | Path | None = None,
) -> dict[str, Any]:
    """Persist the active case selection in ``workspace/state/active_case.json``."""

    workspace_path = Path(workspace or default_workspace_path())
    case = resolve_case(selector, workspace_path, db_path=db_path)
    state = {
        "case_id": case["case_id"],
        "slug": case.get("slug"),
        "name": case.get("name"),
        "workspace": case.get("workspace"),
        "selected_at": utc_timestamp(),
    }
    path = active_case_path(workspace_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    _write_json(path, state)
    return {**state, "active": state, "case": case}


select_active_case = set_active_case


def get_active_case(
    workspace: str | Path | None = None,
    *,
    db_path: str | Path | None = None,
) -> dict[str, Any] | None:
    """Return the active case state, enriched with the current case record."""

    workspace_path = Path(workspace or default_workspace_path())
    state = _read_json(active_case_path(workspace_path), None)
    if not isinstance(state, dict) or not state.get("case_id"):
        return None
    try:
        case = resolve_case(str(state["case_id"]), workspace_path, db_path=db_path)
    except CaseError:
        case = None
    return {**state, "active": state, "case": case}


def attach_artifact(
    selector: str,
    artifact_path: str | Path,
    workspace: str | Path | None = None,
    *,
    dest_name: str | None = None,
    db_path: str | Path | None = None,
) -> dict[str, Any]:
    """Copy a host file into a case's ``artifacts/`` directory safely."""

    case = resolve_case(selector, workspace, db_path=db_path)
    source = Path(artifact_path)
    if not source.is_file():
        raise FileNotFoundError(f"artifact source not found: {source}")

    case_path = Path(case["workspace"])
    artifact_root = case_path / "artifacts"
    relative_name = _safe_relative_path(dest_name or source.name)
    destination = _safe_child_path(artifact_root, relative_name)
    destination.parent.mkdir(parents=True, exist_ok=True)

    if destination.exists() and not _path_is_within(destination.resolve(), artifact_root.resolve()):
        raise ValueError(f"artifact destination escapes case artifact directory: {relative_name}")

    try:
        same_file = source.resolve() == destination.resolve()
    except OSError:
        same_file = False
    if not same_file:
        shutil.copy2(source, destination)

    return {
        "case_id": case["case_id"],
        "source": str(source),
        "artifact": str(destination),
        "relative_path": destination.relative_to(case_path).as_posix(),
        "sha256": _sha256_file(destination),
        "size": destination.stat().st_size,
    }


def add_case_note(
    selector: str,
    note: str,
    workspace: str | Path | None = None,
    *,
    heading: str = "Notes",
    db_path: str | Path | None = None,
) -> dict[str, Any]:
    """Append a bullet note to a case ``WRITEUP.md`` under the requested heading."""

    case = resolve_case(selector, workspace, db_path=db_path)
    writeup = Path(case["workspace"]) / "WRITEUP.md"
    writeup.parent.mkdir(parents=True, exist_ok=True)
    if not writeup.exists():
        title = case.get("name") or case["case_id"]
        writeup.write_text(f"# {title}\n\n", encoding="utf-8")
    _append_markdown_bullet(writeup, heading, note)
    return {"case_id": case["case_id"], "writeup": str(writeup), "note": note}


def mark_case_solved(
    selector: str,
    flag: str | None = None,
    workspace: str | Path | None = None,
    *,
    db_path: str | Path | None = None,
) -> dict[str, Any]:
    """Mark a case solved on disk and, if available, in the SQLite challenge row."""

    case = resolve_case(selector, workspace, db_path=db_path)
    case_path = Path(case["workspace"])
    state_path = case_path / "state.json"
    state = _read_json(state_path, {})
    if not isinstance(state, dict):
        state = {}
    state["status"] = "solved"
    state["solved"] = True
    state["solved_at"] = utc_timestamp()
    if flag:
        state["final_flag"] = flag
        candidates = state.setdefault("flag_candidates", [])
        if isinstance(candidates, list) and flag not in candidates:
            candidates.append(flag)
    _write_json(state_path, state)

    if flag:
        add_case_note(case["case_id"], f"`{flag}`", workspace, heading="Flag", db_path=db_path)

    _update_db_solved(case["case_id"], flag, db_path)
    return {"case_id": case["case_id"], "status": "solved", "flag": flag, "state": str(state_path)}


add_note = add_case_note
attach_case_artifact = attach_artifact
mark_solved = mark_case_solved


def export_case(
    selector: str,
    destination: str | Path,
    workspace: str | Path | None = None,
    *,
    db_path: str | Path | None = None,
) -> dict[str, Any]:
    """Export a case to a deterministic, zip-like directory tree."""

    case = resolve_case(selector, workspace, db_path=db_path)
    case_path = Path(case["workspace"])
    export_root = Path(destination) / str(case["case_id"])
    export_root.mkdir(parents=True, exist_ok=True)

    manifest: dict[str, Any] = {
        "case": _portable_case_record(case),
        "files": [],
    }

    for filename in ("metadata.json", "state.json", "WRITEUP.md"):
        source = case_path / filename
        if source.is_file():
            target = export_root / filename
            shutil.copy2(source, target)
            manifest["files"].append(_export_file_record(export_root, target))

    for dirname in ("files", "artifacts"):
        source_dir = case_path / dirname
        if source_dir.is_dir():
            for source in _iter_files(source_dir):
                relative = source.relative_to(source_dir)
                target = _safe_child_path(export_root / dirname, relative.as_posix())
                target.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(source, target)
                manifest["files"].append(_export_file_record(export_root, target))

    events = _case_evidence_lines(case, workspace)
    if events:
        evidence_path = export_root / "evidence" / "events.jsonl"
        evidence_path.parent.mkdir(parents=True, exist_ok=True)
        evidence_path.write_text("".join(events), encoding="utf-8")
        manifest["files"].append(_export_file_record(export_root, evidence_path))

    try:
        from .writeups import generate_final_writeup

        final_writeup = export_root / "FINAL_WRITEUP.md"
        final_writeup.write_text(
            generate_final_writeup(case["case_id"], workspace, db_path=db_path),
            encoding="utf-8",
        )
        manifest["files"].append(_export_file_record(export_root, final_writeup))
    except Exception as exc:  # pragma: no cover - defensive for partial installs
        manifest["writeup_error"] = str(exc)

    manifest["files"] = sorted(manifest["files"], key=lambda item: item["path"])
    _write_json(export_root / "manifest.json", manifest)
    return {"case_id": case["case_id"], "export_dir": str(export_root), "manifest": manifest}


def _case_record_from_workspace(case_path: Path) -> dict[str, Any]:
    metadata = _read_json(case_path / "metadata.json", {})
    if not isinstance(metadata, dict):
        metadata = {}
    state = _read_json(case_path / "state.json", {})
    if not isinstance(state, dict):
        state = {}
    state_challenge = state.get("challenge") if isinstance(state.get("challenge"), dict) else {}

    name = metadata.get("name") or state_challenge.get("name") or _writeup_title(case_path / "WRITEUP.md") or case_path.name
    category = metadata.get("category") or state_challenge.get("category")
    flag = state.get("final_flag") or _first(state.get("flag_candidates"))
    status = state.get("status") or ("solved" if flag else "active")

    record = {
        "case_id": case_path.name,
        "slug": case_path.name,
        "external_id": metadata.get("id") or state_challenge.get("id"),
        "name": name,
        "category": category,
        "description": metadata.get("description"),
        "status": status,
        "flag": flag,
        "workspace": str(case_path),
        "writeup": str(case_path / "WRITEUP.md"),
        "files_dir": str(case_path / "files"),
        "artifacts_dir": str(case_path / "artifacts"),
        "files_on_disk": [path.relative_to(case_path).as_posix() for path in _iter_files(case_path / "files")],
        "artifacts_on_disk": [path.relative_to(case_path).as_posix() for path in _iter_files(case_path / "artifacts")],
        "source": ["workspace"],
    }
    return record


def _case_record_from_db(row: Mapping[str, Any], workspace: Path) -> dict[str, Any]:
    case_id = str(row.get("challenge_id") or row.get("slug") or row.get("name") or "challenge")
    host_path = _host_case_path_from_db(row, workspace, case_id)
    return {
        "case_id": case_id,
        "slug": row.get("slug") or host_path.name,
        "external_id": row.get("id"),
        "name": row.get("name") or case_id,
        "category": row.get("category"),
        "description": row.get("description"),
        "status": row.get("status") or "active",
        "flag": row.get("flag_captured"),
        "workspace": str(host_path),
        "writeup": str(host_path / "WRITEUP.md"),
        "files_dir": str(host_path / "files"),
        "artifacts_dir": str(host_path / "artifacts"),
        "created_at": row.get("created_at"),
        "solved_at": row.get("solved_at"),
        "last_active_at": row.get("last_active_at"),
        "source": ["db"],
    }


def _merge_case_record(existing: dict[str, Any], incoming: Mapping[str, Any]) -> None:
    for key, value in incoming.items():
        if key == "source":
            for source in value or []:
                if source not in existing.setdefault("source", []):
                    existing["source"].append(source)
            existing["source"].sort()
            continue
        if existing.get(key) in (None, "", [], {}) and value not in (None, "", [], {}):
            existing[key] = value
    if incoming.get("flag"):
        existing["flag"] = incoming["flag"]
    if incoming.get("status") == "solved":
        existing["status"] = "solved"


def _db_challenge_rows(db_path: str | Path | None) -> list[dict[str, Any]]:
    path = Path(db_path) if db_path is not None else default_db_path()
    if not path.exists():
        return []
    try:
        with sqlite3.connect(path) as con:
            con.row_factory = sqlite3.Row
            if not _table_exists(con, "challenges"):
                return []
            rows = con.execute("SELECT * FROM challenges ORDER BY challenge_id").fetchall()
            return [dict(row) for row in rows]
    except sqlite3.Error:
        return []


def _update_db_solved(case_id: str, flag: str | None, db_path: str | Path | None) -> None:
    path = Path(db_path) if db_path is not None else default_db_path()
    if not path.exists():
        return
    try:
        with sqlite3.connect(path) as con:
            if _table_exists(con, "challenges"):
                columns = _table_columns(con, "challenges")
                assignments = ["status = ?"]
                params: list[Any] = ["solved"]
                if "flag_captured" in columns and flag is not None:
                    assignments.append("flag_captured = ?")
                    params.append(flag)
                if "solved_at" in columns:
                    assignments.append("solved_at = CURRENT_TIMESTAMP")
                params.append(case_id)
                con.execute(
                    f"UPDATE challenges SET {', '.join(assignments)} WHERE challenge_id = ?",
                    params,
                )
            if flag and _table_exists(con, "flags"):
                columns = _table_columns(con, "flags")
                if "flag_value" not in columns:
                    con.commit()
                    return
                names = ["flag_value"]
                values: list[Any] = [flag]
                if "source" in columns:
                    names.append("source")
                    values.append("case")
                if "pattern" in columns:
                    names.append("pattern")
                    values.append("manual")
                if "challenge_id" in columns:
                    names.append("challenge_id")
                    values.append(case_id)
                placeholders = ", ".join("?" for _ in names)
                con.execute(
                    f"INSERT INTO flags ({', '.join(names)}) VALUES ({placeholders})",
                    values,
                )
            con.commit()
    except sqlite3.Error:
        return


def _host_case_path_from_db(row: Mapping[str, Any], workspace: Path, case_id: str) -> Path:
    raw_path = str(row.get("workspace_path") or "").replace("\\", "/")
    if raw_path.startswith("/workspace/challenges/"):
        return workspace / "challenges" / raw_path.removeprefix("/workspace/challenges/")
    if raw_path.startswith("/workspace/"):
        return workspace / raw_path.removeprefix("/workspace/")
    if raw_path:
        path = Path(raw_path)
        if path.is_absolute():
            return path
    slug = str(row.get("slug") or case_id)
    return workspace / "challenges" / slug


def _safe_relative_path(raw: str) -> str:
    value = raw.replace("\\", "/").strip()
    if not value:
        raise ValueError("artifact destination name is empty")
    path = PurePosixPath(value)
    if path.is_absolute():
        raise ValueError(f"absolute artifact destination is not allowed: {raw!r}")
    parts = path.parts
    if any(part in ("", ".", "..") for part in parts):
        raise ValueError(f"path traversal is not allowed in artifact destination: {raw!r}")
    if any(":" in part or "\x00" in part for part in parts):
        raise ValueError(f"unsafe artifact destination component: {raw!r}")
    return path.as_posix()


def _safe_child_path(root: Path, relative_path: str) -> Path:
    safe_relative = _safe_relative_path(relative_path)
    root_resolved = root.resolve(strict=False)
    candidate = root / PurePosixPath(safe_relative)
    parent = candidate.parent
    parent.mkdir(parents=True, exist_ok=True)
    if not _path_is_within(parent.resolve(strict=False), root_resolved):
        raise ValueError(f"path escapes root: {relative_path!r}")
    if candidate.exists() and not _path_is_within(candidate.resolve(), root_resolved):
        raise ValueError(f"path escapes root: {relative_path!r}")
    return candidate


def _path_is_within(child: Path, root: Path) -> bool:
    try:
        child.relative_to(root)
        return True
    except ValueError:
        return False


def _append_markdown_bullet(path: Path, heading: str, value: str) -> None:
    heading_text = heading.strip().lstrip("#").strip() or "Notes"
    bullet = f"- {value.strip()}"
    content = path.read_text(encoding="utf-8") if path.exists() else ""
    header = f"## {heading_text}"
    lines = content.splitlines()

    header_index = next((idx for idx, line in enumerate(lines) if line.strip() == header), None)
    if header_index is None:
        if lines and lines[-1].strip():
            lines.append("")
        lines.extend([header, "", bullet])
        path.write_text("\n".join(lines).rstrip() + "\n", encoding="utf-8")
        return

    insert_at = len(lines)
    for idx in range(header_index + 1, len(lines)):
        if lines[idx].startswith("## "):
            insert_at = idx
            break
    insert_lines = [bullet]
    if insert_at < len(lines):
        insert_lines.append("")
    lines[insert_at:insert_at] = insert_lines
    path.write_text("\n".join(lines).rstrip() + "\n", encoding="utf-8")


def _case_evidence_lines(case: Mapping[str, Any], workspace: str | Path | None) -> list[str]:
    workspace_path = Path(workspace or default_workspace_path())
    case_ids = {str(case.get("case_id") or ""), str(case.get("slug") or "")}
    paths = [
        workspace_path / "evidence" / "events.jsonl",
        Path(str(case.get("workspace"))) / "evidence" / "events.jsonl",
    ]
    lines: list[str] = []
    seen_paths: set[Path] = set()
    for path in paths:
        normalized = path.resolve(strict=False)
        if normalized in seen_paths or not path.is_file():
            continue
        seen_paths.add(normalized)
        with path.open(encoding="utf-8") as handle:
            for line in handle:
                try:
                    event = json.loads(line)
                except json.JSONDecodeError:
                    continue
                event_case = str(event.get("challenge_id") or "")
                if path.parent.parent == Path(str(case.get("workspace"))) or event_case in case_ids:
                    lines.append(json.dumps(event, sort_keys=True) + "\n")
    return lines


def _portable_case_record(case: Mapping[str, Any]) -> dict[str, Any]:
    portable_keys = (
        "case_id",
        "slug",
        "external_id",
        "name",
        "category",
        "description",
        "status",
        "flag",
        "created_at",
        "solved_at",
        "last_active_at",
        "source",
    )
    return {key: case.get(key) for key in portable_keys if case.get(key) not in (None, "", [], {})}


def _export_file_record(root: Path, path: Path) -> dict[str, Any]:
    return {
        "path": path.relative_to(root).as_posix(),
        "size": path.stat().st_size,
        "sha256": _sha256_file(path),
    }


def _iter_files(root: Path) -> list[Path]:
    if not root.exists():
        return []
    return sorted(path for path in root.rglob("*") if path.is_file())


def _read_json(path: Path, default: Any) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return default


def _write_json(path: Path, data: Mapping[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _sha256_file(path: Path) -> str:
    hasher = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            hasher.update(chunk)
    return hasher.hexdigest()


def _writeup_title(path: Path) -> str | None:
    try:
        for line in path.read_text(encoding="utf-8").splitlines():
            stripped = line.strip()
            if stripped.startswith("# "):
                return stripped[2:].strip() or None
    except OSError:
        return None
    return None


def _first(value: Any) -> Any:
    if isinstance(value, list) and value:
        return value[0]
    return None


def _table_exists(con: sqlite3.Connection, table: str) -> bool:
    row = con.execute(
        "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?",
        (table,),
    ).fetchone()
    return row is not None


def _table_columns(con: sqlite3.Connection, table: str) -> set[str]:
    return {str(row[1]) for row in con.execute(f"PRAGMA table_info({table})").fetchall()}


__all__ = [
    "CaseAmbiguousError",
    "CaseError",
    "CaseNotFoundError",
    "active_case_path",
    "add_note",
    "add_case_note",
    "attach_case_artifact",
    "attach_artifact",
    "cases_root",
    "default_db_path",
    "default_workspace_path",
    "export_case",
    "get_active_case",
    "list_cases",
    "mark_case_solved",
    "mark_solved",
    "resolve_case",
    "select_active_case",
    "set_active_case",
    "utc_timestamp",
]
