import json
import sqlite3
from pathlib import Path

import pytest

from ctf_core.cases import (
    active_case_path,
    add_case_note,
    attach_artifact,
    export_case,
    get_active_case,
    list_cases,
    mark_case_solved,
    set_active_case,
)
from ctf_core.writeups import generate_final_writeup, summarize_agent_memory


def _make_case(workspace: Path, slug: str = "web-demo") -> Path:
    case_dir = workspace / "challenges" / slug
    (case_dir / "files").mkdir(parents=True)
    (case_dir / "metadata.json").write_text(
        json.dumps(
            {
                "id": 7,
                "name": "Web Demo",
                "category": "web",
                "description": "Find the hidden flag.",
                "downloaded_files": ["files/app.py"],
            }
        ),
        encoding="utf-8",
    )
    (case_dir / "state.json").write_text(
        json.dumps({"status": "running", "runs": [{"agent": "codex", "action": "start", "status": "failed"}]}),
        encoding="utf-8",
    )
    (case_dir / "WRITEUP.md").write_text(
        "# Web Demo\n\n"
        "## Findings\n\n"
        "- Found /admin endpoint\n\n"
        "## Notes\n\n"
        "- Maybe cookie role controls access\n"
        "- sqlmap failed on the login form\n\n"
        "## Solution\n\n"
        "Use the admin cookie.\n\n"
        "## Flag\n\n",
        encoding="utf-8",
    )
    (case_dir / "files" / "app.py").write_text("print('ctf')\n", encoding="utf-8")
    return case_dir


def _make_db(path: Path) -> None:
    with sqlite3.connect(path) as con:
        con.execute(
            "CREATE TABLE challenges (challenge_id TEXT UNIQUE, name TEXT, category TEXT, "
            "description TEXT, status TEXT, flag_captured TEXT, workspace_path TEXT, created_at TEXT, solved_at TEXT)"
        )
        con.execute(
            "INSERT INTO challenges VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                "db-only",
                "DB Only",
                "crypto",
                "Stored only in sqlite",
                "active",
                None,
                "/workspace/challenges/db-only",
                "2026-01-01",
                None,
            ),
        )
        con.execute(
            "CREATE TABLE reasoning_log (id INTEGER PRIMARY KEY, challenge_id TEXT, step_number INTEGER, "
            "step_description TEXT, step_output TEXT)"
        )
        con.execute(
            "INSERT INTO reasoning_log (challenge_id, step_number, step_description, step_output) "
            "VALUES ('web-demo', 1, 'Tried directory brute force', 'Found /admin')"
        )
        con.execute(
            "CREATE TABLE challenge_files (challenge_id TEXT, file_path TEXT, file_name TEXT, "
            "file_size INTEGER, sha256_hash TEXT)"
        )
        con.execute(
            "INSERT INTO challenge_files VALUES ('web-demo', '/workspace/challenges/web-demo/files/db.txt', "
            "'db.txt', 3, 'abc')"
        )
        con.execute("CREATE TABLE flags (id INTEGER PRIMARY KEY, flag_value TEXT, challenge_id TEXT)")
        con.execute("INSERT INTO flags (flag_value, challenge_id) VALUES ('CTF{db_flag}', 'web-demo')")
        con.commit()


def test_list_cases_merges_workspace_and_db_and_tracks_active(tmp_path, monkeypatch):
    workspace = tmp_path / "workspace"
    _make_case(workspace)
    db_path = tmp_path / "ctf_state.db"
    _make_db(db_path)
    monkeypatch.setenv("CTFTOOLKIT_WORKSPACE", str(workspace))
    monkeypatch.setenv("CTFTOOLKIT_DB_PATH", str(db_path))

    cases = list_cases()

    assert [case["case_id"] for case in cases] == ["db-only", "web-demo"]
    assert cases[1]["source"] == ["workspace"]
    assert cases[0]["workspace"] == str(workspace / "challenges" / "db-only")

    active = set_active_case("Web Demo")

    assert active["case"]["case_id"] == "web-demo"
    assert active_case_path().exists()
    assert get_active_case()["case"]["name"] == "Web Demo"


def test_attach_artifact_copies_file_and_blocks_traversal(tmp_path, monkeypatch):
    workspace = tmp_path / "workspace"
    _make_case(workspace)
    monkeypatch.setenv("CTFTOOLKIT_WORKSPACE", str(workspace))
    source = tmp_path / "loot.txt"
    source.write_text("secret\n", encoding="utf-8")

    attached = attach_artifact("web-demo", source, dest_name="notes/loot.txt")

    artifact = Path(attached["artifact"])
    assert artifact.read_text(encoding="utf-8") == "secret\n"
    assert attached["relative_path"] == "artifacts/notes/loot.txt"

    with pytest.raises(ValueError):
        attach_artifact("web-demo", source, dest_name="../escape.txt")

    assert not (workspace / "challenges" / "escape.txt").exists()


def test_notes_solved_memory_and_final_writeup_use_workspace_evidence_and_db(tmp_path, monkeypatch):
    workspace = tmp_path / "workspace"
    _make_case(workspace)
    db_path = tmp_path / "ctf_state.db"
    _make_db(db_path)
    monkeypatch.setenv("CTFTOOLKIT_WORKSPACE", str(workspace))
    monkeypatch.setenv("CTFTOOLKIT_DB_PATH", str(db_path))
    evidence_dir = workspace / "evidence"
    evidence_dir.mkdir()
    evidence_dir.joinpath("events.jsonl").write_text(
        json.dumps(
            {
                "challenge_id": "web-demo",
                "event_type": "tool_run",
                "timestamp": "2026-01-01T00:00:00Z",
                "tool": "curl",
                "command_text": "curl http://target/admin",
                "result_summary": {"ok": True},
                "artifacts": ["artifacts/response.html"],
                "metadata": {"findings": ["admin panel requires cookie"]},
            },
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )

    add_case_note("web-demo", "Confirmed role=admin bypass")
    solved = mark_case_solved("web-demo", "CTF{final_flag}")

    assert solved["status"] == "solved"
    summary = summarize_agent_memory("web-demo")
    assert "Tried directory brute force" in summary["attempts"]
    assert "Found /admin endpoint" in summary["findings"]
    assert "sqlmap failed on the login form" in summary["failures"]
    assert "Maybe cookie role controls access" in summary["hypotheses"]
    assert summary["final_flag"] == "CTF{final_flag}"
    assert any(item["path"] == "files/app.py" for item in summary["important_files"])

    markdown = generate_final_writeup("web-demo")

    assert "# Web Demo" in markdown
    assert "- Final flag: `CTF{final_flag}`" in markdown
    assert "curl http://target/admin" in markdown
    assert "admin panel requires cookie" in markdown
    assert "`files/app.py`" in markdown


def test_export_case_writes_deterministic_folder_structure(tmp_path, monkeypatch):
    workspace = tmp_path / "workspace"
    case_dir = _make_case(workspace)
    monkeypatch.setenv("CTFTOOLKIT_WORKSPACE", str(workspace))
    artifact = tmp_path / "out.bin"
    artifact.write_bytes(b"artifact")
    attach_artifact("web-demo", artifact)

    exported = export_case("web-demo", tmp_path / "exports")

    export_dir = Path(exported["export_dir"])
    assert export_dir == tmp_path / "exports" / "web-demo"
    assert (export_dir / "metadata.json").is_file()
    assert (export_dir / "WRITEUP.md").is_file()
    assert (export_dir / "FINAL_WRITEUP.md").is_file()
    assert (export_dir / "files" / "app.py").read_text(encoding="utf-8") == "print('ctf')\n"
    assert (export_dir / "artifacts" / "out.bin").read_bytes() == b"artifact"

    manifest = json.loads((export_dir / "manifest.json").read_text(encoding="utf-8"))
    manifest_paths = [item["path"] for item in manifest["files"]]
    assert manifest_paths == sorted(manifest_paths)
    assert "files/app.py" in manifest_paths
    assert "artifacts/out.bin" in manifest_paths
    assert "FINAL_WRITEUP.md" in manifest_paths
    assert case_dir.exists()


def test_memory_summary_tolerates_missing_db_and_evidence(tmp_path, monkeypatch):
    workspace = tmp_path / "workspace"
    _make_case(workspace, "offline-demo")
    monkeypatch.setenv("CTFTOOLKIT_WORKSPACE", str(workspace))
    monkeypatch.setenv("CTFTOOLKIT_DB_PATH", str(tmp_path / "missing.db"))

    summary = summarize_agent_memory("offline-demo")

    assert summary["sources"]["db"] is False
    assert summary["sources"]["evidence_events"] == 0
    assert summary["challenge"]["case_id"] == "offline-demo"
