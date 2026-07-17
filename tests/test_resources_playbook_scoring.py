from __future__ import annotations

import json
import sqlite3
from pathlib import Path

from ctf_core.playbook_scoring import common_failure_branches, select_best_playbook, select_scored_playbooks
from ctf_core.resources import (
    build_challenge_files_resource,
    build_evidence_logs_resource,
    build_resource_context,
    list_resource_descriptors,
)


def _make_case(workspace: Path, slug: str = "web-demo") -> Path:
    case_dir = workspace / "challenges" / slug
    (case_dir / "files").mkdir(parents=True)
    (case_dir / "artifacts").mkdir()
    (case_dir / "metadata.json").write_text(
        json.dumps(
            {
                "id": 7,
                "name": "Web Demo",
                "category": "web",
                "description": "Find hidden routes and bypass the login.",
            }
        ),
        encoding="utf-8",
    )
    (case_dir / "state.json").write_text(json.dumps({"status": "active", "notes": ["state note"]}), encoding="utf-8")
    (case_dir / "WRITEUP.md").write_text(
        "# Web Demo\n\n"
        "## Notes\n\n"
        "- Try the admin cookie\n\n"
        "## Hypotheses\n\n"
        "- Maybe JWT role controls access\n\n"
        "## Findings\n\n"
        "- Found /admin endpoint\n",
        encoding="utf-8",
    )
    (case_dir / "files" / "app.py").write_text("print('ctf')\n", encoding="utf-8")
    (case_dir / "artifacts" / "response.html").write_text("<html>admin</html>\n", encoding="utf-8")
    return case_dir


def _make_db(path: Path) -> None:
    with sqlite3.connect(path) as con:
        con.execute(
            "CREATE TABLE challenges (challenge_id TEXT UNIQUE, name TEXT, category TEXT, "
            "description TEXT, status TEXT, flag_captured TEXT, workspace_path TEXT)"
        )
        con.execute(
            "INSERT INTO challenges VALUES (?, ?, ?, ?, ?, ?, ?)",
            ("web-demo", "Web Demo DB", "web", "DB merge", "active", None, "/workspace/challenges/web-demo"),
        )
        con.execute(
            "CREATE TABLE challenge_files (challenge_id TEXT, file_path TEXT, file_name TEXT, "
            "file_size INTEGER, sha256_hash TEXT)"
        )
        con.execute(
            "INSERT INTO challenge_files VALUES (?, ?, ?, ?, ?)",
            ("web-demo", "/workspace/challenges/web-demo/files/db.txt", "db.txt", 3, "abc"),
        )
        con.execute(
            "CREATE TABLE reasoning_log (id INTEGER PRIMARY KEY, challenge_id TEXT, step_number INTEGER, "
            "step_description TEXT, step_output TEXT)"
        )
        con.execute(
            "INSERT INTO reasoning_log (challenge_id, step_number, step_description, step_output) "
            "VALUES ('web-demo', 1, 'Checked routes', 'DB finding')"
        )
        con.commit()


def test_resource_context_merges_workspace_db_evidence_and_static_metadata(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    _make_case(workspace)
    db_path = tmp_path / "ctf_state.db"
    _make_db(db_path)
    evidence_dir = workspace / "evidence"
    evidence_dir.mkdir(parents=True)
    evidence_dir.joinpath("events.jsonl").write_text(
        json.dumps(
            {
                "challenge_id": "web-demo",
                "event_type": "tool_run",
                "timestamp": "2026-01-01T00:00:00Z",
                "tool": "curl",
                "command_text": "curl http://target/admin",
                "metadata": {"findings": ["admin requires cookie"]},
            },
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )

    context = build_resource_context("web-demo", workspace, db_path=db_path)

    json.dumps(context)
    file_paths = {item["path"] for item in context["challenge_files"]["files"]}
    note_text = {item["text"] for item in context["notes"]["notes"]}
    finding_text = {item["text"] for item in context["findings"]["findings"]}

    assert "files/app.py" in file_paths
    assert "web-demo/files/db.txt" in file_paths
    assert "Try the admin cookie" in note_text
    assert "state note" in note_text
    assert {"Found /admin endpoint", "DB finding", "admin requires cookie"} <= finding_text
    assert context["evidence_logs"]["events"][0]["tool"] == "curl"
    assert any(item["id"] == "web_sqli" for item in context["playbooks"]["playbooks"])
    assert any(item["chain_id"] == "web_recon" for item in context["workflow_chains"]["workflow_chains"])
    assert any(item["pack_id"] == "mobile" for item in context["tool_packs"]["tool_packs"])
    assert "generated_final_markdown" in context["writeups"]["writeups"][0]

    bad_selector = build_challenge_files_resource("missing-case", workspace, db_path=db_path)
    assert bad_selector["files"] == []
    assert bad_selector["errors"]


def test_resource_builders_tolerate_missing_workspace_db_and_bad_selector(tmp_path: Path) -> None:
    missing_workspace = tmp_path / "missing-workspace"
    missing_db = tmp_path / "missing.db"

    descriptors = list_resource_descriptors()
    files = build_challenge_files_resource(workspace=missing_workspace, db_path=missing_db)
    evidence = build_evidence_logs_resource("missing-case", missing_workspace, db_path=missing_db)

    json.dumps(files)
    json.dumps(evidence)
    assert any(item["uri"] == "ctfsolver://challenge-files" for item in descriptors)
    assert files["files"] == []
    assert files["errors"] == []
    assert evidence["events"] == []
    assert evidence["errors"]


def test_scored_selector_combines_playbooks_workflows_and_web_failure_branches() -> None:
    results = select_scored_playbooks(
        description="SQL injection login challenge; no web endpoints found after crawl",
        category="web",
        target="https://challenge.local",
        files=["app.js", "routes.py"],
        failures=["no web endpoints found"],
        limit=8,
    )

    ids = {item["id"] for item in results}
    web_recon = next(item for item in results if item["id"] == "web_recon")
    web_sqli = next(item for item in results if item["id"] == "web_sqli")
    branch = next(item for item in web_recon["failure_branches"] if item["id"] == "no_web_endpoints_found")

    assert {"web_recon", "web_sqli"} <= ids
    assert web_recon["kind"] == "workflow_chain"
    assert web_sqli["kind"] == "playbook"
    assert web_recon["score"] > 0
    assert web_sqli["score"] > 0
    assert web_recon["reasons"]
    assert web_sqli["prerequisites"]
    assert web_recon["expected_artifacts"]
    assert branch["active"] is True
    assert any("robots.txt" in action for action in web_recon["next_actions"])
    assert "command" not in web_recon


def test_scored_selector_common_failure_branches_for_crypto_pcap_and_stego() -> None:
    crypto = select_best_playbook(
        description="RSA modulus public key ciphertext; factorization failed",
        category="crypto",
        files=["public.pem", "cipher.txt"],
        failures=["factorization failed"],
    )
    pcap = select_best_playbook(
        description="Packet capture has DNS but no HTTP traffic",
        category="forensics",
        files=["capture.pcapng"],
        failures=["pcap has no HTTP"],
    )
    stego = select_best_playbook(
        description="JPG stego extraction with unknown steghide password",
        category="forensics",
        files=["secret.jpg"],
        failures=["stego passphrase missing"],
    )

    assert crypto is not None
    assert pcap is not None
    assert stego is not None
    assert any(branch["id"] == "crypto_factorization_fails" and branch["active"] for branch in crypto["failure_branches"])
    assert any(branch["id"] == "pcap_no_http" and branch["active"] for branch in pcap["failure_branches"])
    assert any(branch["id"] == "stego_passphrase_missing" and branch["active"] for branch in stego["failure_branches"])
    assert any("Coppersmith" in action for action in crypto["next_actions"])
    assert any("protocol hierarchy" in action for action in pcap["next_actions"])
    assert any("challenge wordlist" in action for action in stego["next_actions"])


def test_common_failure_branch_catalog_includes_required_failures() -> None:
    branch_ids = {branch["id"] for branch in common_failure_branches()}

    assert {
        "no_web_endpoints_found",
        "scanner_out_of_scope",
        "no_strings_found",
        "crypto_factorization_fails",
        "pcap_no_http",
        "stego_passphrase_missing",
    } <= branch_ids
