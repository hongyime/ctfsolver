import json
import pytest
from pathlib import Path
from unittest.mock import MagicMock

from ctf_harness_app.ctfd import Challenge
from ctf_harness_app.workspace import (
    build_prompt,
    build_followup_prompt,
    default_state,
    ensure_state,
    load_state,
    save_state,
    load_challenge,
    challenge_dirs,
    resolve_challenge_dir,
    record_run_start,
    record_run_heartbeat,
    record_run_finish,
    utc_timestamp,
    run_container_name,
)
from ctf_harness_app.util import HarnessError


@pytest.fixture
def sample_challenge():
    return Challenge(
        id=1,
        name="test-challenge",
        category="pwn",
        value=100,
        description="Decode <p>this</p>",
        connection_info="nc host 123",
        files=["file1.bin"],
        tags=["tag1"],
        hints=["hint1"],
        raw={"id": 1, "name": "test-challenge"},
    )


def test_build_prompt(sample_challenge):
    prompt = build_prompt(sample_challenge, ["files/file1.bin"])
    assert "/goal Solve the CTF challenge \"test-challenge\"" in prompt
    assert "- id: 1" in prompt
    assert "- category: pwn" in prompt
    assert "Decode this" in prompt
    assert "- `files/file1.bin`" in prompt


def test_build_followup_prompt(sample_challenge):
    prompt = build_followup_prompt(sample_challenge, "Follow-up instructions here.")
    assert "/goal Continue solving the CTF challenge \"test-challenge\"" in prompt
    assert "Follow-up instructions:" in prompt
    assert "Follow-up instructions here." in prompt



def test_default_state(tmp_path, sample_challenge):
    state = default_state(tmp_path / "chal-dir", sample_challenge, ["files/file1.bin"])
    assert state["version"] == 1
    assert state["slug"] == "chal-dir"
    assert state["status"] == "downloaded"
    assert state["challenge"]["id"] == 1
    assert state["challenge"]["downloaded_files"] == ["files/file1.bin"]


def test_ensure_state(tmp_path, sample_challenge):
    chal_dir = tmp_path / "chal-dir"
    chal_dir.mkdir()
    state = ensure_state(chal_dir, sample_challenge)
    assert (chal_dir / "state.json").exists()
    assert state["status"] == "downloaded"
    
    # Check that calling ensure_state again keeps existing state or updates timestamp
    state2 = ensure_state(chal_dir, sample_challenge)
    assert state2["version"] == 1


def test_load_save_state(tmp_path, sample_challenge):
    chal_dir = tmp_path / "chal-dir"
    chal_dir.mkdir()
    
    # Save metadata.json so load_state doesn't crash on load_challenge
    metadata = {
        "id": 1,
        "name": "test-challenge",
        "category": "pwn",
        "value": 100,
        "description": "Decode <p>this</p>",
        "connection_info": "nc host 123",
        "files": ["file1.bin"],
        "tags": ["tag1"],
        "hints": ["hint1"],
    }
    (chal_dir / "metadata.json").write_text(json.dumps(metadata), encoding="utf-8")

    state = ensure_state(chal_dir, sample_challenge)
    state["status"] = "running"
    save_state(chal_dir, state)

    loaded = load_state(chal_dir)
    assert loaded["status"] == "running"


def test_challenge_dirs_and_resolve(tmp_path):
    # Empty dir
    assert challenge_dirs(tmp_path) == []

    # Add challenges
    chal1 = tmp_path / "0001-pwn-chal1"
    chal1.mkdir()
    (chal1 / "metadata.json").write_text('{"id": 1, "name": "chal1", "category": "pwn", "files": [], "tags": [], "hints": []}', encoding="utf-8")

    chal2 = tmp_path / "0002-crypto-chal2"
    chal2.mkdir()
    (chal2 / "metadata.json").write_text('{"id": 2, "name": "chal2", "category": "crypto", "files": [], "tags": [], "hints": []}', encoding="utf-8")

    dirs = challenge_dirs(tmp_path)
    assert len(dirs) == 2
    assert dirs[0] == chal1
    assert dirs[1] == chal2

    # Resolve challenge by selector
    assert resolve_challenge_dir(tmp_path, "chal1") == chal1
    assert resolve_challenge_dir(tmp_path, "2") == chal2
    assert resolve_challenge_dir(tmp_path, "crypto") == chal2

    with pytest.raises(HarnessError):
        resolve_challenge_dir(tmp_path, "non-existent")

    with pytest.raises(HarnessError):
        resolve_challenge_dir(tmp_path, "chal")  # Ambiguous selector


def test_record_run_lifecycle(tmp_path, sample_challenge):
    chal_dir = tmp_path / "0001-pwn-test-challenge"
    chal_dir.mkdir()
    (chal_dir / "metadata.json").write_text('{"id": 1, "name": "test-challenge", "category": "pwn", "files": [], "tags": [], "hints": []}', encoding="utf-8")

    log_path = chal_dir / "claude.log"
    last_path = chal_dir / "claude_last.log"

    run_id = record_run_start(
        chal_dir,
        sample_challenge,
        agent="claude",
        action="start",
        command=["claude", "run"],
        log_path=log_path,
        last_path=last_path
    )
    assert run_id.endswith("-claude-start")
    
    state = load_state(chal_dir)
    assert state["status"] == "running"
    assert state["active_agent"] == "claude"
    assert len(state["runs"]) == 1
    assert state["runs"][0]["status"] == "running"

    # Heartbeat
    record_run_heartbeat(chal_dir, run_id)
    
    # Finish run
    log_path.write_text("Found flag CTF{workspace_runs_fine} here", encoding="utf-8")
    last_path.write_text("CTF{workspace_runs_fine}", encoding="utf-8")
    record_run_finish(chal_dir, run_id, returncode=0, log_path=log_path, last_path=last_path)

    state = load_state(chal_dir)
    assert state["status"] == "succeeded"
    assert state["last_returncode"] == 0
    assert "CTF{workspace_runs_fine}" in state["flag_candidates"]


def test_utc_timestamp():
    assert utc_timestamp("2026-06-21T01:00:00Z") == pytest.approx(1782003600.0, rel=1e-3)
    assert utc_timestamp("invalid-date") is None
    assert utc_timestamp(123) is None


def test_run_container_name():
    assert run_container_name({"command": ["docker", "run", "--name", "ctf-container", "some-image"]}) == "ctf-container"
    assert run_container_name({"command": ["docker", "run", "some-image"]}) is None
    assert run_container_name({"command": "not-a-list"}) is None
    assert run_container_name({"command": ["docker", "run", "--name"]}) is None
    assert run_container_name({}) is None




# ---- STATE.md / JOURNAL.md scaffolding + prompt inclusion ----


def test_build_prompt_includes_state_maintenance(tmp_path):
    from ctf_harness_app.workspace import build_prompt, STATE_MAINTENANCE_CONTEXT
    from ctf_harness_app.ctfd import Challenge
    challenge = Challenge(
        id=1, name="Sanity", category="misc", value=100, description="desc",
        connection_info=None, files=[], tags=[], hints=[], raw={},
    )
    prompt = build_prompt(challenge, downloaded_files=[])
    # Must contain the state-maintenance block so agents know to write STATE.md + JOURNAL.md
    assert "STATE.md" in prompt
    assert "JOURNAL.md" in prompt
    assert "FLAG.txt" in prompt
    # Sanity: the full maintenance context is present (starts with the distinctive header)
    assert "Persistent state" in prompt


def test_ensure_state_scaffold_creates_files(tmp_path):
    from ctf_harness_app.workspace import _ensure_state_scaffold
    from ctf_harness_app.ctfd import Challenge
    challenge_dir = tmp_path / "chal"
    challenge_dir.mkdir()
    challenge = Challenge(
        id=42, name="Test Challenge", category="web", value=200, description="",
        connection_info=None, files=[], tags=[], hints=[], raw={},
    )
    _ensure_state_scaffold(challenge_dir, challenge)
    assert (challenge_dir / "STATE.md").exists()
    assert (challenge_dir / "JOURNAL.md").exists()
    assert (challenge_dir / "FLAG.txt").exists()
    assert (challenge_dir / "EVIDENCE").is_dir()
    # STATE.md is templated with the challenge name
    state = (challenge_dir / "STATE.md").read_text(encoding="utf-8")
    assert "Test Challenge" in state
    assert "## Status" in state
    assert "not started" in state


def test_ensure_state_scaffold_preserves_existing(tmp_path):
    """A resuming run must not clobber an existing STATE.md."""
    from ctf_harness_app.workspace import _ensure_state_scaffold
    from ctf_harness_app.ctfd import Challenge
    challenge_dir = tmp_path / "chal"
    challenge_dir.mkdir()
    challenge = Challenge(
        id=1, name="X", category="web", value=100, description="",
        connection_info=None, files=[], tags=[], hints=[], raw={},
    )
    (challenge_dir / "STATE.md").write_text("PRIOR AGENT NOTES\n", encoding="utf-8")
    _ensure_state_scaffold(challenge_dir, challenge)
    assert (challenge_dir / "STATE.md").read_text(encoding="utf-8") == "PRIOR AGENT NOTES\n"


def test_build_followup_prompt_injects_existing_state(tmp_path):
    """Continue-mode prompt must surface STATE.md + JOURNAL.md so any resuming
    agent (potentially a different model) sees the prior context."""
    from ctf_harness_app.workspace import build_followup_prompt
    from ctf_harness_app.ctfd import Challenge
    challenge_dir = tmp_path / "chal"
    challenge_dir.mkdir()
    (challenge_dir / "STATE.md").write_text(
        "# STATE — X\n## Status\nprobing service on port 1337\n", encoding="utf-8"
    )
    (challenge_dir / "JOURNAL.md").write_text(
        "# JOURNAL — X\n## 2026-09-19T10:00:00Z — kiro — nmap\nfound port 1337 open\n",
        encoding="utf-8",
    )
    challenge = Challenge(
        id=1, name="X", category="web", value=100, description="",
        connection_info=None, files=[], tags=[], hints=[], raw={},
    )
    prompt = build_followup_prompt(challenge, "keep going", challenge_dir=challenge_dir)
    assert "probing service on port 1337" in prompt
    assert "found port 1337 open" in prompt
    assert "keep going" in prompt


def test_build_followup_prompt_without_challenge_dir_still_works(tmp_path):
    from ctf_harness_app.workspace import build_followup_prompt
    from ctf_harness_app.ctfd import Challenge
    challenge = Challenge(
        id=1, name="X", category="web", value=100, description="",
        connection_info=None, files=[], tags=[], hints=[], raw={},
    )
    prompt = build_followup_prompt(challenge, "next step")
    assert "next step" in prompt
    # Doesn't crash when challenge_dir isn't passed (backwards compat)
