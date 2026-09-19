from __future__ import annotations

import dataclasses
import json
import logging
import subprocess
import textwrap
import time
from pathlib import Path
from typing import Any

from .claude_stream import parse_claude_stream
from .codex_stream import parse_codex_stream
from .config import HARNESS_STATE_FILENAME, STATE_FILENAME
from .ctfd import CTFdClient, Challenge, challenge_from_metadata, strip_html
from .util import HarnessError, extract_flag_candidates, read_json, tail_text, utc_now, write_json

logger = logging.getLogger(__name__)


TOOLING_CONTEXT = """\
Runtime/tooling context:
- You are running inside the per-challenge Docker CTF sandbox, not on the host.
- The challenge workspace is mounted at /workspace.
- Common tools are already installed: gcc/g++/clang/make/cmake, gdb/gdbserver,
  pwntools, checksec, patchelf, binutils, strace/ltrace, radare2 when available,
  nmap/netcat/socat/curl/wget, sqlmap/gobuster/hydra/nikto/wfuzz when available,
  binwalk/foremost/exiftool, john/hashcat, tshark/tcpdump, node/npm, ruby gems
  such as zsteg/one_gadget/seccomp-tools.
- If a useful package is missing, install it inside the container with
  sudo apt-get update && sudo apt-get install -y <package>. Keep installs scoped
  to tools needed for this challenge.
"""

ACTIVITY_LOG_LIMIT = 200_000


def build_prompt(challenge: Challenge, downloaded_files: list[str]) -> str:
    description = strip_html(challenge.description) or challenge.description.strip()
    hints = json.dumps(challenge.hints, indent=2, ensure_ascii=False)
    files = "\n".join(f"- `{path}`" for path in downloaded_files) or "- No files provided."
    tags = ", ".join(challenge.tags) if challenge.tags else "none"
    return textwrap.dedent(
        f"""\
        /goal Solve the CTF challenge "{challenge.name}" and recover the flag.

        You are working in an authorized CTF challenge workspace. Use the
        downloaded artifacts, provided service endpoints, and normal CTF
        techniques to recover the flag. Do not attack unrelated systems.

        {TOOLING_CONTEXT}

        Challenge metadata:
        - id: {challenge.id}
        - name: {challenge.name}
        - category: {challenge.category or "unknown"}
        - value: {challenge.value if challenge.value is not None else "unknown"}
        - tags: {tags}
        - connection_info: {challenge.connection_info or "none"}

        Downloaded files:
        {files}

        Description:
        {description or "No description provided."}

        Hints:
        {hints}

        Expected final answer:
        - the flag
        - a concise explanation of the path used to get it
        """
    )


def build_followup_prompt(challenge: Challenge, message: str) -> str:
    return textwrap.dedent(
        f"""\
        /goal Continue solving the CTF challenge "{challenge.name}" and recover the flag.

        Continue from the existing workspace, logs, and previous agent session.

        {TOOLING_CONTEXT}

        Challenge context:
        - id: {challenge.id}
        - name: {challenge.name}
        - category: {challenge.category or "unknown"}
        - connection_info: {challenge.connection_info or "none"}

        Follow-up instructions:
        {message.strip() or "Continue from the previous attempt. Re-check the workspace, logs, and files, then keep working toward the flag."}
        """
    )


def write_challenge_workspace(client: CTFdClient, challenge: Challenge, output_dir: Path) -> Path:
    challenge_dir = output_dir / challenge.folder_name
    files_dir = challenge_dir / "files"
    files_dir.mkdir(parents=True, exist_ok=True)
    downloaded_files: list[str] = []
    for file_url in challenge.files:
        existing = files_dir / client.filename_for_url(file_url)
        downloaded = existing if existing.exists() else client.download_file(file_url, files_dir)
        downloaded_files.append(str(downloaded.relative_to(challenge_dir)))
    metadata = dataclasses.asdict(challenge)
    metadata["downloaded_files"] = downloaded_files
    write_json(challenge_dir / "metadata.json", metadata)
    (challenge_dir / "PROMPT.md").write_text(build_prompt(challenge, downloaded_files), encoding="utf-8")
    ensure_state(challenge_dir, challenge, downloaded_files)
    return challenge_dir


def download_challenges(client: CTFdClient, output_dir: Path, skip_solved: bool = False) -> list[Path]:
    output_dir.mkdir(parents=True, exist_ok=True)
    paths: list[Path] = []
    update_harness_state(output_dir, download_phase="listing", download_current=None, download_done=0, download_total=None)
    summaries = client.list_challenges()
    total = len(summaries)
    solved_ids = [int(summary["id"]) for summary in summaries if summary.get("solved_by_me")]
    update_harness_state(output_dir, download_phase="details", download_total=total, download_done=0)
    for index, summary in enumerate(summaries, 1):
        if skip_solved and summary.get("solved_by_me"):
            continue
        update_harness_state(
            output_dir,
            download_phase="details",
            download_current=f"{index}/{total}: {summary.get('name') or summary.get('id')}",
            download_done=index - 1,
            download_total=total,
        )
        challenge = client.get_challenge(int(summary["id"]))
        paths.append(write_challenge_workspace(client, challenge, output_dir))
        update_harness_state(output_dir, download_done=index)
    update_harness_state(output_dir, last_download_at=utc_now(), solved_challenge_ids=solved_ids, solved_source="ctfd")
    return paths


def refresh_solved_from_ctfd(client: CTFdClient, output_dir: Path) -> set[int]:
    solved_ids = sorted(client.solved_challenge_ids())
    update_harness_state(
        output_dir,
        solved_challenge_ids=solved_ids,
        solved_source="ctfd",
        solved_refreshed_at=utc_now(),
    )
    return set(solved_ids)


def default_state(challenge_dir: Path, challenge: Challenge, downloaded_files: list[str] | None = None) -> dict[str, Any]:
    now = utc_now()
    return {
        "version": 1,
        "slug": challenge_dir.name,
        "workspace": str(challenge_dir.resolve()),
        "challenge": {
            "id": challenge.id,
            "name": challenge.name,
            "category": challenge.category,
            "value": challenge.value,
            "connection_info": challenge.connection_info,
            "tags": challenge.tags,
            "downloaded_files": downloaded_files or [],
        },
        "status": "downloaded",
        "active_agent": None,
        "last_returncode": None,
        "last_run_id": None,
        "flag_candidates": [],
        "created_at": now,
        "updated_at": now,
        "runs": [],
    }


def ensure_state(challenge_dir: Path, challenge: Challenge, downloaded_files: list[str] | None = None) -> dict[str, Any]:
    state_path = challenge_dir / STATE_FILENAME
    if state_path.exists():
        state = read_json(state_path, {})
        if isinstance(state, dict):
            state.setdefault("runs", [])
            state.setdefault("challenge", default_state(challenge_dir, challenge, downloaded_files)["challenge"])
            state["updated_at"] = utc_now()
            write_json(state_path, state)
            return state
    state = default_state(challenge_dir, challenge, downloaded_files)
    write_json(state_path, state)
    return state


def load_challenge(challenge_dir: Path) -> Challenge:
    metadata = read_json(challenge_dir / "metadata.json", {})
    if not isinstance(metadata, dict):
        raise HarnessError(f"metadata.json in {challenge_dir} is not an object")
    return challenge_from_metadata(metadata)


def load_state(challenge_dir: Path) -> dict[str, Any]:
    challenge = load_challenge(challenge_dir)
    state = read_json(challenge_dir / STATE_FILENAME, None)
    if not isinstance(state, dict):
        return ensure_state(challenge_dir, challenge)
    return state


def save_state(challenge_dir: Path, state: dict[str, Any]) -> None:
    state["updated_at"] = utc_now()
    write_json(challenge_dir / STATE_FILENAME, state)


def challenge_dirs(output_dir: Path) -> list[Path]:
    if not output_dir.exists():
        return []
    return sorted(path.parent for path in output_dir.glob("*/metadata.json"))


def resolve_challenge_dir(output_dir: Path, selector: str) -> Path:
    selector_lower = selector.lower()
    matches: list[Path] = []
    for challenge_dir in challenge_dirs(output_dir):
        challenge = load_challenge(challenge_dir)
        haystack = f"{challenge_dir.name} {challenge.id} {challenge.name} {challenge.category}".lower()
        if selector_lower in haystack:
            matches.append(challenge_dir)
    if not matches:
        raise HarnessError(f"No downloaded challenge matches {selector!r}")
    if len(matches) > 1:
        raise HarnessError(f"Selector {selector!r} matched multiple challenges")
    return matches[0]


def record_run_start(challenge_dir: Path, challenge: Challenge, agent: str, action: str, command: list[str], log_path: Path, last_path: Path) -> str:
    state = ensure_state(challenge_dir, challenge)
    run_id = f"{int(__import__('time').time())}-{agent}-{action}"
    state["status"] = "running"
    state["active_agent"] = agent
    state["last_run_id"] = run_id
    state["last_returncode"] = None
    state.setdefault("runs", []).append({
        "id": run_id,
        "agent": agent,
        "action": action,
        "status": "running",
        "started_at": utc_now(),
        "heartbeat_at": utc_now(),
        "ended_at": None,
        "returncode": None,
        "command": command,
        "log": str(log_path.relative_to(challenge_dir)),
        "last_message": str(last_path.relative_to(challenge_dir)),
    })
    save_state(challenge_dir, state)
    return run_id


def record_run_heartbeat(challenge_dir: Path, run_id: str) -> None:
    state = load_state(challenge_dir)
    for run in state.get("runs", []):
        if run.get("id") == run_id and run.get("status") not in {"succeeded", "failed"}:
            run["status"] = "running"
            run["heartbeat_at"] = utc_now()
            run["ended_at"] = None
            run["returncode"] = None
            state["status"] = "running"
            state["active_agent"] = run.get("agent")
            save_state(challenge_dir, state)
            return


def record_run_finish(challenge_dir: Path, run_id: str, returncode: int, log_path: Path, last_path: Path) -> None:
    state = load_state(challenge_dir)
    status = "succeeded" if returncode == 0 else "failed"
    for run in state.get("runs", []):
        if run.get("id") == run_id:
            run["status"] = status
            run["ended_at"] = utc_now()
            run["heartbeat_at"] = utc_now()
            run["returncode"] = returncode
            break
    output = "\n".join(part for part in (tail_text(last_path, 20000), tail_text(log_path, 20000)) if part)
    state["status"] = status
    state["last_returncode"] = returncode
    state["flag_candidates"] = extract_flag_candidates(output)
    save_state(challenge_dir, state)


def utc_timestamp(value: Any) -> float | None:
    if not isinstance(value, str):
        return None
    try:
        return time.mktime(time.strptime(value, "%Y-%m-%dT%H:%M:%SZ"))
    except ValueError:
        return None


def run_container_name(run: dict[str, Any]) -> str | None:
    command = run.get("command")
    if not isinstance(command, list):
        return None
    for index, part in enumerate(command):
        if part == "--name" and index + 1 < len(command):
            name = command[index + 1]
            return str(name) if name else None
    return None


def active_container_names() -> set[str] | None:
    try:
        completed = subprocess.run(
            ["docker", "ps", "--format", "{{.Names}}"],
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            timeout=5,
            check=False,
        )
    except subprocess.TimeoutExpired:
        logger.warning("docker ps timed out during active_container_names reconciliation")
        return None
    except OSError:
        return None
    if completed.returncode != 0:
        return None
    return {line.strip() for line in completed.stdout.splitlines() if line.strip()}


def stop_running_agent(challenge_dir: Path) -> int:
    state = load_state(challenge_dir)
    stopped = 0
    for run in state.get("runs", []):
        if not isinstance(run, dict) or run.get("status") != "running":
            continue
        container_name = run_container_name(run)
        if container_name:
            subprocess.run(["docker", "stop", container_name], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=15, check=False)
        run["status"] = "stopped"
        run["ended_at"] = utc_now()
        run["heartbeat_at"] = utc_now()
        run["returncode"] = None
        stopped += 1
    if stopped:
        state["status"] = "stopped"
        state["active_agent"] = None
        state["last_returncode"] = None
        save_state(challenge_dir, state)
    return stopped


def mark_agent_succeeded(challenge_dir: Path) -> None:
    state = load_state(challenge_dir)
    run_id = state.get("last_run_id")
    target = None
    for run in reversed(state.get("runs", [])):
        if isinstance(run, dict) and (run.get("id") == run_id or target is None):
            target = run
            if run.get("id") == run_id:
                break
    if target is not None:
        target["status"] = "succeeded"
        target["ended_at"] = utc_now()
        target["heartbeat_at"] = utc_now()
        target["returncode"] = 0
    state["status"] = "succeeded"
    state["active_agent"] = None
    state["last_returncode"] = 0
    output = tail_text(challenge_dir / "claude-last-message.txt", 20000) + "\n" + tail_text(challenge_dir / "claude.log", 20000)
    state["flag_candidates"] = extract_flag_candidates(output)
    save_state(challenge_dir, state)


def reconcile_stale_runs(output_dir: Path) -> None:
    now = time.time()
    containers = active_container_names()
    for challenge_dir in challenge_dirs(output_dir):
        state = read_json(challenge_dir / STATE_FILENAME, {})
        if not isinstance(state, dict):
            continue
        changed = False
        for run in state.get("runs", []):
            if not isinstance(run, dict):
                continue
            heartbeat_at = utc_timestamp(run.get("heartbeat_at"))
            container_name = run_container_name(run)
            if containers is not None and container_name in containers and run.get("status") not in {"succeeded", "failed"}:
                run["status"] = "running"
                run["ended_at"] = None
                run["returncode"] = None
                run["heartbeat_at"] = utc_now()
                state["status"] = "running"
                state["active_agent"] = run.get("agent")
                changed = True
                continue
            if run.get("status") != "running":
                continue
            if heartbeat_at is not None and now - heartbeat_at < 45:
                continue
            started_at = utc_timestamp(run.get("started_at"))
            if heartbeat_at is None and started_at is not None and now - started_at < 180:
                continue
            container_missing = containers is not None and container_name and container_name not in containers
            heartbeat_stale = heartbeat_at is not None and now - heartbeat_at >= 45
            old_run_without_heartbeat = heartbeat_at is None and started_at is not None and now - started_at >= 180
            if container_missing or heartbeat_stale or old_run_without_heartbeat:
                run["status"] = "stopped"
                run["ended_at"] = utc_now()
                run["returncode"] = None
                changed = True
        if changed:
            running_run = next(
                (run for run in state.get("runs", []) if isinstance(run, dict) and run.get("status") == "running"),
                None,
            )
            if running_run:
                state["status"] = "running"
                state["active_agent"] = running_run.get("agent")
            else:
                state["status"] = "stopped"
                state["active_agent"] = None
            state["last_returncode"] = None
            save_state(challenge_dir, state)


def challenge_status(
    challenge_dir: Path,
    solved_ids: set[int] | None = None,
    raw_log_limit: int = 12_000,
    include_logs: bool = False,
    detail_view: str = "Runs",
) -> dict[str, Any]:
    challenge = load_challenge(challenge_dir)
    state = load_state(challenge_dir)
    runs = state.get("runs", [])
    solved = challenge.id in (solved_ids or set())
    row = {
        "slug": challenge_dir.name,
        "workspace": str(challenge_dir.resolve()),
        "id": challenge.id,
        "name": challenge.name,
        "category": challenge.category,
        "value": challenge.value,
        "connection_info": challenge.connection_info,
        "status": state.get("status", "downloaded"),
        "solved": solved,
        "active_agent": state.get("active_agent"),
        "last_returncode": state.get("last_returncode"),
        "flag_candidates": state.get("flag_candidates", []),
        "updated_at": state.get("updated_at"),
        "runs": runs,
    }
    if include_logs and detail_view == "Claude activity":
        claude_log_for_activity = tail_text(challenge_dir / "claude.log", ACTIVITY_LOG_LIMIT)
        row.update({"claude_activity_events": parse_claude_stream(claude_log_for_activity)})
    elif include_logs and detail_view == "Claude raw":
        row.update({"claude_log_tail": tail_text(challenge_dir / "claude.log", raw_log_limit)})
    elif include_logs and detail_view == "Claude last":
        row.update({"claude_last_message": tail_text(challenge_dir / "claude-last-message.txt", 12000)})
    elif include_logs and detail_view == "Codex activity":
        codex_log_for_activity = tail_text(challenge_dir / "codex.log", ACTIVITY_LOG_LIMIT)
        row.update({"codex_activity_events": parse_codex_stream(codex_log_for_activity)})
    elif include_logs and detail_view == "Codex raw":
        row.update({"codex_log_tail": tail_text(challenge_dir / "codex.log", raw_log_limit)})
    elif include_logs and detail_view == "Codex last":
        row.update({"codex_last_message": tail_text(challenge_dir / "codex-last-message.txt", 12000)})
    return row


def collect_dashboard(
    output_dir: Path,
    raw_log_limit: int = 12_000,
    detail_slugs: set[str] | None = None,
    detail_views: dict[str, str] | None = None,
) -> list[dict[str, Any]]:
    reconcile_stale_runs(output_dir)
    harness_state = load_harness_state(output_dir)
    solved_ids = {
        int(challenge_id)
        for challenge_id in harness_state.get("solved_challenge_ids", [])
        if isinstance(challenge_id, int) or str(challenge_id).isdigit()
    }
    rows: list[dict[str, Any]] = []
    detail_slugs = detail_slugs or set()
    detail_views = detail_views or {}
    for challenge_dir in challenge_dirs(output_dir):
        try:
            rows.append(
                challenge_status(
                    challenge_dir,
                    solved_ids=solved_ids,
                    raw_log_limit=raw_log_limit,
                    include_logs=challenge_dir.name in detail_slugs,
                    detail_view=detail_views.get(challenge_dir.name, "Runs"),
                )
            )
        except HarnessError as exc:
            rows.append({"slug": challenge_dir.name, "name": challenge_dir.name, "status": "error", "error": str(exc), "runs": []})
    return sorted(
        rows,
        key=lambda row: (
            str(row.get("category") or "zzz").casefold(),
            row.get("value") if isinstance(row.get("value"), int) else 10**9,
            str(row.get("name") or "").casefold(),
        ),
    )


def harness_state_path(output_dir: Path) -> Path:
    return output_dir / HARNESS_STATE_FILENAME


def load_harness_state(output_dir: Path) -> dict[str, Any]:
    state = read_json(harness_state_path(output_dir), {})
    return state if isinstance(state, dict) else {}


def update_harness_state(output_dir: Path, **updates: Any) -> None:
    output_dir.mkdir(parents=True, exist_ok=True)
    state = load_harness_state(output_dir)
    state.update(updates)
    state["updated_at"] = utc_now()
    write_json(harness_state_path(output_dir), state)
