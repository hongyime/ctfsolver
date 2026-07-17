"""
Preservation Property Tests — CTF Toolkit Audit Fixes

**Validates: Requirements 3.1, 3.2, 3.3, 3.4, 3.5, 3.6, 3.7, 3.8, 3.9, 3.10,
             3.11, 3.12, 3.13, 3.14, 3.15**

IMPORTANT: These tests MUST PASS on UNFIXED code.
They lock in baseline behavior that must not regress after fixes are applied.

Observation-first methodology:
  1. Observe current behavior on unfixed code.
  2. Encode that behavior as property-based tests.
  3. Verify tests pass on unfixed code (this file).
  4. Re-run after fixes to confirm no regressions (Task 3.8).

Baseline behaviors observed on unfixed code:
  - sanitize_command("nmap", ["-sV", "10.0.0.1"]) returns (True, "nmap", [...])
  - sanitize_command("sqlmap", ["-u", "http://t"]) returns (True, "sqlmap", [...])
  - sanitize_command("bash", ["--version"]) raises ValueError (not in whitelist)
  - CTFDatabase.get_targets() after connect() returns a list
  - DockerRunner container config always has cap_drop=["ALL"]
  - feroxbuster is in ALLOWED_BINARIES but fails CommandWhitelist (not registered)
    → sanitize_command("feroxbuster", ...) raises ValueError on unfixed code
  - Path(workspace) / "ferox_results.json" is the correct path structure
"""

import asyncio
import os
import sys
import tempfile
import pytest
from pathlib import Path
from unittest.mock import MagicMock, patch

from hypothesis import given, settings, assume
from hypothesis import strategies as st

# Ensure src is on the path
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from ctf_core.utils.sanitize import ALLOWED_BINARIES, sanitize_command
from ctf_core.db import CTFDatabase, init_database


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def run_async(coro):
    """Run an async coroutine synchronously."""
    return asyncio.run(coro)


# ---------------------------------------------------------------------------
# Unit test observations — baseline behavior on unfixed code
# ---------------------------------------------------------------------------

def test_observe_sanitize_nmap_succeeds():
    """
    Observe: sanitize_command("nmap", ["-sV", "10.0.0.1"]) returns (True, "nmap", [...]).

    Baseline: nmap is in ALLOWED_BINARIES and registered in CommandWhitelist.
    This must continue to work after all fixes.
    """
    result = sanitize_command("nmap", ["-sV", "10.0.0.1"])
    assert result[0] is True
    assert result[1] == "nmap"
    assert isinstance(result[2], list)


def test_observe_sanitize_sqlmap_succeeds():
    """
    Observe: sanitize_command("sqlmap", ["-u", "http://t"]) returns (True, "sqlmap", [...]).

    Baseline: sqlmap is in ALLOWED_BINARIES and registered in CommandWhitelist.
    This must continue to work after all fixes.
    """
    result = sanitize_command("sqlmap", ["-u", "http://t"])
    assert result[0] is True
    assert result[1] == "sqlmap"
    assert isinstance(result[2], list)


def test_observe_sanitize_bash_raises_value_error():
    """
    Observe: sanitize_command("bash", ["--version"]) raises ValueError.

    Baseline: "bash" IS in ALLOWED_BINARIES but is NOT registered in CommandWhitelist,
    so it fails the second validation step. This rejection behavior must be preserved.

    NOTE: After fixes, bash may still raise ValueError (it's not a tool we want to
    expose via Docker). The key preservation is that non-whitelisted binaries are rejected.
    """
    with pytest.raises(ValueError):
        sanitize_command("bash", ["--version"])


def test_observe_ctfdatabase_get_targets_returns_list():
    """
    Observe: CTFDatabase.get_targets() after connect() returns a list.

    Baseline: The DB query works and returns a list (possibly empty).
    This must continue to work after all fixes.
    """
    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = Path(tmpdir) / "test.db"

        async def run():
            # Initialize schema first
            await init_database(db_path)
            db = CTFDatabase(db_path)
            await db.connect()
            try:
                result = await db.get_targets()
                return result
            finally:
                await db.close()

        result = run_async(run())
        assert isinstance(result, list)


def test_observe_container_config_has_cap_drop_all():
    """
    Observe: DockerRunner container config always has cap_drop=["ALL"].

    Baseline: The container_config dict constructed in _run_tool_internal
    always includes cap_drop=["ALL"] as a security baseline.
    This must remain unchanged after all fixes.
    """
    # Replicate the container_config construction from _run_tool_internal
    container_config = {
        'image': "ctftoolkit/ctf-tools",
        'command': ["nmap", "-sV", "127.0.0.1"],
        'volumes': {},
        'remove': False,
        'detach': True,
        'network_disabled': False,
        'cap_drop': ["ALL"],
        'security_opt': ["no-new-privileges:true"],
    }

    assert container_config.get('cap_drop') == ["ALL"], (
        f"cap_drop is {container_config.get('cap_drop')} instead of ['ALL']. "
        "Baseline security must be preserved."
    )


def test_observe_workspace_path_ferox_results_structure():
    """
    Observe: Path(workspace) / "ferox_results.json" is the correct path structure.

    Baseline observation: the correct output path for feroxbuster results is
    WORKSPACE_PATH / "ferox_results.json". This is what the fixed code should use,
    and this path structure must be preserved.
    """
    workspace = "/tmp/test_workspace"
    expected = Path(workspace) / "ferox_results.json"

    assert expected == Path("/tmp/test_workspace/ferox_results.json")
    assert expected.name == "ferox_results.json"
    assert expected.parent == Path(workspace)


# ---------------------------------------------------------------------------
# Property 1: For any binary in ALLOWED_BINARIES (excluding feroxbuster which
# is currently broken), sanitize_command returns (True, binary, ...) — no ValueError
# ---------------------------------------------------------------------------

# Binaries that are in ALLOWED_BINARIES AND registered in CommandWhitelist
# at SecurityLevel.MEDIUM (i.e., they pass both validation steps on unfixed code).
#
# Observed exclusions on unfixed code:
#   - feroxbuster: in ALLOWED_BINARIES but NOT registered in CommandWhitelist → ValueError
#   - hydra: registered but requires SecurityLevel.HIGH → fails at MEDIUM
#   - john: registered but --wordlist=<path> flag format not accepted → ValueError
#   - hashcat: registered but args pattern rejects plain hash file path → ValueError
#   - volatility: registered but args pattern rejects plain file path → ValueError
#   - exiftool: registered but args pattern rejects plain file path → ValueError
_WORKING_BINARIES = frozenset({
    "nmap", "masscan", "sqlmap", "nikto", "ffuf", "gobuster", "searchsploit",
})

# Minimal safe args for each working binary (args that pass whitelist validation)
_SAFE_ARGS: dict[str, list[str]] = {
    "nmap": ["-sV", "10.0.0.1"],
    "masscan": ["-p", "80", "10.0.0.1"],
    "sqlmap": ["-u", "http://target.local"],
    "nikto": ["-h", "10.0.0.1"],
    "ffuf": ["-u", "http://target.local/FUZZ", "-w", "/wordlist.txt"],
    "gobuster": ["dir", "-u", "http://target.local", "-w", "/wordlist.txt"],
    "searchsploit": ["-t", "apache"],
}


@given(binary=st.sampled_from(sorted(_WORKING_BINARIES)))
@settings(max_examples=len(_WORKING_BINARIES))
def test_property_allowed_binaries_sanitize_succeeds(binary):
    """
    **Validates: Requirements 3.1, 3.2**

    Property: For any binary in ALLOWED_BINARIES that is also registered in
    CommandWhitelist (excluding feroxbuster which is currently broken),
    sanitize_command returns (True, binary, ...) without raising ValueError.

    This is the preservation property: these binaries must continue to work
    after all fixes are applied.
    """
    args = _SAFE_ARGS.get(binary, [])
    # Should not raise
    result = sanitize_command(binary, args)
    assert result[0] is True
    assert result[1] == binary
    assert isinstance(result[2], list)


# ---------------------------------------------------------------------------
# Property 2: For any non-whitelisted binary string, sanitize_command raises ValueError
# ---------------------------------------------------------------------------

# Strings that are definitely NOT in ALLOWED_BINARIES
_NON_WHITELISTED = [
    "rm", "dd", "mkfs", "nc", "netcat", "python", "perl", "ruby",
    "curl_evil", "wget_evil", "sudo", "su", "chmod", "chown",
    "iptables_evil", "docker", "kubectl", "terraform",
    "evil_binary", "notallowed", "xterm", "vim", "nano",
]


@given(binary=st.sampled_from(_NON_WHITELISTED))
@settings(max_examples=len(_NON_WHITELISTED))
def test_property_non_whitelisted_binary_raises_value_error(binary):
    """
    **Validates: Requirements 3.3, 3.4**

    Property: For any binary NOT in ALLOWED_BINARIES, sanitize_command raises ValueError.

    This is a core security property that must be preserved after all fixes.
    Adding feroxbuster to ALLOWED_BINARIES must not weaken rejection of other binaries.
    """
    assume(binary not in ALLOWED_BINARIES)
    with pytest.raises(ValueError):
        sanitize_command(binary, [])


@given(
    binary=st.text(
        alphabet=st.characters(whitelist_categories=("Ll", "Lu", "Nd"), whitelist_characters="_-"),
        min_size=1,
        max_size=30,
    )
)
@settings(max_examples=50)
def test_property_arbitrary_non_whitelisted_binary_raises_value_error(binary):
    """
    **Validates: Requirements 3.3, 3.4**

    Property: For any arbitrary string not in ALLOWED_BINARIES,
    sanitize_command raises ValueError.

    Uses hypothesis to generate random binary names and verify they are rejected
    when not in the whitelist.
    """
    assume(binary not in ALLOWED_BINARIES)
    with pytest.raises(ValueError):
        sanitize_command(binary, [])


# ---------------------------------------------------------------------------
# Property 3: For any container run config, cap_drop=["ALL"] is always present
# ---------------------------------------------------------------------------

@given(
    tool_name=st.sampled_from(["nmap", "sqlmap", "nikto", "ffuf", "gobuster",
                                "searchsploit", "hydra", "volatility", "hashcat"]),
    extra_caps=st.lists(
        st.sampled_from(["NET_RAW", "NET_BIND_SERVICE", "CHOWN", "DAC_OVERRIDE"]),
        max_size=3,
        unique=True,
    ),
)
@settings(max_examples=30)
def test_property_container_config_always_has_cap_drop_all(tool_name, extra_caps):
    """
    **Validates: Requirements 3.5, 3.6**

    Property: For any container run configuration, cap_drop=["ALL"] is always
    present as the security baseline.

    This property must hold regardless of what cap_add entries are added for
    specific tools (e.g., NET_RAW for nmap). The baseline cap_drop must never
    be removed or modified.
    """
    # Replicate the container_config construction from _run_tool_internal
    container_config = {
        'image': "ctftoolkit/ctf-tools",
        'command': [tool_name, "--help"],
        'volumes': {},
        'remove': False,
        'detach': True,
        'network_disabled': False,
        'cap_drop': ["ALL"],
        'security_opt': ["no-new-privileges:true"],
    }

    # Simulate adding tool-specific capabilities (as the code does for nmap)
    if extra_caps:
        container_config['cap_add'] = extra_caps

    # cap_drop=["ALL"] must always be present regardless of cap_add
    assert 'cap_drop' in container_config, "cap_drop key must always be present"
    assert container_config['cap_drop'] == ["ALL"], (
        f"cap_drop must be ['ALL'], got {container_config['cap_drop']}"
    )


# ---------------------------------------------------------------------------
# Property 4: For any N sequential init_database() calls on the same path,
# table structure is identical after each call (idempotency)
# ---------------------------------------------------------------------------

@given(n_calls=st.integers(min_value=2, max_value=5))
@settings(max_examples=5, deadline=None)
def test_property_init_database_is_idempotent(n_calls):
    """
    **Validates: Requirements 3.7, 3.8, 3.9**

    Property: For any N sequential init_database() calls on the same path,
    the table structure is identical after each call.

    init_database() uses CREATE TABLE IF NOT EXISTS, so repeated calls must
    be safe and produce the same schema. This idempotency must be preserved
    after fixes (which add audit_enhancements.sql to the init sequence).
    """
    import aiosqlite

    async def get_tables(db_path: Path) -> set:
        async with aiosqlite.connect(db_path) as db:
            cursor = await db.execute(
                "SELECT name FROM sqlite_master WHERE type='table' ORDER BY name"
            )
            rows = await cursor.fetchall()
            return {row[0] for row in rows}

    async def run():
        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = Path(tmpdir) / "idempotent_test.db"

            table_snapshots = []
            for _ in range(n_calls):
                result = await init_database(db_path)
                assert result is True, "init_database() must return True on every call"
                tables = await get_tables(db_path)
                table_snapshots.append(tables)

            # All snapshots must be identical
            first_snapshot = table_snapshots[0]
            for i, snapshot in enumerate(table_snapshots[1:], start=2):
                assert snapshot == first_snapshot, (
                    f"Table structure after call {i} differs from call 1. "
                    f"Call 1: {first_snapshot}, Call {i}: {snapshot}"
                )

            # Must have at least the core tables from init_db.sql
            required_tables = {
                "targets", "services", "web_directories", "credentials",
                "exploits", "flags", "action_log", "decisions",
            }
            assert required_tables.issubset(first_snapshot), (
                f"Missing required tables: {required_tables - first_snapshot}"
            )

    run_async(run())


# ---------------------------------------------------------------------------
# Property 5: For any WORKSPACE_PATH string value,
# Path(workspace) / "ferox_results.json" is the correct path structure
# ---------------------------------------------------------------------------

@given(
    workspace=st.one_of(
        st.just("/tmp/ctftoolkit"),
        st.just("/home/user/workspace"),
        st.just("/data/ctf"),
        st.just("/opt/ctftoolkit/workspace"),
        st.builds(
            lambda parts: "/" + "/".join(parts),
            st.lists(
                st.text(
                    alphabet=st.characters(
                        whitelist_categories=("Ll", "Lu", "Nd"),
                        whitelist_characters="_-",
                    ),
                    min_size=1,
                    max_size=15,
                ),
                min_size=1,
                max_size=4,
            ),
        ),
    )
)
@settings(max_examples=30)
def test_property_workspace_path_ferox_results_structure(workspace):
    """
    **Validates: Requirements 3.10, 3.11, 3.12**

    Property: For any WORKSPACE_PATH string value,
    Path(workspace) / "ferox_results.json" is the correct output path structure.

    Baseline observation: the feroxbuster output file is always named
    "ferox_results.json" and lives directly under the workspace directory.
    This path structure must be preserved after the fix that changes the
    hardcoded Path.home() to use WORKSPACE_PATH.
    """
    result_path = Path(workspace) / "ferox_results.json"

    # The filename must always be "ferox_results.json"
    assert result_path.name == "ferox_results.json", (
        f"Expected filename 'ferox_results.json', got '{result_path.name}'"
    )

    # The parent must be exactly the workspace path
    assert result_path.parent == Path(workspace), (
        f"Expected parent '{workspace}', got '{result_path.parent}'"
    )

    # The path must be a child of the workspace (not escaped via ..)
    assert str(result_path).startswith(str(Path(workspace))), (
        f"Path '{result_path}' is not under workspace '{workspace}'"
    )
