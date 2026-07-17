"""
Bug Condition Exploration Tests — CTF Toolkit Audit Findings (P0–P4)

**Validates: Requirements 1.1, 1.2, 1.3, 1.4, 1.10, 1.11, 1.12, 1.16, 1.27, 1.28**

CRITICAL: These tests are EXPECTED TO FAIL on unfixed code.
Failure confirms the bugs exist. DO NOT fix the code to make these pass.
After fixes are applied (Task 3), these tests should all PASS.
"""

import asyncio
import os
import sys
import tempfile
import pytest
from pathlib import Path
from unittest.mock import MagicMock, patch

# Ensure src is on the path
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))


# ---------------------------------------------------------------------------
# P0-001: userns_mode must NOT be present in container_config on Linux
# ---------------------------------------------------------------------------

def test_p0_001_no_userns_mode_on_linux():
    """
    P0-001: docker_runner._run_tool_internal must NOT set userns_mode='host'.
    Reads the actual source to verify the fix is in place.
    """
    import inspect
    import ctf_core.docker_runner as dr_module

    source = inspect.getsource(dr_module.DockerRunner._run_tool_internal)
    assert "userns_mode" not in source, (
        "BUG P0-001: 'userns_mode' still present in _run_tool_internal source. "
        "Container user namespace isolation is disabled on Linux."
    )


# ---------------------------------------------------------------------------
# P0-002: container_config['remove'] must be True
# ---------------------------------------------------------------------------

def test_p0_002_container_remove_is_true():
    """
    P0-002: container_config must use 'remove': True so Docker auto-removes containers.
    Reads the actual source to verify the fix is in place.
    """
    import inspect
    import ctf_core.docker_runner as dr_module

    source = inspect.getsource(dr_module.DockerRunner._run_tool_internal)
    assert "'remove': True" in source or '"remove": True' in source, (
        "BUG P0-002: 'remove': True not found in _run_tool_internal. "
        "Containers will be orphaned if the Python process is killed."
    )


# ---------------------------------------------------------------------------
# P1-001: feroxbuster output path must use WORKSPACE_PATH, not Path.home()
# ---------------------------------------------------------------------------

def test_p1_001_feroxbuster_uses_workspace_path():
    """
    P1-001: run_feroxbuster must read results from WORKSPACE_PATH / 'ferox_results.json'.
    Reads the actual source to verify Path.home() is no longer used.
    """
    server_src = (
        Path(__file__).parent.parent / "src" / "ctf_core" / "server.py"
    ).read_text()

    # Find the run_feroxbuster function body
    start = server_src.find("async def run_feroxbuster(")
    end = server_src.find("\n@mcp.tool()", start)
    func_src = server_src[start:end] if end != -1 else server_src[start:start + 2000]

    assert "Path.home()" not in func_src, (
        "BUG P1-001: run_feroxbuster still uses Path.home() for output path. "
        "The CTFTOOLKIT_WORKSPACE env var is ignored."
    )
    assert "WORKSPACE_PATH" in func_src, (
        "BUG P1-001: run_feroxbuster does not use WORKSPACE_PATH for output path."
    )


# ---------------------------------------------------------------------------
# P1-002: run_searchsploit must use sploit_parser.generate_summary
# ---------------------------------------------------------------------------

def test_p1_002_searchsploit_uses_sploit_parser_summary():
    """
    P1-002: run_searchsploit must call sploit_parser.generate_summary.
    Reads the actual source to verify nmap_parser.generate_summary is not used.
    """
    server_src = (
        Path(__file__).parent.parent / "src" / "ctf_core" / "server.py"
    ).read_text()

    # Find the run_searchsploit function body
    start = server_src.find("async def run_searchsploit(")
    end = server_src.find("\n@mcp.tool()", start)
    func_src = server_src[start:end] if end != -1 else server_src[start:start + 2000]

    assert "sploit_generate_summary" in func_src or "sploit_parser" in func_src, (
        "BUG P1-002: run_searchsploit does not use sploit_parser summary function."
    )


# ---------------------------------------------------------------------------
# P1-008: init_database() must create the network_audit table
# ---------------------------------------------------------------------------

def test_p1_008_init_database_creates_network_audit_table():
    """
    P1-008: init_database() must apply audit_enhancements.sql so that
    the network_audit table exists after initialization.

    Bug: init_database() only applies init_db.sql, never audit_enhancements.sql,
    so AuditLogger raises OperationalError: no such table: network_audit.

    Expected (fixed): network_audit table exists after init_database().
    FAILS on unfixed code because the table is absent.
    """
    import aiosqlite
    from ctf_core.db import init_database

    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = Path(tmpdir) / "test_audit.db"

        # Run init_database on a fresh path
        result = asyncio.run(init_database(db_path))
        assert result is True, "init_database() returned False — schema init failed"

        # Check that network_audit table exists
        async def check_table():
            async with aiosqlite.connect(db_path) as db:
                cursor = await db.execute(
                    "SELECT name FROM sqlite_master WHERE type='table' AND name='network_audit'"
                )
                row = await cursor.fetchone()
                return row is not None

        table_exists = asyncio.run(check_table())

        assert table_exists, (
            "BUG P1-008: 'network_audit' table does not exist after init_database(). "
            "audit_enhancements.sql is never applied."
        )


# ---------------------------------------------------------------------------
# P2-001: CTFDatabase methods before connect() must raise RuntimeError
# ---------------------------------------------------------------------------

def test_p2_001_ctfdatabase_raises_runtime_error_before_connect():
    """
    P2-001: Calling CTFDatabase methods before connect() must raise RuntimeError,
    not AssertionError.

    Bug: All methods use 'assert self._db is not None' which raises AssertionError
    (and is silently stripped in optimized builds with python -O).

    Expected (fixed): RuntimeError("Database not connected. Call connect() first.")
    FAILS on unfixed code because AssertionError is raised instead.
    """
    from ctf_core.db import CTFDatabase

    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = Path(tmpdir) / "test.db"
        db = CTFDatabase(db_path)

        # Call a method without connect() — should raise RuntimeError
        with pytest.raises(RuntimeError, match="not connected"):
            asyncio.run(db.get_targets())


# ---------------------------------------------------------------------------
# P2-002: nmap cap_add must be ['NET_RAW'] only
# ---------------------------------------------------------------------------

def test_p2_002_nmap_cap_add_is_net_raw_only():
    """
    P2-002: nmap container must only add NET_RAW capability, not NET_ADMIN.
    Reads the actual source to verify NET_ADMIN is no longer present.
    """
    import inspect
    import ctf_core.docker_runner as dr_module

    source = inspect.getsource(dr_module.DockerRunner._run_tool_internal)
    assert "NET_ADMIN" not in source, (
        "BUG P2-002: 'NET_ADMIN' still present in _run_tool_internal. "
        "nmap container has excessive network privileges."
    )
    assert "NET_RAW" in source, (
        "BUG P2-002: 'NET_RAW' not found in _run_tool_internal. "
        "nmap requires NET_RAW for raw socket access."
    )


# ---------------------------------------------------------------------------
# P2-006: DockerRunner semaphore must respect CTFTOOLKIT_MAX_CONTAINERS
# ---------------------------------------------------------------------------

def test_p2_006_docker_runner_semaphore_respects_env_var():
    """
    P2-006: When CTFTOOLKIT_MAX_CONTAINERS=3 is set, DockerRunner's semaphore
    must be initialized with value 3.

    Bug: docker_runner.py uses the hardcoded constant MAX_CONCURRENT_CONTAINERS = 5
    and ignores the environment variable.

    Expected (fixed): semaphore value equals int(os.environ['CTFTOOLKIT_MAX_CONTAINERS'])
    FAILS on unfixed code because the semaphore is always 5.
    """
    os.environ["CTFTOOLKIT_MAX_CONTAINERS"] = "3"

    try:
        # Re-import to pick up the env var (module-level constant is set at import time)
        import importlib
        import ctf_core.docker_runner as dr_module
        importlib.reload(dr_module)

        max_containers = dr_module.MAX_CONCURRENT_CONTAINERS

        assert max_containers == 3, (
            f"BUG P2-006: MAX_CONCURRENT_CONTAINERS is {max_containers} "
            "instead of 3. CTFTOOLKIT_MAX_CONTAINERS env var is ignored."
        )
    finally:
        del os.environ["CTFTOOLKIT_MAX_CONTAINERS"]
        # Reload to restore default
        import importlib
        import ctf_core.docker_runner as dr_module
        importlib.reload(dr_module)


# ---------------------------------------------------------------------------
# P4-001: sanitize_command("feroxbuster", ...) must succeed
# ---------------------------------------------------------------------------

def test_p4_001_sanitize_command_allows_feroxbuster():
    """
    P4-001: sanitize_command("feroxbuster", ["-u", "http://t"]) must succeed.

    Bug: "feroxbuster" is absent from ALLOWED_BINARIES in sanitize.py,
    so every call to run_feroxbuster raises ValueError before Docker is even invoked.

    Expected (fixed): sanitize_command returns (True, "feroxbuster", [...])
    FAILS on unfixed code with ValueError: Binary 'feroxbuster' is not in the allowed list.
    """
    from ctf_core.utils.sanitize import sanitize_command

    # This should NOT raise — will FAIL on unfixed code
    result = sanitize_command("feroxbuster", ["-u", "http://t"])

    assert result[0] is True, (
        f"BUG P4-001: sanitize_command('feroxbuster', ...) returned {result} "
        "instead of (True, 'feroxbuster', [...]). "
        "feroxbuster is missing from ALLOWED_BINARIES."
    )
    assert result[1] == "feroxbuster"


# ---------------------------------------------------------------------------
# P4-002: "checksec" must be in TOOL_IMAGES
# ---------------------------------------------------------------------------

def test_p4_002_checksec_in_tool_images():
    """
    P4-002: "checksec" must be present in TOOL_IMAGES.

    Bug: checksec is absent from TOOL_IMAGES in docker_runner.py, so the Planner
    selecting a pwn path raises ValueError: No Docker image configured for tool: checksec.

    Expected (fixed): TOOL_IMAGES["checksec"] == "ctftoolkit/ctf-pwn"
    FAILS on unfixed code because the key is absent.
    """
    from ctf_core.docker_runner import TOOL_IMAGES

    assert "checksec" in TOOL_IMAGES, (
        "BUG P4-002: 'checksec' is not in TOOL_IMAGES. "
        "The Planner will raise ValueError when selecting a pwn path with checksec."
    )
    assert TOOL_IMAGES["checksec"] == "ctftoolkit/ctf-pwn", (
        f"BUG P4-002: TOOL_IMAGES['checksec'] = '{TOOL_IMAGES['checksec']}' "
        "instead of 'ctftoolkit/ctf-pwn'."
    )
