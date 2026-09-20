"""Tests for T61/T62/T65-T69: workdir resolution, AuthError, platform registry."""
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

import pytest


# Test 1: resolve_workdir() raises WorkdirError when no env set
def test_resolve_workdir_raises_when_nothing_set(monkeypatch, tmp_path):
    monkeypatch.delenv("CTF_WORKDIR", raising=False)
    monkeypatch.delenv("CTFTOOLKIT_WORKSPACE", raising=False)
    # Also ensure config file doesn't interfere - point it to a nonexistent path
    from ctf_harness_app.config import resolve_workdir, WorkdirError
    with pytest.raises(WorkdirError):
        resolve_workdir()


# Test 2: cli_flag takes top priority
def test_resolve_workdir_cli_flag_priority(monkeypatch, tmp_path):
    monkeypatch.setenv("CTF_WORKDIR", str(tmp_path / "env_dir"))
    from ctf_harness_app.config import resolve_workdir
    result = resolve_workdir(cli_flag=str(tmp_path / "cli_dir"))
    assert result == (tmp_path / "cli_dir").resolve()


# Test 3: CTF_WORKDIR env var works
def test_resolve_workdir_env_var(monkeypatch, tmp_path):
    monkeypatch.setenv("CTF_WORKDIR", str(tmp_path / "my_workdir"))
    monkeypatch.delenv("CTFTOOLKIT_WORKSPACE", raising=False)
    from ctf_harness_app.config import resolve_workdir
    result = resolve_workdir()
    assert result == (tmp_path / "my_workdir").resolve()


# Test 4: in-repo path is rejected
def test_resolve_workdir_rejects_repo_path(monkeypatch):
    from ctf_harness_app.config import resolve_workdir, WorkdirError, REPO_ROOT
    monkeypatch.setenv("CTF_WORKDIR", str(REPO_ROOT / "subdir"))
    monkeypatch.delenv("CTFTOOLKIT_WORKSPACE", raising=False)
    with pytest.raises(WorkdirError, match="outside the repo"):
        resolve_workdir()


# Test 5: AuthError is importable and is an Exception
def test_auth_error_is_exception():
    from ctf_harness_app.platforms import AuthError
    err = AuthError("bad creds")
    assert isinstance(err, Exception)
    assert str(err) == "bad creds"


# Test 6: platform registry lookup
def test_platform_registry_all_three():
    from ctf_harness_app.platforms import get_connector, list_platforms
    platforms = {p["id"] for p in list_platforms()}
    assert platforms == {"ctfd", "rctf", "manual"}
    for pid in ("ctfd", "rctf", "manual"):
        c = get_connector(pid)
        assert c is not None


# Test 7: unknown platform raises ValueError
def test_platform_registry_unknown_raises():
    from ctf_harness_app.platforms import get_connector
    with pytest.raises(ValueError, match="Unknown platform"):
        get_connector("bogus")
