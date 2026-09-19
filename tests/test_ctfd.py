import pytest
from unittest.mock import patch, MagicMock
from pathlib import Path
import urllib.error

from ctf_harness_app.ctfd import (
    normalize_base_url,
    strip_html,
    filename_from_url,
    filename_from_headers,
    challenge_from_raw,
    challenge_from_metadata,
    Challenge,
    CTFdClient,
    HarnessError,
)


def test_normalize_base_url():
    assert normalize_base_url("https://ctf.example.com/challenges") == "https://ctf.example.com"
    assert normalize_base_url("http://localhost:8000/api/v1") == "http://localhost:8000"
    assert normalize_base_url("ctf.example.com") == "ctf.example.com"


def test_strip_html():
    assert strip_html("<p>Hello <br/>World!</p>") == "Hello \nWorld!"
    assert strip_html("No HTML here") == "No HTML here"
    assert strip_html("Link <a href='#'>here</a>") == "Link here"


def test_filename_from_url():
    assert filename_from_url("https://example.com/files/flag.txt") == "flag.txt"
    assert filename_from_url("https://example.com/files/some%20file.bin") == "some-file.bin"
    assert filename_from_url("https://example.com/") == "attachment.bin"


def test_filename_from_headers():
    headers = {"Content-Disposition": "attachment; filename=\"correct_file.zip\""}
    assert filename_from_headers(headers) == "correct_file.zip"

    headers_utf8 = {"Content-Disposition": "attachment; filename*=UTF-8''special-char.txt"}
    assert filename_from_headers(headers_utf8) == "special-char.txt"

    assert filename_from_headers({}) is None
    assert filename_from_headers({"Content-Disposition": "inline"}) is None


def test_challenge_from_raw():
    raw = {
        "id": 42,
        "name": "Super Challenge",
        "category": "Pwn",
        "value": 100,
        "description": "Solve <p>this</p>",
        "connection_info": "nc pwn.ctf 1337",
        "files": ["/files/abcd/run.sh"],
        "tags": [{"value": "easy"}, "binary"],
        "hints": [{"cost": 0, "content": "Look at the main func"}],
    }
    chal = challenge_from_raw(42, raw)
    assert chal.id == 42
    assert chal.name == "Super Challenge"
    assert chal.category == "Pwn"
    assert chal.value == 100
    assert chal.description == "Solve <p>this</p>"
    assert chal.connection_info == "nc pwn.ctf 1337"
    assert chal.files == ["/files/abcd/run.sh"]
    assert chal.tags == ["easy", "binary"]
    assert chal.hints == [{"cost": 0, "content": "Look at the main func"}]
    assert chal.slug == "0042-pwn-super-challenge"


def test_challenge_from_metadata():
    metadata = {
        "id": 10,
        "name": "crypto-1",
        "category": "Crypto",
        "value": 50,
        "description": "Decode this",
        "connection_info": None,
        "files": ["file1.txt"],
        "tags": ["xor"],
        "hints": [],
        "raw": {"some_extra": "info"},
    }
    chal = challenge_from_metadata(metadata)
    assert chal.id == 10
    assert chal.name == "crypto-1"
    assert chal.slug == "0010-crypto-crypto-1"


@patch("urllib.request.urlopen")
def test_ctfd_client_api_get(mock_urlopen):
    # Mock response
    mock_resp = MagicMock()
    mock_resp.read.return_value = b'{"success": true, "data": {"key": "val"}}'
    mock_resp.headers = {"Content-Type": "application/json"}
    mock_urlopen.return_value.__enter__.return_value = mock_resp

    client = CTFdClient("https://ctf.example.com", token="mytoken")
    res = client.api_get("/api/v1/some-endpoint")
    assert res == {"success": True, "data": {"key": "val"}}

    # Verify authorization header is passed
    args, kwargs = mock_urlopen.call_args
    req = args[0]
    assert req.headers["Authorization"] == "Token mytoken"


@patch("urllib.request.urlopen")
def test_ctfd_client_retry_logic(mock_urlopen):
    # Mock behavior to fail twice with HTTP 502, then succeed
    mock_err = urllib.error.HTTPError(
        url="https://ctf.example.com/api/v1/test",
        code=502,
        msg="Bad Gateway",
        hdrs=None,
        fp=MagicMock()
    )
    mock_err.fp.read.return_value = b"Gateway error"

    mock_resp = MagicMock()
    mock_resp.read.return_value = b'{"success": true}'
    mock_resp.headers = {"Content-Type": "application/json"}
    mock_resp.__enter__.return_value = mock_resp
    mock_urlopen.side_effect = [mock_err, mock_err, mock_resp]


    client = CTFdClient("https://ctf.example.com", timeout=1)
    
    # We mock time.sleep to run tests quickly without waiting
    with patch("time.sleep") as mock_sleep:
        res = client.api_get("/api/v1/test")
        assert res == {"success": True}
        assert mock_urlopen.call_count == 3
        assert mock_sleep.call_count == 2
        mock_sleep.assert_any_call(1)
        mock_sleep.assert_any_call(2)


@patch("urllib.request.urlopen")
def test_ctfd_client_retry_logic_failure(mock_urlopen):
    # Mock behavior to fail consistently
    mock_err = urllib.error.HTTPError(
        url="https://ctf.example.com/api/v1/test",
        code=500,
        msg="Internal Server Error",
        hdrs=None,
        fp=MagicMock()
    )
    mock_err.fp.read.return_value = b"Internal Server Error"
    mock_urlopen.side_effect = mock_err

    client = CTFdClient("https://ctf.example.com", timeout=1)
    
    with patch("time.sleep") as mock_sleep:
        with pytest.raises(HarnessError) as exc_info:
            client.api_get("/api/v1/test")
        assert "HTTP 500" in str(exc_info.value)
        assert mock_urlopen.call_count == 3




# ---- Challenge folder-name (Bryan's <YEAR> <CTF NAME>/<challenge>/ layout) ----


def test_challenge_folder_name_uses_raw_name_by_default(monkeypatch) -> None:
    from ctf_harness_app.ctfd import Challenge
    monkeypatch.delenv("CTF_HARNESS_CHALLENGE_LAYOUT", raising=False)
    c = Challenge(
        id=42, name="Go Going Goen", category="Misc", value=100,
        description="", connection_info=None, files=[], tags=[], hints=[], raw={},
    )
    assert c.folder_name == "Go Going Goen"


def test_challenge_folder_name_sanitizes_windows_invalid_chars(monkeypatch) -> None:
    from ctf_harness_app.ctfd import Challenge
    monkeypatch.delenv("CTF_HARNESS_CHALLENGE_LAYOUT", raising=False)
    c = Challenge(
        id=1, name='Path?Traversal: <hack> | attack', category="Web", value=100,
        description="", connection_info=None, files=[], tags=[], hints=[], raw={},
    )
    # Colons, slashes, angle brackets, pipes, question marks all stripped.
    fn = c.folder_name
    for bad in '<>:"/\\|?*':
        assert bad not in fn, f"{bad!r} should be stripped: {fn!r}"
    assert "Path" in fn and "attack" in fn


def test_challenge_folder_name_falls_back_to_slug_when_name_empty() -> None:
    from ctf_harness_app.ctfd import Challenge
    c = Challenge(
        id=7, name="?????", category="crypto", value=0,
        description="", connection_info=None, files=[], tags=[], hints=[], raw={},
    )
    # After stripping ? chars, name is empty — falls back to slug id-cat-slugify(name).
    assert c.folder_name == c.slug


def test_challenge_folder_name_layout_env_override(monkeypatch) -> None:
    from ctf_harness_app.ctfd import Challenge
    c = Challenge(
        id=5, name="Whistle", category="Forensics", value=200,
        description="", connection_info=None, files=[], tags=[], hints=[], raw={},
    )
    monkeypatch.setenv("CTF_HARNESS_CHALLENGE_LAYOUT", "slug")
    assert c.folder_name == c.slug  # legacy layout
    monkeypatch.setenv("CTF_HARNESS_CHALLENGE_LAYOUT", "name")
    assert c.folder_name == "Whistle"


def test_sanitize_folder_name_edge_cases() -> None:
    from ctf_harness_app.util import sanitize_folder_name
    assert sanitize_folder_name("Simple Name") == "Simple Name"
    assert sanitize_folder_name("With/slash") == "Withslash"
    assert sanitize_folder_name("trailing dots...") == "trailing dots"
    assert sanitize_folder_name("   ") == "challenge"  # fallback
    assert sanitize_folder_name("", fallback="fallback-id") == "fallback-id"
