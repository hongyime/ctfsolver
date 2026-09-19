from __future__ import annotations

import json
import os
import re
import time
from pathlib import Path
from typing import Any


class HarnessError(RuntimeError):
    pass


def utc_now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def read_json(path: Path, default: Any) -> Any:
    if not path.exists():
        return default
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise HarnessError(f"Invalid JSON in {path}: {exc}") from exc


def write_json(path: Path, data: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp_path = path.with_suffix(path.suffix + ".tmp")
    tmp_path.write_text(json.dumps(data, indent=2, sort_keys=True), encoding="utf-8")
    tmp_path.replace(path)


def tail_text(path: Path, limit: int = 8192) -> str:
    if not path.exists():
        return ""
    with path.open("rb") as handle:
        handle.seek(0, os.SEEK_END)
        size = handle.tell()
        handle.seek(max(0, size - limit), os.SEEK_SET)
        return handle.read().decode("utf-8", errors="replace")


def slugify(value: str) -> str:
    value = value.strip().lower()
    value = re.sub(r"[^a-z0-9._-]+", "-", value)
    value = re.sub(r"-{2,}", "-", value).strip("-._")
    return value or "challenge"


def sanitize_folder_name(value: str, fallback: str = "challenge") -> str:
    """Turn a raw challenge name into a filesystem-safe folder name.

    Preserves spaces, letter case, and most punctuation so the layout matches
    Bryan's manual `<YEAR> <CTF NAME>/<challenge>/` convention rather than
    lowercase-hyphen slug form. Strips only characters that Windows / most
    filesystems reject in path components.
    """
    invalid = r'[<>:"/\\|?*\x00-\x1f]'
    value = re.sub(invalid, "", value).strip()
    # Windows also treats trailing dots / spaces as invalid on the final segment.
    value = value.rstrip(". ")
    # Bound length so we don't blow the 255-byte per-segment limit.
    if len(value.encode("utf-8", "replace")) > 200:
        value = value.encode("utf-8", "replace")[:200].decode("utf-8", "replace")
    return value or fallback


def unique_path(path: Path) -> Path:
    if not path.exists():
        return path
    for index in range(2, 10_000):
        candidate = path.with_name(f"{path.stem}-{index}{path.suffix}")
        if not candidate.exists():
            return candidate
    raise HarnessError(f"Could not find a free filename for {path}")


def extract_flag_candidates(text: str) -> list[str]:
    candidates = re.findall(r"\b[A-Za-z0-9_.-]{0,32}\{[^{}\s]{4,200}\}", text)
    deduped: list[str] = []
    for candidate in candidates:
        if candidate not in deduped:
            deduped.append(candidate)
    return deduped[:10]

