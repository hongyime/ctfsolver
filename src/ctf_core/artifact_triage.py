"""Safe first-pass artifact triage helpers.

This module only reads bytes from the requested file. It computes hashes,
recognizes lightweight stdlib-friendly signatures, extracts bounded printable
string samples, and asks the workflow helper for next-tool recommendations.
"""

from __future__ import annotations

from hashlib import sha256
from pathlib import Path
from typing import Any

from .workflows import suggest_next_tools


_SAMPLE_BYTES = 1024 * 1024
_HASH_CHUNK_BYTES = 1024 * 1024
_PRINTABLE = set(range(32, 127)) | {9}


def triage_artifact(
    path: str | Path,
    *,
    max_sample_bytes: int = _SAMPLE_BYTES,
    max_strings: int = 20,
    min_string_length: int = 4,
) -> dict[str, Any]:
    """Hash, identify, and safely summarize a local artifact.

    The helper never executes the artifact and never invokes Docker. Large files
    are hashed fully, while string extraction and type hints use a bounded byte
    sample from the beginning of the file.
    """

    artifact_path = Path(path)
    digest, size, sample = _hash_and_sample(artifact_path, max_sample_bytes)
    suffix = artifact_path.suffix.lower()
    type_hints = _detect_type_hints(sample, suffix)
    string_samples = _extract_printable_strings(
        sample,
        limit=max_strings,
        min_length=min_string_length,
    )
    category_hint = _infer_category(type_hints, suffix, string_samples)
    recommendations = suggest_next_tools(
        description=f"Artifact triage for {artifact_path.name}",
        category=category_hint,
        files=[artifact_path.name],
        findings=[*type_hints, *string_samples],
    )

    return {
        "path": str(artifact_path),
        "name": artifact_path.name,
        "sha256": digest,
        "size": size,
        "suffix": suffix,
        "type_hints": type_hints,
        "category_hint": category_hint,
        "string_samples": string_samples,
        "printable_strings": string_samples,
        "recommended_next_tools": recommendations,
    }


def _hash_and_sample(path: Path, max_sample_bytes: int) -> tuple[str, int, bytes]:
    digest = sha256()
    sample = bytearray()
    size = 0
    sample_budget = max(0, max_sample_bytes)

    with path.open("rb") as handle:
        while True:
            chunk = handle.read(_HASH_CHUNK_BYTES)
            if not chunk:
                break
            digest.update(chunk)
            size += len(chunk)
            if len(sample) < sample_budget:
                sample.extend(chunk[: sample_budget - len(sample)])

    return digest.hexdigest(), size, bytes(sample)


def _detect_type_hints(data: bytes, suffix: str) -> list[str]:
    hints: list[str] = []

    def add(hint: str) -> None:
        if hint not in hints:
            hints.append(hint)

    if data.startswith(b"\x7fELF"):
        add("elf executable")
    if data.startswith(b"MZ"):
        add("pe executable")
    if data.startswith(b"\x00asm"):
        add("webassembly module")
    if data.startswith(b"\x89PNG\r\n\x1a\n"):
        add("png image")
    if data.startswith(b"\xff\xd8\xff"):
        add("jpeg image")
    if data.startswith((b"GIF87a", b"GIF89a")):
        add("gif image")
    if data.startswith(b"%PDF-"):
        add("pdf document")
    if data.startswith(b"PK\x03\x04"):
        add("zip archive")
    if data.startswith(b"\x1f\x8b"):
        add("gzip archive")
    if data.startswith(b"7z\xbc\xaf\x27\x1c"):
        add("7z archive")
    if data.startswith(b"Rar!\x1a\x07"):
        add("rar archive")
    if data.startswith((b"\xd4\xc3\xb2\xa1", b"\xa1\xb2\xc3\xd4", b"\x4d\x3c\xb2\xa1", b"\xa1\xb2\x3c\x4d")):
        add("pcap capture")
    if data.startswith(b"\x0a\x0d\x0d\x0a"):
        add("pcapng capture")
    if data.startswith(b"SQLite format 3\x00"):
        add("sqlite database")
    if data.startswith(b"OggS"):
        add("ogg media")
    if data.startswith(b"ID3"):
        add("mp3 audio")
    if data.startswith(b"RIFF") and data[8:12] == b"WAVE":
        add("wave audio")
    if len(data) > 262 and data[257:263] == b"ustar\x00":
        add("tar archive")

    if _looks_like_text(data):
        add("text")
        text = data[:4096].decode("utf-8", errors="ignore").lower()
        if "-----begin " in text and "key-----" in text:
            add("pem key")
        if "<html" in text or "<?php" in text or "<script" in text:
            add("web source")
        if "rsa" in text or "modulus" in text or "ciphertext" in text:
            add("crypto material")

    suffix_hint = {
        ".bmp": "bitmap image",
        ".cap": "pcap capture",
        ".elf": "elf executable",
        ".exe": "pe executable",
        ".jpg": "jpeg image",
        ".jpeg": "jpeg image",
        ".pcap": "pcap capture",
        ".pcapng": "pcapng capture",
        ".pem": "pem key",
        ".png": "png image",
        ".pub": "pem key",
        ".wasm": "webassembly module",
        ".wav": "wave audio",
        ".zip": "zip archive",
    }.get(suffix)
    if suffix_hint:
        add(suffix_hint)

    if not hints:
        add("unknown binary" if b"\x00" in data else "unknown")
    return hints


def _extract_printable_strings(
    data: bytes,
    *,
    limit: int,
    min_length: int,
    max_length: int = 160,
) -> list[str]:
    strings: list[str] = []
    current = bytearray()

    def flush() -> None:
        if len(current) < min_length:
            current.clear()
            return
        value = current.decode("ascii", errors="ignore").strip()
        current.clear()
        if not value or value in strings:
            return
        if len(value) > max_length:
            value = value[: max_length - 3] + "..."
        strings.append(value)

    for byte in data:
        if byte in _PRINTABLE:
            current.append(byte)
        else:
            flush()
            if len(strings) >= limit:
                break
    if len(strings) < limit:
        flush()
    return strings[: max(0, limit)]


def _looks_like_text(data: bytes) -> bool:
    if not data:
        return False
    sample = data[:4096]
    if b"\x00" in sample:
        return False
    printable = sum(1 for byte in sample if byte in _PRINTABLE or byte in {10, 13})
    return printable / len(sample) >= 0.85


def _infer_category(type_hints: list[str], suffix: str, strings: list[str]) -> str:
    text = " ".join([*type_hints, suffix, *strings]).lower()
    if any(marker in text for marker in ("png", "jpeg", "gif", "stego", "pcap", "audio", "archive", "pdf", "memory")):
        return "forensics"
    if any(marker in text for marker in ("elf", "pe executable", "webassembly", "binary")):
        return "re"
    if any(marker in text for marker in ("pem key", "rsa", "modulus", "ciphertext", "crypto")):
        return "crypto"
    if any(marker in text for marker in ("web source", "html", "php", "javascript", "http")):
        return "web"
    return ""


__all__ = ["triage_artifact"]
