"""File ingester — walk a directory and register challenge files in the database."""
import hashlib
import os
import shutil
import sys
from pathlib import Path
from typing import Any

from ctf_core.utils.resilience import _SHUTDOWN

# Map MIME-type prefixes/exact strings to suggested CTF tools
_MIME_TO_TOOLS: dict[str, list[str]] = {
    "application/x-executable": ["checksec", "gdb", "radare2"],
    "application/x-sharedlib": ["checksec", "gdb", "radare2"],
    "application/x-elf": ["checksec", "gdb", "radare2"],
    "application/x-mach-binary": ["checksec", "gdb", "radare2"],
    "application/x-dosexec": ["checksec", "radare2"],
    "application/vnd.tcpdump.pcap": ["tshark"],
    "application/x-pcap": ["tshark"],
    "application/zip": ["binwalk"],
    "application/x-tar": ["binwalk"],
    "application/gzip": ["binwalk"],
    "application/x-bzip2": ["binwalk"],
    "application/x-7z-compressed": ["binwalk"],
    "application/x-rar": ["binwalk"],
    "image/": ["exiftool", "binwalk", "strings"],
    "text/": ["strings"],
    "application/octet-stream": ["strings", "binwalk"],
}

_DEFAULT_TOOLS = ["strings"]


def _get_mime_type(path: Path) -> str:
    """Return MIME type using python-magic if available, else a generic fallback."""
    try:
        import magic
        return magic.from_file(str(path), mime=True) or "application/octet-stream"
    except Exception:
        return "application/octet-stream"


def _suggest_tools(mime_type: str) -> list[str]:
    for prefix, tools in _MIME_TO_TOOLS.items():
        if mime_type.startswith(prefix) or mime_type == prefix:
            return tools
    return _DEFAULT_TOOLS


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while True:
            chunk = f.read(8192)
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest()


def _classify_file_type(mime_type: str) -> str:
    if any(mime_type.startswith(p) for p in ("application/x-executable", "application/x-elf", "application/x-mach", "application/x-dosexec", "application/x-sharedlib")):
        return "binary"
    if "pcap" in mime_type:
        return "pcap"
    if mime_type.startswith("image/"):
        return "image"
    if any(mime_type in p for p in ("zip", "tar", "gzip", "bzip2", "7z", "rar")):
        return "archive"
    if mime_type.startswith("text/"):
        return "source"
    return "document"


def ingest_challenge_files(directory_path: str, challenge_id: str) -> dict[str, Any]:
    """Walk directory_path, copy files to workspace/{challenge_id}/, register in DB.

    Returns inventory: {file_name: {type, size, hash, mime_type, suggested_tools}}
    Memory-safe: processes one file at a time, never loads full content into RAM.
    """
    src_dir = Path(directory_path)
    if not src_dir.exists():
        raise ValueError(f"Directory not found: {directory_path}")

    workspace_root = Path(os.environ.get("CTFTOOLKIT_WORKSPACE", "workspace"))
    dest_dir = workspace_root / challenge_id
    dest_dir.mkdir(parents=True, exist_ok=True)

    inventory: dict[str, Any] = {}

    for root, _dirs, files in os.walk(src_dir):
        for file_name in files:
            if _SHUTDOWN.is_set():
                print(f"[STOPPED] Ingestion interrupted after {len(inventory)} files.")
                break

            src_path = Path(root) / file_name
            rel_path = src_path.relative_to(src_dir)
            dest_path = dest_dir / rel_path

            dest_path.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(src_path, dest_path)

            mime_type = _get_mime_type(dest_path)
            file_type = _classify_file_type(mime_type)
            file_size = dest_path.stat().st_size
            sha256 = _sha256(dest_path)
            suggested_tools = _suggest_tools(mime_type)

            inventory[file_name] = {
                "file_path": str(dest_path),
                "file_type": file_type,
                "file_size": file_size,
                "sha256_hash": sha256,
                "mime_type": mime_type,
                "suggested_tools": suggested_tools,
            }

            print(f"[INGESTED] {file_name} ({file_type}, {file_size} bytes)", flush=True)
            sys.stdout.flush()

        if _SHUTDOWN.is_set():
            break

    return inventory
