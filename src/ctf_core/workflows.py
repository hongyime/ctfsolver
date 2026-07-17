"""Deterministic workflow recommendation helpers.

The helpers in this module are intentionally server-free. They inspect text,
file names, playbooks, and the declarative registry, but they do not import the
MCP server, start Docker, or execute challenge artifacts.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from pathlib import PurePath
import re
from typing import Any

from .playbooks import PLAYBOOKS
from .registry import TOOL_REGISTRY, ToolEntry


Recommendation = dict[str, Any]


_CATEGORY_ALIASES = {
    "binary": "re",
    "crypto": "crypto",
    "cryptography": "crypto",
    "forensic": "forensics",
    "forensics": "forensics",
    "misc": "misc",
    "osint": "osint",
    "pwn": "pwn",
    "re": "re",
    "rev": "re",
    "reverse": "re",
    "reverse engineering": "re",
    "stego": "forensics",
    "web": "web",
}

_DIRECT_TOOL_NAMES = {
    "analyze_challenge",
    "decode_stego",
    "extract_usb_hid_pcap",
    "gdb_start",
    "get_playbook",
    "run_angr",
    "run_binary_analysis",
    "run_capa",
    "run_challenge_analysis",
    "run_feroxbuster",
    "run_ffuf",
    "run_floss",
    "run_gdb_script",
    "run_ghidra",
    "run_harvester",
    "run_jwt_tool",
    "run_libc_lookup",
    "run_lll",
    "run_nmap",
    "run_nuclei",
    "run_one_gadget",
    "run_patchelf",
    "run_pwntools",
    "run_rizin",
    "run_ropgadget",
    "run_rsactftool",
    "run_sage",
    "run_searchsploit",
    "run_seccomp_tools",
    "run_sox_spectrogram",
    "run_spiderfoot",
    "run_sqlmap",
    "run_stegseek",
    "run_volatility",
    "run_wasm2wat",
    "run_z3",
    "run_zsteg",
    "start_scan",
}

_REGISTRY_TOOL_ALIASES = {
    "ROPgadget": "run_ropgadget",
    "RsaCtfTool": "run_rsactftool",
    "capa": "run_capa",
    "file": "run_binary_analysis",
    "flatter": "run_lll",
    "floss": "run_floss",
    "gdb": "run_gdb_script",
    "ghidra": "run_ghidra",
    "jwt_tool": "run_jwt_tool",
    "nm": "run_binary_analysis",
    "objdump": "run_binary_analysis",
    "one_gadget": "run_one_gadget",
    "patchelf": "run_patchelf",
    "python3": "run_pwntools",
    "r2": "run_rizin",
    "radare2": "run_rizin",
    "readelf": "run_binary_analysis",
    "rizin": "run_rizin",
    "ropgadget": "run_ropgadget",
    "sage": "run_sage",
    "seccomp-tools": "run_seccomp_tools",
    "sox": "run_sox_spectrogram",
    "strings": "run_binary_analysis",
    "theHarvester": "run_harvester",
    "usb_hid_extract": "extract_usb_hid_pcap",
    "volatility": "run_volatility",
    "wasm2wat": "run_wasm2wat",
    "zsteg": "run_zsteg",
}

_CATEGORY_DEFAULTS = {
    "web": (
        "run_feroxbuster",
        "run_ffuf",
        "run_sqlmap",
        "run_nuclei",
        "run_jwt_tool",
        "run_nmap",
    ),
    "re": (
        "run_binary_analysis",
        "run_capa",
        "run_floss",
        "run_ghidra",
        "run_rizin",
        "run_wasm2wat",
    ),
    "crypto": (
        "run_rsactftool",
        "run_sage",
        "run_z3",
        "run_lll",
        "start_scan",
    ),
    "forensics": (
        "run_binary_analysis",
        "run_zsteg",
        "run_stegseek",
        "decode_stego",
        "extract_usb_hid_pcap",
        "run_sox_spectrogram",
        "run_volatility",
    ),
    "pwn": (
        "run_binary_analysis",
        "run_ropgadget",
        "run_one_gadget",
        "run_pwntools",
        "gdb_start",
        "run_seccomp_tools",
    ),
    "osint": (
        "run_harvester",
        "run_spiderfoot",
        "run_nmap",
    ),
}

_SUFFIX_HINTS = {
    ".7z": ("forensics", ("run_binary_analysis", "start_scan")),
    ".bmp": ("forensics", ("run_zsteg", "run_binary_analysis")),
    ".cap": ("forensics", ("extract_usb_hid_pcap", "start_scan")),
    ".dll": ("re", ("run_binary_analysis", "run_capa", "run_floss", "run_ghidra")),
    ".elf": ("re", ("run_binary_analysis", "run_capa", "run_floss", "run_rizin")),
    ".exe": ("re", ("run_binary_analysis", "run_capa", "run_floss", "run_ghidra")),
    ".gif": ("forensics", ("run_binary_analysis", "decode_stego")),
    ".gz": ("forensics", ("run_binary_analysis", "start_scan")),
    ".jpg": ("forensics", ("run_stegseek", "decode_stego", "run_binary_analysis")),
    ".jpeg": ("forensics", ("run_stegseek", "decode_stego", "run_binary_analysis")),
    ".key": ("crypto", ("run_rsactftool", "run_sage")),
    ".pcap": ("forensics", ("extract_usb_hid_pcap", "start_scan")),
    ".pcapng": ("forensics", ("extract_usb_hid_pcap", "start_scan")),
    ".pem": ("crypto", ("run_rsactftool", "run_sage")),
    ".png": ("forensics", ("run_zsteg", "run_binary_analysis", "decode_stego")),
    ".pub": ("crypto", ("run_rsactftool", "run_sage")),
    ".so": ("re", ("run_binary_analysis", "run_capa", "run_floss", "run_ghidra")),
    ".tar": ("forensics", ("run_binary_analysis", "start_scan")),
    ".wasm": ("re", ("run_wasm2wat", "run_z3", "run_binary_analysis")),
    ".wav": ("forensics", ("run_sox_spectrogram", "run_binary_analysis")),
    ".zip": ("forensics", ("run_binary_analysis", "start_scan")),
}

_KEYWORD_HINTS = (
    (("sql", "sqli", "union select", "database", "blind injection"), "web", ("run_sqlmap",), 16),
    (("jwt", "cookie", "session", "token"), "web", ("run_jwt_tool",), 13),
    (("directory", "endpoint", "path traversal", "admin panel", "hidden route"), "web", ("run_ffuf", "run_feroxbuster"), 11),
    (("cve", "template", "misconfig", "vulnerability scan"), "web", ("run_nuclei",), 9),
    (("http://", "https://", "web", "login", "url"), "web", ("run_feroxbuster", "run_ffuf", "run_nmap"), 8),
    (("rsa", "public key", "modulus", "ciphertext", "wiener", "fermat"), "crypto", ("run_rsactftool", "run_sage"), 16),
    (("lattice", "lll", "coppersmith", "hidden number", "lcg", "knapsack"), "crypto", ("run_lll", "run_sage", "run_z3"), 14),
    (("xor", "constraint", "sat solver", "z3"), "crypto", ("run_z3", "run_sage"), 8),
    (("hash", "password", "crack"), "crypto", ("start_scan",), 7),
    (("wasm", "webassembly", "wat"), "re", ("run_wasm2wat", "run_z3", "run_angr"), 16),
    (("elf", "pe32", "binary", "reverse", "stripped", "malware"), "re", ("run_binary_analysis", "run_capa", "run_floss", "run_ghidra"), 12),
    (("rop", "ret2libc", "overflow", "canary", "libc", "gadget"), "pwn", ("run_ropgadget", "run_one_gadget", "run_pwntools", "gdb_start"), 14),
    (("stego", "lsb", "hidden", "png", "jpg", "jpeg", "bmp"), "forensics", ("run_zsteg", "run_stegseek", "decode_stego"), 13),
    (("pcap", "pcapng", "usb", "hid", "keystroke", "packet"), "forensics", ("extract_usb_hid_pcap", "start_scan"), 13),
    (("audio", "wav", "spectrogram", "sstv"), "forensics", ("run_sox_spectrogram", "run_binary_analysis"), 12),
    (("memory", "volatility", "dump", "imageinfo"), "forensics", ("run_volatility",), 12),
)


def suggest_next_tools(
    description: str = "",
    category: str = "",
    target: str = "",
    files: Iterable[Any] | None = None,
    findings: Iterable[Any] | Mapping[str, Any] | str | None = None,
    limit: int = 10,
) -> list[Recommendation]:
    """Return ranked next-tool recommendations for a CTF workflow.

    Inputs are treated as signals only. The function is deterministic and does
    not touch the filesystem or execute tools.
    """

    file_names = [str(item) for item in _flatten(files)]
    finding_text = [str(item) for item in _flatten(findings)]
    raw_category = str(category or "")
    normalized_category = _normalize_category(raw_category)
    context_parts = [description, raw_category, target, *file_names, *finding_text]
    context = " ".join(part for part in context_parts if part).lower()

    recommendations: dict[str, Recommendation] = {}

    if normalized_category:
        for tool in _CATEGORY_DEFAULTS.get(normalized_category, ()):
            _add_recommendation(
                recommendations,
                tool,
                10,
                f"category:{normalized_category}",
                normalized_category,
                "category",
            )

    if _looks_like_network_target(target):
        for tool in ("run_nmap", "run_feroxbuster", "run_ffuf"):
            _add_recommendation(
                recommendations,
                tool,
                8,
                "target looks like a URL or host",
                "web",
                "target",
            )

    for file_name in file_names:
        suffix = PurePath(file_name).suffix.lower()
        if suffix in _SUFFIX_HINTS:
            hint_category, tools = _SUFFIX_HINTS[suffix]
            for index, tool in enumerate(tools):
                _add_recommendation(
                    recommendations,
                    tool,
                    9 + max(0, 2 - index),
                    f"file suffix {suffix}",
                    hint_category,
                    "file",
                )

    for keywords, hint_category, tools, score in _KEYWORD_HINTS:
        matched = [keyword for keyword in keywords if _keyword_matches(keyword, context)]
        if matched:
            reason = "matched " + ", ".join(matched[:3])
            for tool in tools:
                _add_recommendation(
                    recommendations,
                    tool,
                    score + len(matched),
                    reason,
                    hint_category,
                    "keyword",
                )

    for playbook in PLAYBOOKS:
        playbook_score = sum(
            1 for trigger in playbook.triggers if _keyword_matches(trigger.lower(), context)
        )
        category_bonus = normalized_category == playbook.category
        if playbook_score <= 0:
            continue
        score = (playbook_score * 5) + (8 if category_bonus else 0)
        for tool in playbook.tools:
            _add_recommendation(
                recommendations,
                tool,
                score,
                f"playbook:{playbook.name}",
                playbook.category,
                "playbook",
            )

    if not recommendations:
        _add_recommendation(
            recommendations,
            "run_challenge_analysis",
            1,
            "fallback challenge analysis",
            normalized_category or "",
            "fallback",
        )

    ranked = sorted(
        (_finalize_recommendation(item) for item in recommendations.values()),
        key=lambda item: (-int(item["score"]), str(item["tool"])),
    )
    return ranked[: max(0, limit)]


def _add_recommendation(
    recommendations: dict[str, Recommendation],
    tool_name: str,
    score: int,
    reason: str,
    category: str,
    source: str,
) -> None:
    tool = _canonical_tool_name(tool_name)
    item = recommendations.setdefault(
        tool,
        {
            "tool": tool,
            "score": 0,
            "category": category,
            "reasons": [],
            "sources": [],
        },
    )
    item["score"] = int(item["score"]) + score
    if category and not item.get("category"):
        item["category"] = category
    _append_unique(item["reasons"], reason)
    _append_unique(item["sources"], source)


def _finalize_recommendation(item: Recommendation) -> Recommendation:
    tool = str(item["tool"])
    finalized = dict(item)
    finalized["reasons"] = sorted(str(reason) for reason in finalized["reasons"])
    finalized["sources"] = sorted(str(source) for source in finalized["sources"])

    registry_entry = _REGISTRY_BY_PUBLIC_TOOL.get(tool)
    if registry_entry is not None:
        finalized["registry_tool"] = registry_entry.name
        finalized["binary"] = registry_entry.binary
        finalized["image"] = registry_entry.image
        finalized["offline"] = registry_entry.offline
        finalized["security_level"] = registry_entry.security_level.name.lower()
    elif tool == "start_scan":
        finalized["registry_tool"] = "registry-backed scan"
    return finalized


def _canonical_tool_name(tool_name: str) -> str:
    if tool_name in _DIRECT_TOOL_NAMES:
        return tool_name
    if tool_name in _REGISTRY_TOOL_ALIASES:
        return _REGISTRY_TOOL_ALIASES[tool_name]

    lowered = tool_name.lower()
    for alias, public_name in _REGISTRY_TOOL_ALIASES.items():
        if lowered == alias.lower():
            return public_name

    if lowered in _REGISTRY_NAMES:
        return tool_name
    return tool_name


def _normalize_category(category: str) -> str:
    normalized = " ".join(category.strip().lower().replace("_", " ").split())
    return _CATEGORY_ALIASES.get(normalized, normalized)


def _looks_like_network_target(target: str) -> bool:
    text = target.strip().lower()
    if not text:
        return False
    return (
        text.startswith(("http://", "https://"))
        or "." in text
        or ":" in text
    )


def _keyword_matches(keyword: str, context: str) -> bool:
    if any(not char.isalnum() and char != "_" for char in keyword):
        return keyword in context
    pattern = rf"(?<![a-z0-9_]){re.escape(keyword)}(?![a-z0-9_])"
    return re.search(pattern, context) is not None


def _flatten(value: Any) -> list[Any]:
    if value is None:
        return []
    if isinstance(value, (str, bytes, PurePath)):
        return [value]
    if isinstance(value, Mapping):
        flattened: list[Any] = []
        for key, nested in value.items():
            flattened.append(key)
            flattened.extend(_flatten(nested))
        return flattened
    if isinstance(value, Iterable):
        flattened = []
        for nested in value:
            flattened.extend(_flatten(nested))
        return flattened
    return [value]


def _append_unique(items: list[Any], value: Any) -> None:
    if value not in items:
        items.append(value)


def _build_registry_index() -> dict[str, ToolEntry]:
    index: dict[str, ToolEntry] = {}
    for entry in TOOL_REGISTRY:
        public_name = _canonical_tool_name(entry.name)
        for key in {entry.name, entry.binary, public_name}:
            index.setdefault(key, entry)
    return index


_REGISTRY_NAMES = {entry.name.lower() for entry in TOOL_REGISTRY} | {
    entry.binary.lower() for entry in TOOL_REGISTRY
}
_REGISTRY_BY_PUBLIC_TOOL = _build_registry_index()


__all__ = ["suggest_next_tools"]
