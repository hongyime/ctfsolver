"""'/goal' autonomous-solve prompt template + flag verification (Phase 3).

Borrowed from clank-the-flag's /goal pattern (UPGRADE_PLAN §2). Produces a
structured triage -> category-route -> solve -> verify prompt the agent pipeline
injects as context, and a small flag-verification helper used to confirm a
candidate flag before a challenge is marked solved.
"""

from __future__ import annotations

import re
from typing import Optional

# Per-category solve hints (expanded by Phase 5 playbooks).
CATEGORY_ROUTES = {
    "pwn": "checksec -> identify mitigations; rizin/ghidra decompile; ROPgadget/one_gadget; "
           "build exploit with run_pwntools; gdb_start for live debugging; pwninit if libc given.",
    "reverse": "file/strings/floss; ghidra or rizin decompile; capa for capabilities; "
               "wasm2wat for WebAssembly; angr for symbolic execution of checks.",
    "re": "file/strings/floss; ghidra or rizin decompile; capa; angr for input-solving.",
    "crypto": "identify scheme; run_rsactftool for RSA; run_lll (fpylll) / flatter for lattice; "
              "run_sage for algebra/number-theory; run_z3 for constraints.",
    "forensics": "exiftool/binwalk/foremost; zsteg/stegseek/steghide for stego; "
                 "run_sox_spectrogram for audio; extract_usb_hid_pcap for USB captures; "
                 "run_volatility for memory images; tshark for pcaps.",
    "web": "run_feroxbuster/run_ffuf to map; run_sqlmap for SQLi; run_nuclei for known CVEs; "
           "run_jwt_tool for JWT; check sources/headers.",
    "osint": "run_spiderfoot / run_harvester; pivot on emails/subdomains.",
    "recon": "run_nmap for services; enumerate; then category-specific tools.",
    "misc": "triage with file/strings; categorise; apply the matching playbook.",
}


def build_goal_prompt(challenge_name: str, category: str, description: str,
                      target: Optional[str] = None,
                      files: Optional[list[str]] = None) -> str:
    """Render a /goal-style structured autonomous-solve prompt."""
    cat = (category or "misc").lower()
    route = CATEGORY_ROUTES.get(cat, CATEGORY_ROUTES["misc"])
    files_line = ", ".join(files) if files else "(none ingested)"
    return (
        f"# GOAL: capture the flag for '{challenge_name}'\n\n"
        f"## Triage\n"
        f"- Category: {cat}\n"
        f"- Target: {target or '(local artifact)'}\n"
        f"- Files: {files_line}\n"
        f"- Description: {description or '(none)'}\n\n"
        f"## Route ({cat})\n{route}\n\n"
        f"## Solve loop\n"
        f"1. Run the routed tools (record findings against the challenge).\n"
        f"2. Extract a candidate flag from any tool output.\n"
        f"3. VERIFY the flag matches the expected format before declaring success.\n"
        f"4. record_challenge_finding(..., kind='flag', value=<flag>) on success.\n\n"
        f"## Verify\n"
        f"A flag is only accepted if verify_flag() returns true for it.\n"
    )


# Common CTF flag shapes. verify_flag accepts an optional explicit format regex.
_DEFAULT_FLAG_RES = [
    re.compile(r"^[A-Za-z0-9_]{2,32}\{[\x20-\x7e]{1,200}\}$"),  # name{...}
    re.compile(r"^flag\{[\x20-\x7e]{1,200}\}$", re.IGNORECASE),
    re.compile(r"^[A-Za-z0-9]{32}$"),  # bare md5-style token
]


def verify_flag(candidate: str, fmt: Optional[str] = None) -> bool:
    """Return True if `candidate` looks like a valid flag.

    If `fmt` (a regex) is supplied (e.g. the CTF's known prefix), it takes priority;
    otherwise the candidate must match one of the common flag shapes.
    """
    if not candidate or not candidate.strip():
        return False
    c = candidate.strip()
    if fmt:
        try:
            return re.fullmatch(fmt, c) is not None
        except re.error:
            pass
    return any(rx.match(c) for rx in _DEFAULT_FLAG_RES)
