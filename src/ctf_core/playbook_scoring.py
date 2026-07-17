"""Scored, side-effect-free playbook and workflow-chain selection."""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from pathlib import PurePath
import re
from typing import Any

from .playbooks import PLAYBOOKS, Playbook
from .workflow_chains import select_workflow_chains


_CATEGORY_ALIASES = {
    "api testing": "api",
    "crawl": "crawler",
    "crawler": "crawler",
    "forensic": "forensics",
    "forensics": "forensics",
    "network forensics": "pcap",
    "packet": "pcap",
    "params": "params",
    "parameter": "params",
    "parameters": "params",
    "reverse": "re",
    "reverse engineering": "re",
    "reversing": "re",
    "secret": "secret",
    "secret leak": "secret",
    "secrets": "secret",
    "steganography": "stego",
}


_PLAYBOOK_PREREQUISITES: dict[str, tuple[str, ...]] = {
    "web_sqli": (
        "Authorized web target scope is configured.",
        "A base URL or captured request is available.",
        "Authentication context is recorded when required.",
    ),
    "re_wasm": (
        "WASM artifact is available in the workspace.",
        "Static analysis can run on a copied artifact.",
    ),
    "pwn_rop": (
        "Binary and matching libc/loader, when provided, are preserved.",
        "Remote host and port are confirmed in scope before exploit testing.",
    ),
    "crypto_rsa": (
        "RSA parameters, public key, and ciphertext are collected.",
        "Numeric inputs are normalized as integers or PEM files.",
    ),
    "crypto_lattice": (
        "Modular relations and bounds on unknowns are identified.",
        "Sage/fpylll-ready equations are written from challenge data.",
    ),
    "forensics_usb_hid": (
        "Capture file is available and hashed before extraction.",
        "USB HID traffic is present or strongly suspected.",
    ),
    "forensics_stego": (
        "Original artifact is available and hashed before extraction.",
        "Derived files will be written separately from the original.",
    ),
}


_PLAYBOOK_EXPECTED_ARTIFACTS: dict[str, tuple[str, ...]] = {
    "web_sqli": (
        "endpoint_map",
        "injectable_parameter_notes",
        "database_or_admin_proof",
        "verified_flag",
    ),
    "re_wasm": (
        "wat_disassembly",
        "validation_logic_notes",
        "solver_constraints",
        "candidate_flag",
    ),
    "pwn_rop": (
        "checksec_summary",
        "overflow_offset",
        "leak_strategy",
        "exploit_script",
    ),
    "crypto_rsa": (
        "normalized_rsa_parameters",
        "attack_attempt_notes",
        "private_key_or_plaintext",
        "verified_flag",
    ),
    "crypto_lattice": (
        "lattice_basis",
        "reduced_vectors",
        "recovered_secret",
        "verified_flag",
    ),
    "forensics_usb_hid": (
        "capture_metadata",
        "hid_report_summary",
        "decoded_keystrokes_or_plot",
        "candidate_flag",
    ),
    "forensics_stego": (
        "metadata_report",
        "strings_report",
        "carved_files",
        "decoded_payloads",
    ),
}


_CATEGORY_PREREQUISITES: dict[str, tuple[str, ...]] = {
    "web": ("Authorized target scope is configured.", "A URL, request, or source artifact is available."),
    "re": ("Challenge artifact is available in the workspace.", "Analysis is read-only against a copy."),
    "pwn": ("Binary artifact or remote endpoint is known.", "Exploit testing stays within challenge scope."),
    "crypto": ("Ciphertext, public parameters, and hints are collected.",),
    "forensics": ("Original artifact is available and preserved.",),
}


_CATEGORY_EXPECTED_ARTIFACTS: dict[str, tuple[str, ...]] = {
    "web": ("endpoint_notes", "reproduction_steps", "verified_flag"),
    "re": ("static_analysis_notes", "solver_script", "candidate_flag"),
    "pwn": ("mitigation_summary", "exploit_notes", "exploit_script"),
    "crypto": ("normalized_parameters", "attack_notes", "recovered_plaintext"),
    "forensics": ("artifact_metadata", "extraction_notes", "candidate_flag"),
}


_FAILURE_BRANCHES: tuple[dict[str, Any], ...] = (
    {
        "id": "no_web_endpoints_found",
        "failure": "No web endpoints found.",
        "signals": ("no web endpoints found", "no endpoints found", "no routes found", "crawler found nothing"),
        "applies_to_categories": ("web", "api", "crawler", "params", "secret"),
        "applies_to_ids": (
            "web_recon",
            "crawler_endpoint_discovery",
            "parameter_discovery",
            "secret_leak",
            "api_testing",
            "web_sqli",
        ),
        "next_actions": (
            "Verify the base URL, redirects, virtual host, and saved scope before broadening discovery.",
            "Seed discovery from robots.txt, sitemap.xml, JavaScript files, HAR captures, and source routes.",
            "Run a shallow crawl before fuzzing and relax status/length filters that may be hiding soft-404s.",
            "Pivot to source review or downloaded artifacts if the live service exposes no routes.",
        ),
    },
    {
        "id": "scanner_out_of_scope",
        "failure": "Scanner target is out of scope.",
        "signals": ("scanner out of scope", "target out of scope", "scope denied", "not in scope"),
        "applies_to_categories": ("web", "api", "crawler", "params", "secret", "osint", "cloud"),
        "applies_to_ids": (
            "web_recon",
            "nuclei_lite",
            "crawler_endpoint_discovery",
            "xss_discovery",
            "parameter_discovery",
            "secret_leak",
            "api_testing",
            "web_sqli",
        ),
        "next_actions": (
            "Stop network-capable scans until the target list is normalized against the saved scope.",
            "Check redirects, alternate ports, and derived hosts with the scope checker before retrying.",
            "Retarget only allowed origins and continue offline review of downloaded files while scope is fixed.",
        ),
    },
    {
        "id": "no_strings_found",
        "failure": "No useful printable strings found.",
        "signals": ("no strings found", "strings found nothing", "no printable strings", "strings empty"),
        "applies_to_categories": ("re", "forensics", "stego", "pwn", "malware"),
        "applies_to_ids": ("re_wasm", "forensics_stego", "stego_triage", "pwn_rop"),
        "next_actions": (
            "Repeat string extraction with wider encodings, shorter minimum length, and FLOSS for binaries.",
            "Inspect file type, entropy, headers, and hexdump offsets for compression or packing.",
            "Run metadata and carving passes before assuming the artifact has no embedded clues.",
        ),
    },
    {
        "id": "crypto_factorization_fails",
        "failure": "Crypto factorization path fails.",
        "signals": (
            "factorization fails",
            "factorization failed",
            "cannot factor",
            "factoring failed",
            "factordb failed",
        ),
        "applies_to_categories": ("crypto",),
        "applies_to_ids": ("crypto_rsa", "crypto_lattice"),
        "next_actions": (
            "Check for RSA non-factor attacks: low exponent, common modulus, Wiener, Boneh-Durfee, or partial key leaks.",
            "Validate n, e, c parsing and convert PEM/hex/decimal inputs before retrying automated tooling.",
            "If a message prefix or partial secret is known, pivot to Coppersmith/lattice modeling instead of factoring.",
        ),
    },
    {
        "id": "pcap_no_http",
        "failure": "PCAP has no HTTP traffic.",
        "signals": ("pcap has no http", "no http in pcap", "no http traffic", "http absent"),
        "applies_to_categories": ("pcap", "forensics"),
        "applies_to_ids": ("pcap_triage", "forensics_usb_hid"),
        "next_actions": (
            "Build protocol hierarchy and conversation summaries before choosing extractors.",
            "Inspect DNS, TLS SNI, FTP, SMB, SMTP, ICMP, and USB HID instead of HTTP object extraction.",
            "Create a timeline from notable non-HTTP packets and look for tunneling or encoded data.",
        ),
    },
    {
        "id": "stego_passphrase_missing",
        "failure": "Stego passphrase is missing.",
        "signals": (
            "stego passphrase missing",
            "missing passphrase",
            "unknown stego password",
            "steghide password unknown",
        ),
        "applies_to_categories": ("stego", "forensics"),
        "applies_to_ids": ("stego_triage", "forensics_stego"),
        "next_actions": (
            "Derive a challenge wordlist from title, description, filenames, metadata, strings, and comments.",
            "Try challenge-specific words with stegseek before broad cracking.",
            "Pivot to metadata, LSB, carving, and spectrogram checks if steghide-compatible extraction remains blocked.",
        ),
    },
)


def common_failure_branches() -> list[dict[str, Any]]:
    """Return all supported failure branches as JSON-serializable dictionaries."""

    return [
        {
            "id": branch["id"],
            "failure": branch["failure"],
            "signals": list(branch["signals"]),
            "next_actions": list(branch["next_actions"]),
        }
        for branch in _FAILURE_BRANCHES
    ]


def select_scored_playbooks(
    description: str = "",
    category: str = "",
    target: str = "",
    files: Iterable[Any] | None = None,
    findings: Iterable[Any] | Mapping[str, Any] | str | None = None,
    failures: Iterable[Any] | Mapping[str, Any] | str | None = None,
    *,
    limit: int = 10,
    min_score: int = 1,
) -> list[dict[str, Any]]:
    """Rank built-in playbooks and workflow chains from challenge signals.

    The selector is metadata-only: it returns suggested workflows and branching
    next actions, but it never executes tools or opens network connections.
    """

    file_names = [str(item) for item in _flatten(files)]
    finding_text = [str(item) for item in _flatten(findings)]
    failure_text = [str(item) for item in _flatten(failures)]
    normalized_category = _normalize_category(category)
    context = _context_text(description, category, target, file_names, finding_text, failure_text)
    target_kind = _target_kind(target)
    active_branch_ids = _active_failure_branch_ids(context)

    items: list[dict[str, Any]] = []
    workflow_findings = [*finding_text, *failure_text]
    for chain in select_workflow_chains(
        description=description,
        category=category,
        target=target,
        files=file_names,
        findings=workflow_findings,
        limit=100,
        min_score=min_score,
    ):
        item = _workflow_item(chain, context, target_kind, file_names, active_branch_ids)
        if item["score"] >= min_score:
            items.append(item)

    for playbook in PLAYBOOKS:
        item = _playbook_item(playbook, normalized_category, context, target_kind, file_names, active_branch_ids)
        if item["score"] >= min_score:
            items.append(item)

    items.sort(key=lambda item: (-int(item["score"]), str(item["kind"]), str(item["id"])))
    return items[: max(0, limit)]


def select_best_playbook(
    description: str = "",
    category: str = "",
    target: str = "",
    files: Iterable[Any] | None = None,
    findings: Iterable[Any] | Mapping[str, Any] | str | None = None,
    failures: Iterable[Any] | Mapping[str, Any] | str | None = None,
) -> dict[str, Any] | None:
    """Return the highest-scoring playbook/workflow candidate, if any."""

    matches = select_scored_playbooks(
        description=description,
        category=category,
        target=target,
        files=files,
        findings=findings,
        failures=failures,
        limit=1,
    )
    return matches[0] if matches else None


def _workflow_item(
    chain: Mapping[str, Any],
    context: str,
    target_kind: str,
    file_names: list[str],
    active_branch_ids: set[str],
) -> dict[str, Any]:
    chain_id = str(chain["chain_id"])
    category = _normalize_category(str(chain.get("category") or ""))
    branches = _branches_for_item(chain_id, category, target_kind, file_names, active_branch_ids)
    active = [branch for branch in branches if branch["active"]]
    reasons = list(chain.get("reasons") or [])
    score = int(chain.get("score") or 0)
    if active:
        score += 12
        reasons.extend(f"failure:{branch['id']}" for branch in active)

    steps = [dict(step) for step in chain.get("steps") or []]
    expected_artifacts = _dedupe(
        str(artifact)
        for step in steps
        for artifact in (step.get("expected_artifacts") or [])
        if artifact
    )
    base_actions = [
        f"{step.get('step_id')}: {step.get('purpose')}"
        for step in steps[:4]
        if step.get("step_id") and step.get("purpose")
    ]

    return {
        "id": chain_id,
        "kind": "workflow_chain",
        "name": chain.get("name"),
        "category": category,
        "score": score,
        "reasons": sorted(_dedupe(reasons)),
        "prerequisites": list(chain.get("prerequisites") or []),
        "expected_artifacts": expected_artifacts,
        "failure_branches": branches,
        "next_actions": _next_actions(branches, base_actions),
        "source": "ctf_core.workflow_chains",
        "tools": _dedupe(str(step.get("tool")) for step in steps if step.get("tool")),
        "steps": steps,
    }


def _playbook_item(
    playbook: Playbook,
    normalized_category: str,
    context: str,
    target_kind: str,
    file_names: list[str],
    active_branch_ids: set[str],
) -> dict[str, Any]:
    category = _normalize_category(playbook.category)
    score = 0
    reasons: list[str] = []

    if normalized_category and normalized_category == category:
        score += 24
        reasons.append(f"category:{category}")

    keyword_matches = [trigger for trigger in playbook.triggers if _keyword_matches(trigger, context)]
    if keyword_matches:
        score += min(42, len(keyword_matches) * 6)
        reasons.append("keyword:" + ",".join(keyword_matches[:3]))

    suffix_matches = _matching_suffixes(file_names, tuple(trigger for trigger in playbook.triggers if trigger.startswith(".")))
    if suffix_matches:
        score += 12 + min(6, len(suffix_matches) * 2)
        reasons.append("file_suffix:" + ",".join(suffix_matches[:3]))

    if _target_matches_category(target_kind, category):
        score += 6
        reasons.append(f"target:{target_kind}")

    branches = _branches_for_item(playbook.name, category, target_kind, file_names, active_branch_ids)
    active = [branch for branch in branches if branch["active"]]
    if active:
        score += 12
        reasons.extend(f"failure:{branch['id']}" for branch in active)

    base_actions = _workflow_next_actions(playbook.workflow)
    return {
        "id": playbook.name,
        "kind": "playbook",
        "name": playbook.name,
        "category": category,
        "score": score,
        "reasons": sorted(_dedupe(reasons)),
        "prerequisites": list(_PLAYBOOK_PREREQUISITES.get(playbook.name) or _CATEGORY_PREREQUISITES.get(category, ())),
        "expected_artifacts": list(
            _PLAYBOOK_EXPECTED_ARTIFACTS.get(playbook.name) or _CATEGORY_EXPECTED_ARTIFACTS.get(category, ())
        ),
        "failure_branches": branches,
        "next_actions": _next_actions(branches, base_actions),
        "source": "ctf_core.playbooks",
        "tools": list(playbook.tools),
        "triggers": list(playbook.triggers),
        "workflow": playbook.workflow,
    }


def _branches_for_item(
    item_id: str,
    category: str,
    target_kind: str,
    file_names: list[str],
    active_branch_ids: set[str],
) -> list[dict[str, Any]]:
    branches: list[dict[str, Any]] = []
    suffixes = {PurePath(name.lower()).suffix for name in file_names}
    for branch in _FAILURE_BRANCHES:
        applies = item_id in branch["applies_to_ids"] or category in branch["applies_to_categories"]
        if branch["id"] == "scanner_out_of_scope" and target_kind in {"url", "host"}:
            applies = True
        if branch["id"] == "no_web_endpoints_found" and (target_kind == "url" or suffixes & {".html", ".js", ".har"}):
            applies = True
        if branch["id"] == "pcap_no_http" and suffixes & {".pcap", ".pcapng", ".cap"}:
            applies = True
        if branch["id"] == "stego_passphrase_missing" and suffixes & {
            ".png",
            ".jpg",
            ".jpeg",
            ".bmp",
            ".gif",
            ".wav",
            ".flac",
            ".mp3",
        }:
            applies = True
        if not applies:
            continue
        branches.append(
            {
                "id": branch["id"],
                "failure": branch["failure"],
                "detect_when": list(branch["signals"]),
                "next_actions": list(branch["next_actions"]),
                "active": branch["id"] in active_branch_ids,
            }
        )
    return branches


def _next_actions(branches: list[Mapping[str, Any]], base_actions: list[str]) -> list[str]:
    branch_actions = [
        str(action)
        for branch in branches
        if branch.get("active")
        for action in (branch.get("next_actions") or [])
    ]
    return _dedupe([*branch_actions, *base_actions])[:8]


def _workflow_next_actions(workflow: str) -> list[str]:
    actions: list[str] = []
    for line in workflow.splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        match = re.match(r"^\d+\.\s+(.*)$", stripped)
        if match:
            actions.append(match.group(1).strip())
    return actions[:5]


def _active_failure_branch_ids(context: str) -> set[str]:
    active: set[str] = set()
    for branch in _FAILURE_BRANCHES:
        if any(_keyword_matches(signal, context) for signal in branch["signals"]):
            active.add(str(branch["id"]))
    return active


def _context_text(
    description: str,
    category: str,
    target: str,
    files: list[str],
    findings: list[str],
    failures: list[str],
) -> str:
    return " ".join(str(part) for part in [description, category, target, *files, *findings, *failures] if part).lower()


def _normalize_category(category: str) -> str:
    normalized = " ".join(str(category or "").strip().lower().replace("_", " ").split())
    return _CATEGORY_ALIASES.get(normalized, normalized)


def _target_kind(target: str) -> str:
    text = str(target or "").strip().lower()
    if not text:
        return ""
    if text.startswith(("http://", "https://")):
        return "url"
    if "." in text or ":" in text:
        return "host"
    return "file"


def _target_matches_category(target_kind: str, category: str) -> bool:
    if not target_kind:
        return False
    if category == "web" and target_kind in {"url", "host"}:
        return True
    if category in {"re", "forensics", "crypto"} and target_kind == "file":
        return True
    if category == "pwn" and target_kind in {"file", "host"}:
        return True
    return False


def _matching_suffixes(file_names: Iterable[str], suffixes: tuple[str, ...]) -> list[str]:
    suffix_set = {suffix.lower() for suffix in suffixes}
    matches: list[str] = []
    for file_name in file_names:
        suffix = PurePath(str(file_name).lower()).suffix
        if suffix in suffix_set and suffix not in matches:
            matches.append(suffix)
    return matches


def _keyword_matches(keyword: str, context: str) -> bool:
    keyword = str(keyword or "").lower()
    if not keyword:
        return False
    if any(not char.isalnum() and char != "_" for char in keyword):
        return keyword in context
    pattern = rf"(?<![a-z0-9_]){re.escape(keyword)}(?![a-z0-9_])"
    return re.search(pattern, context) is not None


def _flatten(value: Any) -> list[Any]:
    if value is None:
        return []
    if isinstance(value, (str, bytes, PurePath)):
        return [value.decode() if isinstance(value, bytes) else value]
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


def _dedupe(items: Iterable[Any]) -> list[Any]:
    seen: set[str] = set()
    unique: list[Any] = []
    for item in items:
        if item in (None, ""):
            continue
        key = str(item)
        if key in seen:
            continue
        seen.add(key)
        unique.append(item)
    return unique


__all__ = [
    "common_failure_branches",
    "select_best_playbook",
    "select_scored_playbooks",
]
