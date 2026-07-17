"""Deterministic solver template catalog for CTF challenge categories.

The templates in this module are metadata only. They describe safe analysis
plans, expected outputs, and educational code skeletons, but they do not run
tools, generate payloads, open files, or touch the network.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from pathlib import PurePath
import re
from typing import Any


_TEMPLATE_ID_PATTERN = re.compile(r"^[a-z0-9][a-z0-9_]*$")


@dataclass(frozen=True)
class SolverTemplate:
    """One reusable, declarative solver template."""

    template_id: str
    category: str
    title: str
    applicable_signals: tuple[str, ...]
    required_tools: tuple[str, ...]
    optional_tools: tuple[str, ...]
    workflow_steps: tuple[str, ...]
    safety_notes: tuple[str, ...]
    expected_artifacts: tuple[str, ...]
    code_skeleton: str = ""
    trigger_keywords: tuple[str, ...] = ()
    file_suffixes: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        return {
            "template_id": self.template_id,
            "category": self.category,
            "title": self.title,
            "applicable_signals": list(self.applicable_signals),
            "required_tools": list(self.required_tools),
            "optional_tools": list(self.optional_tools),
            "workflow_steps": list(self.workflow_steps),
            "safety_notes": list(self.safety_notes),
            "expected_artifacts": list(self.expected_artifacts),
            "code_skeleton": self.code_skeleton,
            "trigger_keywords": list(self.trigger_keywords),
            "file_suffixes": list(self.file_suffixes),
        }


SOLVER_TEMPLATES: tuple[SolverTemplate, ...] = (
    SolverTemplate(
        template_id="mobile_android_static_reverse",
        category="mobile",
        title="Android APK Static Reverse Engineering",
        applicable_signals=(
            "Android APK, classes.dex, resources.arsc, or AndroidManifest.xml",
            "Java or Kotlin validation logic hidden in an application package",
            "Hardcoded secrets, endpoints, crypto keys, or native library bridge code",
        ),
        required_tools=("jadx", "apktool", "file", "strings"),
        optional_tools=("yara", "apksigner", "dex2jar", "adb", "frida-tools"),
        workflow_steps=(
            "Record the APK hash and identify package metadata without installing it.",
            "Use apktool to decode resources, manifests, strings, and asset files.",
            "Use jadx to inspect Java/Kotlin classes and search validation branches.",
            "Check native libraries with file, strings, and reverse-engineering tools.",
            "Run YARA rules for packers, obfuscators, embedded secrets, and malware-like hints.",
            "Summarize candidate flag construction, storage, or network retrieval paths.",
        ),
        safety_notes=(
            "Do not install or execute unknown APKs on the host.",
            "Keep device bridge tools opt-in and challenge-scoped.",
            "Treat decoded files as untrusted and keep extraction inside the workspace.",
        ),
        expected_artifacts=(
            "apktool resource tree",
            "jadx source tree or notes",
            "manifest permissions summary",
            "YARA findings",
            "candidate validation paths",
        ),
        code_skeleton="""\
# Android static triage notes
apk_path = "challenge.apk"
outputs = {
    "manifest": "android/AndroidManifest.xml",
    "jadx_notes": "android/jadx-review.md",
    "resource_hints": "android/resources-review.md",
    "yara_hits": "android/yara-findings.json",
}
# Fill these after static review:
package_name = None
interesting_classes = []
candidate_secrets = []
""",
        trigger_keywords=(
            "apk",
            "android",
            "classes.dex",
            "jadx",
            "apktool",
            "manifest",
            "kotlin",
            "smali",
            "mobile",
        ),
        file_suffixes=(".apk", ".dex", ".so"),
    ),
    SolverTemplate(
        template_id="managed_dotnet_static_reverse",
        category="managed-code",
        title=".NET Managed-Code Static Reverse Engineering",
        applicable_signals=(
            ".NET PE, CIL, C#, VB.NET, or Mono assembly",
            "Challenge references mscoree, CLR metadata, or managed resources",
            "Validation logic likely exists in recoverable IL or decompiled C#",
        ),
        required_tools=("ilspycmd", "file", "strings"),
        optional_tools=("dnSpyEx", "dotnet", "yara", "capa", "floss"),
        workflow_steps=(
            "Identify CLR metadata, target framework, architecture, and entry point.",
            "Decompile with ilspycmd and preserve project structure for review.",
            "Search decompiled source and resources for checks, encoders, and constants.",
            "Inspect IL where decompiled control flow is ambiguous or obfuscated.",
            "Run YARA and string extraction for packers, embedded blobs, and secrets.",
            "Document the exact method path from input to flag check.",
        ),
        safety_notes=(
            "Review assemblies statically before executing any managed code.",
            "Do not load unknown assemblies into privileged IDE sessions.",
            "Keep recovered resources in a derived-output directory.",
        ),
        expected_artifacts=(
            "ILSpy project output",
            "entry point and method map",
            "resource extraction notes",
            "YARA findings",
            "flag-check pseudocode",
        ),
        code_skeleton="""\
# Managed-code review worksheet
assembly_path = "challenge.exe"
entry_points = []
interesting_methods = []
resource_files = []
decoded_constants = {}
# Record namespace.class.method -> observation as review proceeds.
""",
        trigger_keywords=(
            ".net",
            "dotnet",
            "managed",
            "c#",
            "cil",
            "ilspy",
            "mono",
            "dnspy",
        ),
        file_suffixes=(".exe", ".dll"),
    ),
    SolverTemplate(
        template_id="managed_pyinstaller_unpack",
        category="managed-code",
        title="PyInstaller Bundle Unpack and Python Bytecode Review",
        applicable_signals=(
            "Python executable bundle, PyInstaller bootloader, or embedded PYZ archive",
            "Binary contains Python version markers or .pyc-like artifacts",
            "Validation logic likely exists in recoverable Python bytecode",
        ),
        required_tools=("pyinstxtractor", "python3", "file", "strings"),
        optional_tools=("uncompyle6", "pycdc", "yara", "binwalk"),
        workflow_steps=(
            "Record the executable hash and identify PyInstaller or archive markers.",
            "Extract the bundle with pyinstxtractor into a derived output folder.",
            "Match bytecode magic to the Python version before decompilation.",
            "Decompile or disassemble recovered modules and inspect entry-point logic.",
            "Run YARA and strings against bundled data files and native extensions.",
            "Document import graph, decoded constants, and candidate flag generation.",
        ),
        safety_notes=(
            "Do not execute the recovered Python application during initial triage.",
            "Keep extraction read-only relative to the original executable.",
            "Treat bundled native extensions as untrusted binaries.",
        ),
        expected_artifacts=(
            "PyInstaller extraction directory",
            "bytecode version notes",
            "decompiled or disassembled modules",
            "YARA findings",
            "candidate flag-generation notes",
        ),
        code_skeleton="""\
# PyInstaller review worksheet
bundle_path = "challenge.exe"
python_magic = None
entry_module = None
modules_to_review = []
decoded_values = {}
# Prefer static decompilation/disassembly before any execution.
""",
        trigger_keywords=(
            "pyinstaller",
            "pyz",
            "pyc",
            "python executable",
            "pyinstxtractor",
            "frozen app",
        ),
        file_suffixes=(".exe", ".pyc", ".pyz"),
    ),
    SolverTemplate(
        template_id="ghidra_batch_summary",
        category="reverse",
        title="Ghidra Headless Batch Summary",
        applicable_signals=(
            "ELF, PE, Mach-O, firmware blob, or native shared library",
            "Many binaries need consistent strings, functions, imports, and decompile summaries",
            "Challenge benefits from repeatable Ghidra project automation",
        ),
        required_tools=("ghidra", "file", "strings"),
        optional_tools=("capa", "floss", "rizin", "objdump"),
        workflow_steps=(
            "Create a throwaway Ghidra project under the workspace.",
            "Import target binaries read-only and run default analysis.",
            "Export strings, function list, entry points, symbols, and imports.",
            "Decompile selected functions such as main, validate, decrypt, and compare loops.",
            "Build a call graph around suspicious functions and imported APIs.",
            "Write a batch summary with evidence links and next reverse-engineering targets.",
        ),
        safety_notes=(
            "Run Ghidra headless in a disposable project directory.",
            "Do not execute analyzed binaries as part of the automation.",
            "Keep generated scripts deterministic and workspace-relative.",
        ),
        expected_artifacts=(
            "Ghidra project",
            "strings report",
            "function and import summary",
            "selected decompile output",
            "call graph notes",
            "batch summary markdown",
        ),
        code_skeleton="""\
# Ghidra headless script outline (Jython-style pseudocode)
program_name = currentProgram.getName()
reports = {
    "strings": [],
    "functions": [],
    "imports": [],
    "suspicious_functions": [],
}
# Iterate strings/functions/imports, then write JSON or markdown reports.
""",
        trigger_keywords=(
            "ghidra",
            "decompile",
            "call graph",
            "imports",
            "strings",
            "batch",
            "native",
        ),
        file_suffixes=(".elf", ".exe", ".dll", ".so", ".bin", ".fw"),
    ),
    SolverTemplate(
        template_id="ghidra_suspicious_imports_callgraph",
        category="reverse",
        title="Ghidra Suspicious Imports and Call Graph Review",
        applicable_signals=(
            "Binary imports crypto, process, filesystem, anti-debug, or network APIs",
            "Interesting strings have cross references into a small function cluster",
            "Need a focused review plan before manual decompilation",
        ),
        required_tools=("ghidra",),
        optional_tools=("capa", "floss", "strings", "objdump"),
        workflow_steps=(
            "Tag imports related to crypto, comparison, encoding, files, sockets, and process APIs.",
            "Collect callers of suspicious imports and string cross references.",
            "Rank functions by references to suspicious imports and challenge strings.",
            "Decompile the top-ranked functions and note data-flow assumptions.",
            "Sketch caller/callee relationships around validation and decode routines.",
            "Export a prioritized manual-review queue.",
        ),
        safety_notes=(
            "Use import and xref analysis as hints, not proof.",
            "Avoid automatic patching or binary modification in this template.",
            "Keep the call graph bounded to prevent noisy summaries.",
        ),
        expected_artifacts=(
            "suspicious import table",
            "xref-ranked function list",
            "bounded call graph",
            "decompile notes",
            "manual review queue",
        ),
        code_skeleton="""\
# Suspicious import review outline
suspicious_terms = [
    "strcmp", "memcmp", "Crypt", "AES", "sha", "socket", "CreateFile",
]
ranked_functions = []
# Score functions by import callers, string xrefs, and proximity to entry points.
""",
        trigger_keywords=(
            "suspicious imports",
            "suspicious",
            "imports",
            "review",
            "xref",
            "cross reference",
            "call graph",
            "decompiler",
            "ghidra",
        ),
        file_suffixes=(".elf", ".exe", ".dll", ".so"),
    ),
    SolverTemplate(
        template_id="pwn_pwntools_scaffold",
        category="pwn",
        title="Educational pwntools Solver Scaffold",
        applicable_signals=(
            "Local pwn challenge with ELF binary and optional remote host/port",
            "Need structured notes for architecture, mitigations, offsets, and IO",
            "Exploit path is not yet known and should start with safe probes",
        ),
        required_tools=("pwntools", "checksec", "file"),
        optional_tools=("ROPgadget", "rizin", "gdb", "seccomp-tools"),
        workflow_steps=(
            "Record binary hash, architecture, linked libraries, and mitigations.",
            "Map challenge IO manually with benign sample inputs.",
            "Identify the bug class and required primitives before writing an exploit.",
            "Track offsets, addresses, and constraints as placeholders until proven.",
            "Keep local, debugger, and remote modes separated in configuration.",
            "Write a final solve script only after every primitive is documented.",
        ),
        safety_notes=(
            "This template intentionally omits a working exploit body.",
            "Use only challenge-owned binaries and authorized remote endpoints.",
            "Do not include shell-spawning or destructive post-exploitation actions.",
        ),
        expected_artifacts=(
            "checksec report",
            "architecture notes",
            "IO transcript",
            "offset worksheet",
            "primitive proof notes",
            "solver scaffold",
        ),
        code_skeleton="""\
from pwn import ELF, context

binary_path = "./challenge"
context.binary = ELF(binary_path, checksec=False)

analysis = {
    "mode": "local-or-remote-placeholder",
    "offset": None,
    "leak_source": None,
    "control_target": None,
    "constraints": [],
}

def describe_plan():
    return analysis
""",
        trigger_keywords=(
            "pwn",
            "pwntools",
            "overflow",
            "rop",
            "ret2libc",
            "canary",
            "exploit template",
        ),
        file_suffixes=(".elf", ".so"),
    ),
    SolverTemplate(
        template_id="pwn_libc_resolution_flow",
        category="pwn",
        title="libc Resolution and Dynamic Linker Flow",
        applicable_signals=(
            "Pwn binary depends on remote libc, loader, or BuildID matching",
            "Need to reconcile local debug environment with challenge service",
            "Mitigations or leaks suggest a ret2libc-style analysis path",
        ),
        required_tools=("pwninit", "patchelf", "checksec", "ldd"),
        optional_tools=("one_gadget", "libc-database", "readelf", "objdump"),
        workflow_steps=(
            "Record the binary, libc, and loader hashes before patching copies.",
            "Use pwninit or manual notes to pair the binary with the provided libc and ld.",
            "Patch only a derived copy for local reproduction and keep the original intact.",
            "List imported functions, GOT/PLT entries, symbol versions, and BuildID.",
            "Document any leak source needed to identify libc base during solving.",
            "Record candidate constraints before considering one_gadget-style shortcuts.",
        ),
        safety_notes=(
            "Patch derived files only; never overwrite original challenge artifacts.",
            "Do not treat one_gadget output as directly usable without constraint review.",
            "Keep remote interaction code out of this planning template.",
        ),
        expected_artifacts=(
            "binary/libc/ld hashes",
            "patched local copy",
            "symbol and BuildID notes",
            "leak plan",
            "constraint worksheet",
        ),
        code_skeleton="""\
# libc resolution worksheet
artifacts = {
    "binary": "./challenge",
    "libc": "./libc.so.6",
    "loader": "./ld-linux.so.2",
}
symbol_notes = {}
leak_plan = {"source": None, "symbol": None, "base_formula": None}
constraint_notes = []
""",
        trigger_keywords=(
            "libc",
            "ret2libc",
            "pwninit",
            "patchelf",
            "one_gadget",
            "got",
            "plt",
            "buildid",
        ),
        file_suffixes=(".elf", ".so"),
    ),
    SolverTemplate(
        template_id="pwn_multiarch_debugger_flow",
        category="pwn",
        title="Multiarch Pwn Debugger Flow",
        applicable_signals=(
            "Binary architecture differs from the host architecture",
            "Need debugger, emulator, or gdbserver setup notes before exploitation",
            "Challenge includes ARM, MIPS, AArch64, RISC-V, or unusual ABI hints",
        ),
        required_tools=("gdb", "gdbserver", "file", "checksec"),
        optional_tools=("qemu-user", "gef", "pwndbg", "rizin", "seccomp-tools"),
        workflow_steps=(
            "Identify architecture, endianness, ABI, interpreter, and required libraries.",
            "Choose a matching emulator/debugger pair and document launch assumptions.",
            "Create a debugger command file that sets breakpoints and prints state only.",
            "Trace safe sample inputs to understand IO, crashes, and memory mappings.",
            "Capture syscall/seccomp constraints before choosing primitives.",
            "Record reproducible debugger steps separately from any final solver script.",
        ),
        safety_notes=(
            "Debugger helpers should inspect state and avoid modifying target files.",
            "Use challenge-owned binaries and benign sample inputs until constraints are understood.",
            "Keep emulator filesystem mappings minimal and workspace-local.",
        ),
        expected_artifacts=(
            "architecture summary",
            "debugger command file",
            "memory map notes",
            "syscall or seccomp notes",
            "crash transcript",
        ),
        code_skeleton="""\
# debugger command sketch
set pagination off
set disassembly-flavor intel
# break *main
# run with a benign sample input, then record registers and mappings.
""",
        trigger_keywords=(
            "multiarch",
            "arm",
            "mips",
            "aarch64",
            "qemu",
            "gdbserver",
            "debugger",
            "seccomp",
        ),
        file_suffixes=(".elf",),
    ),
    SolverTemplate(
        template_id="crypto_rsa_attack_selector",
        category="crypto",
        title="RSA Attack Selector",
        applicable_signals=(
            "RSA public key, modulus/exponent/ciphertext, or PEM files",
            "Hints mention Fermat, Wiener, common modulus, small exponent, or CRT",
            "Challenge asks for private key recovery or message decryption",
        ),
        required_tools=("RsaCtfTool", "sage", "python3"),
        optional_tools=("z3", "openssl", "factordb", "yafu"),
        workflow_steps=(
            "Parse n, e, c, public keys, and any repeated-modulus relationships.",
            "Check trivial cases: small n, shared factors, small e, and malformed padding.",
            "Try named RSA attacks based on concrete preconditions, not guesswork.",
            "Escalate to factoring, lattice, or Coppersmith only when signals fit.",
            "Verify recovered plaintext encoding and flag format independently.",
            "Write a short note explaining why the selected attack applies.",
        ),
        safety_notes=(
            "Use challenge-provided keys and ciphertexts only.",
            "Avoid online factor database lookups unless network use is allowed.",
            "Do not print private keys from non-challenge material.",
        ),
        expected_artifacts=(
            "parsed RSA parameters",
            "attack precondition notes",
            "tool output",
            "recovered plaintext candidate",
            "verification note",
        ),
        code_skeleton="""\
# RSA worksheet
n = None
e = None
c = None
known = {"p": None, "q": None, "phi": None, "d": None}
checks = ["shared_factor", "fermat", "wiener", "small_exponent", "padding"]
# Fill values from challenge files, then apply only attacks with satisfied preconditions.
""",
        trigger_keywords=(
            "rsa",
            "modulus",
            "public key",
            "ciphertext",
            "fermat",
            "wiener",
            "common modulus",
            "small exponent",
        ),
        file_suffixes=(".pem", ".pub", ".key", ".txt"),
    ),
    SolverTemplate(
        template_id="crypto_prng_lcg_mt19937",
        category="crypto",
        title="LCG and MT19937 PRNG Recovery",
        applicable_signals=(
            "Output sequence from rand, LCG, MT19937, or Python random",
            "Challenge exposes consecutive tokens, nonces, stream values, or timestamps",
            "Need to distinguish parameter recovery from state cloning",
        ),
        required_tools=("python3", "sage"),
        optional_tools=("z3", "randcrack", "numpy"),
        workflow_steps=(
            "Normalize observed outputs, bit widths, truncation, and ordering.",
            "For LCG, solve or brute constrained modulus, multiplier, and increment.",
            "For MT19937, collect enough untempered 32-bit outputs for state recovery.",
            "Model truncated or modular observations with z3 or Sage equations.",
            "Predict only challenge values needed to recover the flag or token.",
            "Record observation count and assumptions so predictions are reproducible.",
        ),
        safety_notes=(
            "Use only challenge-generated token streams.",
            "Do not target live third-party session tokens or production systems.",
            "Label predictions as hypotheses until verified by challenge evidence.",
        ),
        expected_artifacts=(
            "normalized output list",
            "PRNG family decision",
            "recovered parameters or state notes",
            "predicted challenge value",
            "verification transcript",
        ),
        code_skeleton="""\
# PRNG recovery worksheet
observations = []
bit_width = None
model = None  # "lcg" or "mt19937"
recovered = {"modulus": None, "multiplier": None, "increment": None, "state": None}
# Add equations only after confirming output format and truncation.
""",
        trigger_keywords=(
            "lcg",
            "mt19937",
            "mersenne",
            "random",
            "prng",
            "rand",
            "seed",
            "nonce",
        ),
        file_suffixes=(".txt", ".json", ".py"),
    ),
    SolverTemplate(
        template_id="crypto_xor_repeating_key",
        category="crypto",
        title="XOR and Repeating-Key Cipher Analysis",
        applicable_signals=(
            "Ciphertext hints mention XOR, repeating key, crib dragging, or many-time pad",
            "Multiple ciphertexts may reuse a stream or key",
            "Plaintext likely contains known flag, JSON, HTTP, or English structure",
        ),
        required_tools=("python3",),
        optional_tools=("xortool", "cyberchef", "z3"),
        workflow_steps=(
            "Decode transport encodings such as hex, base64, or escaped bytes first.",
            "Estimate key length with Hamming distance, periodicity, or known cribs.",
            "Test single-byte, repeating-key, and reused-keystream hypotheses separately.",
            "Score candidate plaintexts with expected format and flag markers.",
            "Recover the shortest sufficient key material and explain uncertainty.",
        ),
        safety_notes=(
            "Keep analysis limited to provided challenge ciphertexts.",
            "Avoid overfitting English scoring when the plaintext format is known.",
            "Preserve original ciphertexts and write decoded variants separately.",
        ),
        expected_artifacts=(
            "decoded byte streams",
            "key length candidates",
            "crib notes",
            "candidate key bytes",
            "plaintext candidates",
        ),
        code_skeleton="""\
def xor_bytes(left: bytes, right: bytes) -> bytes:
    return bytes(a ^ b for a, b in zip(left, right))

ciphertexts = []
cribs = [b"CTF{", b"flag{"]
key_candidates = []
# Score candidates only after normalizing encodings.
""",
        trigger_keywords=(
            "xor",
            "many time pad",
            "repeating key",
            "crib",
            "keystream",
            "otp",
        ),
        file_suffixes=(".txt", ".bin", ".hex"),
    ),
    SolverTemplate(
        template_id="crypto_hash_length_extension",
        category="crypto",
        title="Hash Length Extension Review",
        applicable_signals=(
            "Challenge uses secret-prefix MAC with MD5, SHA1, SHA256, or similar hash",
            "User-controlled message and digest are both visible",
            "Goal is to append data without knowing the secret prefix",
        ),
        required_tools=("python3",),
        optional_tools=("hashpump", "hlextend", "hash_extender"),
        workflow_steps=(
            "Confirm the construction is secret-prefix hash(message), not HMAC.",
            "Identify hash algorithm, digest, original message, and append target.",
            "Enumerate plausible secret lengths within challenge constraints.",
            "Generate candidate extended messages and digests.",
            "Verify candidates only against the challenge oracle or local checker.",
            "Document why HMAC or suffix-keyed variants would not be vulnerable.",
        ),
        safety_notes=(
            "Use only challenge-owned tokens, messages, and validation endpoints.",
            "Do not brute force unrelated authentication secrets.",
            "Keep candidate tokens redacted in shared notes unless they are CTF artifacts.",
        ),
        expected_artifacts=(
            "hash construction notes",
            "secret length range",
            "extended message candidates",
            "candidate digest list",
            "verification result",
        ),
        code_skeleton="""\
# Length extension worksheet
algorithm = "sha1"
original_message = b""
original_digest = ""
append_data = b""
secret_length_range = range(1, 65)
# Use a reviewed library/tool to build glue padding and candidate digests.
""",
        trigger_keywords=(
            "length extension",
            "hashpump",
            "secret prefix",
            "sha1",
            "md5",
            "mac",
            "digest",
        ),
        file_suffixes=(".txt", ".json"),
    ),
    SolverTemplate(
        template_id="crypto_lattice_coppersmith_hnp",
        category="crypto",
        title="Lattice, Coppersmith, and Hidden Number Attacks",
        applicable_signals=(
            "Challenge mentions LLL, lattice, Coppersmith, HNP, partial nonce, or small roots",
            "RSA or signature values leak partial bits or constrained unknowns",
            "Equations have small unknowns over integers or modular rings",
        ),
        required_tools=("sage", "flatter"),
        optional_tools=("fpylll", "z3", "magma"),
        workflow_steps=(
            "Write exact equations, moduli, bounds, and known/unknown variables.",
            "Confirm each unknown is small enough for a lattice or small-root approach.",
            "Choose the construction: Coppersmith, HNP, knapsack, or custom LLL.",
            "Scale the basis carefully and record determinant/bound assumptions.",
            "Validate candidate roots or keys in the original equations.",
            "Keep a minimal Sage script and a short explanation of the lattice basis.",
        ),
        safety_notes=(
            "Do not apply lattice attacks blindly without bounds.",
            "Keep computations local unless the challenge explicitly allows remote checks.",
            "Record parameters to make failed basis choices debuggable.",
        ),
        expected_artifacts=(
            "equation worksheet",
            "bounds table",
            "basis construction notes",
            "Sage script",
            "candidate roots or key material",
        ),
        code_skeleton="""\
# Sage lattice worksheet
modulus = None
known_values = {}
unknown_bounds = {}
# Define polynomial/equations only after bounds are justified.
# Validate each recovered candidate in the original congruence.
""",
        trigger_keywords=(
            "lattice",
            "lll",
            "coppersmith",
            "hidden number",
            "hnp",
            "partial nonce",
            "small root",
            "knapsack",
        ),
        file_suffixes=(".sage", ".py", ".txt"),
    ),
    SolverTemplate(
        template_id="crypto_aes_mode_padding_mistakes",
        category="crypto",
        title="AES Mode and Padding Mistake Review",
        applicable_signals=(
            "Challenge provides AES ciphertexts, IVs, nonces, padding errors, or oracle responses",
            "Hints mention ECB, CBC bit flipping, CTR nonce reuse, GCM nonce reuse, or padding",
            "Need to distinguish mode misuse from implementation bugs",
        ),
        required_tools=("python3", "openssl"),
        optional_tools=("cyberchef", "z3"),
        workflow_steps=(
            "Identify encoding, block size, mode, IV/nonce handling, and padding scheme.",
            "Check ECB block repetition, CBC malleability, CTR/GCM nonce reuse, and padding oracles.",
            "Build local validators for block alignment and candidate transformations.",
            "Use harmless marker plaintexts when interacting with a challenge oracle.",
            "Recover only the plaintext, token, or key material needed for the CTF flag.",
            "Document why the observed behavior implies the chosen mode bug.",
        ),
        safety_notes=(
            "Use challenge-provided ciphertexts and oracles only.",
            "Avoid high-rate oracle probing; keep requests bounded and logged.",
            "Do not reuse recovered keys outside the challenge context.",
        ),
        expected_artifacts=(
            "mode identification notes",
            "block analysis table",
            "oracle transcript",
            "candidate plaintext",
            "mode-bug explanation",
        ),
        code_skeleton="""\
# AES mode worksheet
block_size = 16
ciphertexts = []
ivs_or_nonces = []
observations = {"ecb_repeats": [], "nonce_reuse": [], "padding_errors": []}
# Add mode-specific checks only after normalizing bytes and block boundaries.
""",
        trigger_keywords=(
            "aes",
            "ecb",
            "cbc",
            "ctr",
            "gcm",
            "padding oracle",
            "nonce reuse",
            "iv",
        ),
        file_suffixes=(".txt", ".bin", ".json"),
    ),
    SolverTemplate(
        template_id="number_theory_factoring_workbench",
        category="number-theory",
        title="Factoring-Heavy Crypto Workbench",
        applicable_signals=(
            "Large composite modulus, RSA-style challenge, or factoring hints",
            "Need to choose between trial, Fermat, Pollard p-1, ECM, SIQS, NFS, or CADO/yafu",
            "Numbers may have close primes, smooth p-1, shared factors, or small cofactors",
        ),
        required_tools=("sage", "python3"),
        optional_tools=("yafu", "msieve", "ecm", "cado-nfs", "pari-gp", "factordb"),
        workflow_steps=(
            "Parse integers exactly and record decimal/hex forms, bit lengths, and gcd relationships.",
            "Run cheap checks first: small factors, perfect powers, gcd across moduli, and close primes.",
            "Select Fermat, Pollard p-1, ECM, SIQS, or NFS based on factor size signals.",
            "Track partial factors and recompose to verify the original integer.",
            "Use recovered factors to derive RSA/private-key values only for challenge material.",
            "Record commands, bounds, curves, and elapsed time for reproducibility.",
        ),
        safety_notes=(
            "Use external factor databases only when challenge rules allow network access.",
            "Do not spend unbounded compute without recording factor-size assumptions.",
            "Never submit non-challenge private keys or moduli to online services.",
        ),
        expected_artifacts=(
            "integer inventory",
            "gcd and bit-length table",
            "factoring method decision",
            "partial or complete factorization",
            "RSA reconstruction notes",
        ),
        code_skeleton="""\
# Factoring worksheet
values = {"n": None}
checks = {
    "bit_length": None,
    "small_factors": [],
    "shared_gcds": [],
    "close_prime_delta": None,
}
factors = []
# Verify product(factors) == n before deriving any RSA values.
""",
        trigger_keywords=(
            "factor",
            "factoring",
            "fermat",
            "pollard",
            "ecm",
            "smooth",
            "cado",
            "yafu",
            "rsa modulus",
        ),
        file_suffixes=(".txt", ".pem", ".pub", ".key"),
    ),
    SolverTemplate(
        template_id="number_theory_modular_equations",
        category="number-theory",
        title="Modular Arithmetic and CRT Equation Solver",
        applicable_signals=(
            "Challenge gives congruences, residues, CRT fragments, modular inverses, or discrete logs",
            "RSA or custom crypto requires reconstructing values from modular constraints",
            "Need a disciplined worksheet before coding transformations",
        ),
        required_tools=("sage", "python3"),
        optional_tools=("pari-gp", "z3", "sympy"),
        workflow_steps=(
            "Normalize all congruences with modulus, residue, and unknown definitions.",
            "Check coprimality and invertibility assumptions before applying CRT or inverses.",
            "Separate exact integer equations from modular equations.",
            "Solve small systems with Sage/SymPy and verify every candidate directly.",
            "Escalate to discrete log or lattice only when group and bound signals match.",
            "Document transformations from challenge statement to solved variables.",
        ),
        safety_notes=(
            "Do not assume moduli are pairwise coprime without checking gcd.",
            "Keep all recovered values tied to challenge artifacts.",
            "Verify results in the original equations before decoding.",
        ),
        expected_artifacts=(
            "congruence table",
            "gcd/invertibility notes",
            "solver script",
            "candidate variables",
            "direct verification output",
        ),
        code_skeleton="""\
# Modular equation worksheet
congruences = []  # tuples of (residue, modulus)
unknowns = {}
assumptions = []
# Check gcd relationships before CRT, inversion, or discrete-log attempts.
""",
        trigger_keywords=(
            "crt",
            "congruence",
            "modular",
            "inverse",
            "discrete log",
            "residue",
            "modulus",
            "number theory",
        ),
        file_suffixes=(".txt", ".sage", ".py"),
    ),
    SolverTemplate(
        template_id="forensics_pcap_network_triage",
        category="forensics",
        title="Network Capture Forensics Triage",
        applicable_signals=(
            "PCAP, PCAPNG, CAP, packet capture, DNS, HTTP objects, credentials, or USB HID",
            "Need protocol summary, extracted objects, anomalies, and timeline",
            "Challenge asks for flag hidden in network traffic",
        ),
        required_tools=("tshark", "capinfos"),
        optional_tools=("wireshark", "NetworkMiner", "usb_hid_extract", "zeek", "strings"),
        workflow_steps=(
            "Record capture hash, packet count, time range, and link-layer type.",
            "Summarize protocols, endpoints, conversations, DNS, and HTTP hosts.",
            "Extract supported objects into a derived directory and hash outputs.",
            "Search for credentials, tokens, long DNS labels, suspicious user agents, and USB HID data.",
            "Build a timeline of notable packets and extracted files.",
            "Summarize recovered flags, credentials, or next hypotheses.",
        ),
        safety_notes=(
            "Analyze captures offline and do not replay packets during triage.",
            "Avoid resolving captured domains unless the challenge explicitly allows it.",
            "Redact credentials in shared notes until confirmed challenge-only.",
        ),
        expected_artifacts=(
            "capture metadata",
            "protocol summary",
            "extracted objects",
            "credential and DNS anomaly notes",
            "timeline",
        ),
        code_skeleton="""\
# PCAP triage worksheet
capture_path = "capture.pcapng"
reports = {
    "metadata": "pcap/capinfos.txt",
    "protocols": "pcap/protocol-summary.txt",
    "objects": "pcap/objects/",
    "timeline": "pcap/timeline.tsv",
}
notable_packets = []
""",
        trigger_keywords=(
            "pcap",
            "pcapng",
            "packet",
            "traffic",
            "dns",
            "http object",
            "usb hid",
            "wireshark",
        ),
        file_suffixes=(".pcap", ".pcapng", ".cap"),
    ),
    SolverTemplate(
        template_id="forensics_document_macro_triage",
        category="forensics",
        title="Document and Macro Forensics Triage",
        applicable_signals=(
            "Office document, PDF, OLE, macro, embedded object, metadata, or suspicious script",
            "Challenge hides data in document properties, streams, attachments, or macros",
            "Need safe static extraction before opening a file",
        ),
        required_tools=("exiftool", "oletools", "file", "strings"),
        optional_tools=("yara", "pdfid", "pdf-parser", "binwalk", "7z"),
        workflow_steps=(
            "Record file hash, type, metadata, and container structure.",
            "Extract OLE streams, macro source, PDF objects, attachments, and embedded files statically.",
            "Run YARA and strings over extracted streams and scripts.",
            "Decode obvious encodings and inspect suspicious URLs, formulas, and comments.",
            "Build a document object map and identify flag-bearing streams.",
            "Document extraction commands and recovered artifacts.",
        ),
        safety_notes=(
            "Do not open unknown documents in a full office suite during triage.",
            "Disable macros and active content in any later manual review.",
            "Keep extracted streams in a derived directory and preserve originals.",
        ),
        expected_artifacts=(
            "metadata report",
            "stream/object listing",
            "macro or script extraction",
            "YARA findings",
            "decoded candidate content",
        ),
        code_skeleton="""\
# Document triage worksheet
document_path = "challenge.docm"
streams = []
macros = []
embedded_objects = []
decoded_candidates = []
# Static extraction first; interactive opening only after risk review.
""",
        trigger_keywords=(
            "doc",
            "docx",
            "docm",
            "pdf",
            "macro",
            "ole",
            "vba",
            "metadata",
            "embedded object",
        ),
        file_suffixes=(".doc", ".docx", ".docm", ".xls", ".xlsx", ".xlsm", ".pdf", ".rtf"),
    ),
    SolverTemplate(
        template_id="forensics_archive_recovery",
        category="forensics",
        title="Archive and Compression Recovery",
        applicable_signals=(
            "ZIP, 7z, tar, gzip, rar, nested archive, corrupted archive, or password hint",
            "Challenge likely hides data in archive comments, extra fields, file names, or nested layers",
            "Need safe extraction, inventory, and repair attempts",
        ),
        required_tools=("7z", "file", "binwalk", "strings"),
        optional_tools=("zipinfo", "zip2john", "john", "foremost", "exiftool"),
        workflow_steps=(
            "Record archive hash and inspect headers, comments, file list, and compression methods.",
            "Test archive integrity and extract into a new workspace directory only.",
            "Inventory nested archives and suspicious names, timestamps, comments, and extra fields.",
            "Carve appended data and repair common header/footer corruption when indicated.",
            "Use challenge-specific password hints before broad cracking workflows.",
            "Summarize recovered files, passwords, and remaining locked entries.",
        ),
        safety_notes=(
            "Prevent path traversal by extracting only inside the workspace.",
            "Do not overwrite files during nested extraction.",
            "Keep password cracking bounded and challenge-specific.",
        ),
        expected_artifacts=(
            "archive inventory",
            "integrity test output",
            "extraction tree",
            "nested archive map",
            "password or repair notes",
        ),
        code_skeleton="""\
# Archive recovery worksheet
archive_path = "challenge.zip"
extraction_root = "archives/extracted"
inventory = []
password_hints = []
repair_attempts = []
# Validate extracted paths stay under extraction_root.
""",
        trigger_keywords=(
            "archive",
            "zip",
            "7z",
            "rar",
            "tar",
            "gzip",
            "password",
            "corrupt",
            "nested",
        ),
        file_suffixes=(".zip", ".7z", ".rar", ".tar", ".gz", ".bz2", ".xz"),
    ),
    SolverTemplate(
        template_id="forensics_carving_disk_recovery",
        category="forensics",
        title="Carving and Disk Recovery Triage",
        applicable_signals=(
            "Disk image, raw image, deleted file, filesystem, firmware, memory-adjacent blob, or carving hint",
            "Need partition, filesystem, deleted-file, and embedded-object recovery",
            "Challenge asks for files hidden in unallocated space or appended data",
        ),
        required_tools=("file", "binwalk", "foremost"),
        optional_tools=("testdisk", "photorec", "sleuthkit", "volatility", "exiftool", "strings"),
        workflow_steps=(
            "Record source image hash, size, partition table, filesystem hints, and entropy hotspots.",
            "Mount or parse images read-only where possible; otherwise work on a copy.",
            "Carve known file types and inspect appended or embedded data streams.",
            "Recover deleted files using filesystem-aware tools before blind carving.",
            "Hash recovered artifacts and triage them recursively with file and strings.",
            "Build a recovery map from offsets, paths, hashes, and candidate flags.",
        ),
        safety_notes=(
            "Never write recovery output into the source image.",
            "Prefer read-only parsing and derived copies over mounting unknown images.",
            "Limit recursive carving depth to avoid noisy or unbounded output.",
        ),
        expected_artifacts=(
            "image metadata",
            "partition and filesystem notes",
            "carved files",
            "deleted file recovery output",
            "offset/path/hash recovery map",
        ),
        code_skeleton="""\
# Disk/carving worksheet
image_path = "disk.img"
recovery_root = "disk/recovered"
partitions = []
carved_files = []
deleted_files = []
offset_map = []
# Store recovered artifacts separately and hash every candidate.
""",
        trigger_keywords=(
            "disk",
            "image",
            "carve",
            "foremost",
            "binwalk",
            "deleted",
            "filesystem",
            "partition",
            "photorec",
            "testdisk",
        ),
        file_suffixes=(".img", ".dd", ".raw", ".bin", ".iso", ".vmdk"),
    ),
)


_TEMPLATE_BY_ID = {template.template_id: template for template in SOLVER_TEMPLATES}

_CATEGORY_ALIASES = {
    ".net": "managed-code",
    "android": "mobile",
    "apk": "mobile",
    "binary": "reverse",
    "binary exploitation": "pwn",
    "crypto": "crypto",
    "cryptography": "crypto",
    "dotnet": "managed-code",
    "forensic": "forensics",
    "forensics": "forensics",
    "managed": "managed-code",
    "managed code": "managed-code",
    "managed-code": "managed-code",
    "mobile": "mobile",
    "native": "reverse",
    "number theory": "number-theory",
    "number-theory": "number-theory",
    "pwn": "pwn",
    "re": "reverse",
    "rev": "reverse",
    "reverse": "reverse",
    "reverse engineering": "reverse",
}


def list_solver_templates() -> list[dict[str, Any]]:
    """Return every solver template in stable catalog order."""

    return [template.to_dict() for template in SOLVER_TEMPLATES]


def get_solver_template(template_id: str) -> dict[str, Any]:
    """Return one solver template by id as a plain dictionary."""

    return _TEMPLATE_BY_ID[template_id].to_dict()


def select_solver_templates(
    description: str = "",
    category: str = "",
    files: Iterable[Any] | None = None,
    findings: Iterable[Any] | Mapping[str, Any] | str | None = None,
    limit: int = 10,
) -> list[dict[str, Any]]:
    """Select matching solver templates from challenge signals.

    Selection is deterministic and side-effect free. Returned dictionaries
    include ``score`` and ``reasons`` plus the template metadata.
    """

    file_names = [str(item) for item in _flatten(files)]
    finding_text = [str(item) for item in _flatten(findings)]
    raw_category = str(category or "")
    normalized_category = _normalize_category(raw_category)
    context = " ".join(
        part for part in [description, raw_category, *file_names, *finding_text] if part
    ).lower()

    matches: list[dict[str, Any]] = []
    for template in SOLVER_TEMPLATES:
        score = 0
        reasons: list[str] = []

        if normalized_category and normalized_category == template.category:
            score += 28
            reasons.append(f"category:{normalized_category}")
        elif normalized_category == "reverse" and template.category in {"mobile", "managed-code"}:
            score += 8
            reasons.append("category:reverse-related")
        elif normalized_category == "crypto" and template.category == "number-theory":
            score += 8
            reasons.append("category:crypto-related")

        suffix_matches = _matching_suffixes(file_names, template.file_suffixes)
        if suffix_matches:
            score += 20 + min(8, len(suffix_matches) * 2)
            reasons.append("file_suffix:" + ",".join(suffix_matches[:3]))

        keyword_matches = [
            keyword
            for keyword in template.trigger_keywords
            if _keyword_matches(keyword, context)
        ]
        signal_matches = [
            signal
            for signal in template.applicable_signals
            if _signal_matches(signal, context)
        ]

        if keyword_matches:
            score += min(36, len(keyword_matches) * 6)
            reasons.append("keyword:" + ",".join(keyword_matches[:3]))
        if signal_matches:
            score += min(12, len(signal_matches) * 4)
            reasons.append("signal:" + str(len(signal_matches)))

        if score <= 0:
            continue

        item = template.to_dict()
        item["score"] = score
        item["reasons"] = sorted(reasons)
        matches.append(item)

    matches.sort(key=lambda item: (-int(item["score"]), str(item["template_id"])))
    return matches[: max(0, limit)]


def validate_solver_templates(
    templates: Iterable[SolverTemplate] = SOLVER_TEMPLATES,
) -> list[str]:
    """Return metadata validation errors for solver templates."""

    errors: list[str] = []
    seen_ids: set[str] = set()
    for template in templates:
        prefix = f"template {template.template_id!r}"
        if not template.template_id:
            errors.append("template id is required")
        elif not _TEMPLATE_ID_PATTERN.match(template.template_id):
            errors.append(f"{prefix}: template_id must be lowercase snake_case")

        if template.template_id in seen_ids:
            errors.append(f"{prefix}: duplicate template id")
        seen_ids.add(template.template_id)

        if not template.category or not template.title:
            errors.append(f"{prefix}: category and title are required")
        if not template.applicable_signals:
            errors.append(f"{prefix}: applicable_signals are required")
        if not template.required_tools:
            errors.append(f"{prefix}: required_tools are required")
        if _has_blank(template.required_tools) or _has_blank(template.optional_tools):
            errors.append(f"{prefix}: tool names must be non-empty")
        if len(set(template.required_tools)) != len(template.required_tools):
            errors.append(f"{prefix}: required_tools must be unique")
        if len(set(template.optional_tools)) != len(template.optional_tools):
            errors.append(f"{prefix}: optional_tools must be unique")
        overlap = set(template.required_tools).intersection(template.optional_tools)
        if overlap:
            errors.append(f"{prefix}: tools cannot be both required and optional")
        if len(template.workflow_steps) < 3:
            errors.append(f"{prefix}: at least three workflow_steps are required")
        if not template.safety_notes:
            errors.append(f"{prefix}: safety_notes are required")
        if not template.expected_artifacts:
            errors.append(f"{prefix}: expected_artifacts are required")
        if _skeleton_has_unsafe_text(template.code_skeleton):
            errors.append(f"{prefix}: code_skeleton contains unsafe exploit text")
    return errors


def _normalize_category(category: str) -> str:
    normalized = " ".join(category.strip().lower().replace("_", " ").split())
    return _CATEGORY_ALIASES.get(normalized, normalized.replace(" ", "-"))


def _matching_suffixes(
    file_names: Iterable[str],
    suffixes: tuple[str, ...],
) -> list[str]:
    matches: list[str] = []
    suffix_set = {suffix.lower() for suffix in suffixes}
    for file_name in file_names:
        lower_name = file_name.lower()
        suffix = PurePath(lower_name).suffix
        if suffix in suffix_set and suffix not in matches:
            matches.append(suffix)
    return matches


def _keyword_matches(keyword: str, context: str) -> bool:
    keyword = keyword.lower()
    if any(not char.isalnum() and char != "_" for char in keyword):
        return keyword in context
    pattern = rf"(?<![a-z0-9_]){re.escape(keyword)}(?![a-z0-9_])"
    return re.search(pattern, context) is not None


def _signal_matches(signal: str, context: str) -> bool:
    words = re.findall(r"[a-z0-9_.+-]+", signal.lower())
    if not words:
        return False
    return sum(1 for word in words if _keyword_matches(word, context)) >= min(3, len(words))


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


def _has_blank(values: Iterable[str]) -> bool:
    return any(not str(value).strip() for value in values)


def _skeleton_has_unsafe_text(code_skeleton: str) -> bool:
    lowered = code_skeleton.lower()
    unsafe_markers = (
        "/bin/sh",
        "shellcraft",
        "execve",
        "system(",
        "os.system",
        "subprocess.",
        "rm -rf",
        "payload =",
        "sendline(",
        "sendafter(",
        "interactive(",
        "remote(",
        "process(",
    )
    return any(marker in lowered for marker in unsafe_markers)


__all__ = [
    "SOLVER_TEMPLATES",
    "SolverTemplate",
    "get_solver_template",
    "list_solver_templates",
    "select_solver_templates",
    "validate_solver_templates",
]
