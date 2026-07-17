from __future__ import annotations

from ctf_core.solver_templates import (
    SOLVER_TEMPLATES,
    SolverTemplate,
    get_solver_template,
    list_solver_templates,
    select_solver_templates,
    validate_solver_templates,
)


def _template_ids(templates: list[dict]) -> list[str]:
    return [str(template["template_id"]) for template in templates]


def _all_tools() -> set[str]:
    tools: set[str] = set()
    for template in SOLVER_TEMPLATES:
        tools.update(template.required_tools)
        tools.update(template.optional_tools)
    return tools


def test_solver_template_catalog_covers_t40_t45_foundation() -> None:
    assert validate_solver_templates() == []

    categories = {template.category for template in SOLVER_TEMPLATES}
    assert {"mobile", "managed-code", "reverse", "pwn", "crypto", "number-theory", "forensics"} <= categories

    template_ids = {template.template_id for template in SOLVER_TEMPLATES}
    assert {
        "mobile_android_static_reverse",
        "managed_dotnet_static_reverse",
        "managed_pyinstaller_unpack",
        "ghidra_batch_summary",
        "ghidra_suspicious_imports_callgraph",
        "pwn_pwntools_scaffold",
        "pwn_libc_resolution_flow",
        "pwn_multiarch_debugger_flow",
        "crypto_rsa_attack_selector",
        "crypto_prng_lcg_mt19937",
        "crypto_xor_repeating_key",
        "crypto_hash_length_extension",
        "crypto_lattice_coppersmith_hnp",
        "crypto_aes_mode_padding_mistakes",
        "number_theory_factoring_workbench",
        "number_theory_modular_equations",
        "forensics_pcap_network_triage",
        "forensics_document_macro_triage",
        "forensics_archive_recovery",
        "forensics_carving_disk_recovery",
    } <= template_ids

    tools = _all_tools()
    assert {"jadx", "apktool", "ilspycmd", "pyinstxtractor", "yara"} <= tools
    assert {"ghidra", "pwntools", "pwninit", "patchelf", "gdb", "gdbserver"} <= tools
    assert {"RsaCtfTool", "sage", "flatter", "tshark", "oletools", "foremost"} <= tools


def test_list_and_get_solver_templates_return_plain_metadata() -> None:
    templates = list_solver_templates()
    first = templates[0]
    fetched = get_solver_template(str(first["template_id"]))

    assert isinstance(first, dict)
    assert fetched == first
    assert _template_ids(templates) == [template.template_id for template in SOLVER_TEMPLATES]

    required_fields = {
        "template_id",
        "category",
        "title",
        "applicable_signals",
        "required_tools",
        "optional_tools",
        "workflow_steps",
        "safety_notes",
        "expected_artifacts",
        "code_skeleton",
    }
    for template in templates:
        assert required_fields <= set(template)
        assert template["workflow_steps"]
        assert template["safety_notes"]
        assert template["expected_artifacts"]


def test_select_solver_templates_is_deterministic_and_signal_ranked() -> None:
    first = select_solver_templates(
        description="Android APK has classes.dex, smali, and obfuscated Kotlin validation logic",
        category="reverse engineering",
        files=["challenge.apk"],
        findings=["AndroidManifest mentions a secret activity"],
        limit=5,
    )
    second = select_solver_templates(
        description="Android APK has classes.dex, smali, and obfuscated Kotlin validation logic",
        category="reverse engineering",
        files=["challenge.apk"],
        findings=["AndroidManifest mentions a secret activity"],
        limit=5,
    )

    assert first == second
    assert _template_ids(first)[0] == "mobile_android_static_reverse"
    assert first[0]["score"] >= first[1]["score"]
    assert first[0]["reasons"] == sorted(first[0]["reasons"])


def test_select_solver_templates_prefers_specific_t41_t45_paths() -> None:
    ghidra_ids = _template_ids(
        select_solver_templates(
            description="Use Ghidra to review suspicious imports and build a call graph",
            category="reverse",
            files=["checker.exe"],
        )
    )
    pwn_ids = _template_ids(
        select_solver_templates(
            description="ret2libc pwn challenge with provided libc and loader",
            category="pwn",
            files=["chall.elf", "libc.so"],
        )
    )
    rsa_ids = _template_ids(
        select_solver_templates(
            description="RSA modulus n, exponent e, ciphertext c, maybe Fermat factoring",
            category="crypto",
            files=["public.pem"],
        )
    )
    factoring_ids = _template_ids(
        select_solver_templates(
            description="Factoring heavy RSA modulus with smooth p-1 and ECM hints",
            category="number theory",
            files=["modulus.txt"],
        )
    )
    pcap_ids = _template_ids(
        select_solver_templates(
            description="Packet capture with DNS anomalies and USB HID traffic",
            category="forensics",
            files=["capture.pcapng"],
        )
    )
    document_ids = _template_ids(
        select_solver_templates(
            description="Office document macro with OLE streams and embedded object",
            category="forensics",
            files=["invoice.docm"],
        )
    )
    archive_ids = _template_ids(
        select_solver_templates(
            description="Corrupt nested zip archive with password hints",
            category="forensics",
            files=["challenge.zip"],
        )
    )
    disk_ids = _template_ids(
        select_solver_templates(
            description="Disk image needs deleted file recovery and carving",
            category="forensics",
            files=["disk.img"],
        )
    )

    assert ghidra_ids[0] == "ghidra_suspicious_imports_callgraph"
    assert pwn_ids[0] == "pwn_libc_resolution_flow"
    assert rsa_ids[0] == "crypto_rsa_attack_selector"
    assert factoring_ids[0] == "number_theory_factoring_workbench"
    assert pcap_ids[0] == "forensics_pcap_network_triage"
    assert document_ids[0] == "forensics_document_macro_triage"
    assert archive_ids[0] == "forensics_archive_recovery"
    assert disk_ids[0] == "forensics_carving_disk_recovery"


def test_crypto_solver_templates_cover_requested_attack_families() -> None:
    crypto_text = "\n".join(
        " ".join(
            [
                template.title,
                *template.applicable_signals,
                *template.workflow_steps,
                template.code_skeleton,
            ]
        ).lower()
        for template in SOLVER_TEMPLATES
        if template.category in {"crypto", "number-theory"}
    )

    for term in [
        "rsa",
        "lcg",
        "mt19937",
        "xor",
        "length extension",
        "lattice",
        "aes",
        "padding",
        "factoring",
    ]:
        assert term in crypto_text


def test_pwn_template_skeletons_remain_safe_and_educational() -> None:
    forbidden = (
        "/bin/sh",
        "shellcraft",
        "execve",
        "system(",
        "payload =",
        "sendline(",
        "sendafter(",
        "interactive(",
        "remote(",
        "process(",
    )

    for template in SOLVER_TEMPLATES:
        skeleton = template.code_skeleton.lower()
        assert not any(marker in skeleton for marker in forbidden)
        if template.category == "pwn":
            safety_text = " ".join(template.safety_notes).lower()
            assert "challenge" in safety_text
            assert "shell" not in skeleton


def test_solver_template_validation_reports_metadata_errors() -> None:
    invalid = SolverTemplate(
        template_id="Bad-ID",
        category="",
        title="",
        applicable_signals=(),
        required_tools=("tool", "tool", ""),
        optional_tools=("tool", ""),
        workflow_steps=("only one",),
        safety_notes=(),
        expected_artifacts=(),
        code_skeleton="payload = b'/bin/sh'",
    )

    errors = validate_solver_templates([invalid, invalid])

    assert any("template_id must be lowercase snake_case" in error for error in errors)
    assert any("duplicate template id" in error for error in errors)
    assert any("category and title are required" in error for error in errors)
    assert any("applicable_signals are required" in error for error in errors)
    assert any("tool names must be non-empty" in error for error in errors)
    assert any("required_tools must be unique" in error for error in errors)
    assert any("tools cannot be both required and optional" in error for error in errors)
    assert any("at least three workflow_steps are required" in error for error in errors)
    assert any("safety_notes are required" in error for error in errors)
    assert any("expected_artifacts are required" in error for error in errors)
    assert any("code_skeleton contains unsafe exploit text" in error for error in errors)
