from __future__ import annotations

from ctf_core.tool_packs import TOOL_PACKS, ToolPack, validate_tool_packs
from ctf_core.workflow_chains import (
    WORKFLOW_CHAINS,
    get_workflow_chain,
    select_workflow_chains,
    validate_workflow_chains,
)


def _chain_ids(chains: list[dict]) -> list[str]:
    return [str(chain["chain_id"]) for chain in chains]


def test_select_workflow_chains_prefers_web_recon_for_general_web() -> None:
    chains = select_workflow_chains(
        description=(
            "Fingerprint the web app, find hidden directories, discover "
            "parameters, run nuclei-lite, and summarize routes."
        ),
        category="web",
        target="https://challenge.local",
        files=["app.js"],
    )
    chain_ids = _chain_ids(chains)

    assert chain_ids[0] == "web_recon"
    assert "crawler_endpoint_discovery" in chain_ids
    assert "parameter_discovery" in chain_ids

    web_recon = chains[0]
    assert [step["step_id"] for step in web_recon["steps"]] == [
        "fingerprint",
        "probe-live",
        "discover-directories",
        "discover-parameters",
        "nuclei-lite",
        "summary",
    ]
    assert web_recon["steps"][0]["tool"] == "whatweb"
    assert "target" in web_recon["steps"][0]["parameter_templates"]


def test_select_workflow_chains_prefers_specific_api_and_pcap_paths() -> None:
    api_chains = select_workflow_chains(
        description="OpenAPI JWT GraphQL auth and session testing",
        category="web",
        target="https://api.challenge.local/graphql",
        files=["openapi.yaml", "requests.har"],
    )
    pcap_chains = select_workflow_chains(
        description="Packet capture with DNS anomalies and possible USB HID traffic",
        category="forensics",
        files=["capture.pcapng"],
    )

    assert _chain_ids(api_chains)[0] == "api_testing"
    assert _chain_ids(pcap_chains)[0] == "pcap_triage"


def test_workflow_chain_metadata_is_complete_and_declarative() -> None:
    assert validate_workflow_chains() == []
    assert {chain.chain_id for chain in WORKFLOW_CHAINS} == {
        "web_recon",
        "nuclei_lite",
        "crawler_endpoint_discovery",
        "xss_discovery",
        "parameter_discovery",
        "secret_leak",
        "api_testing",
        "pcap_triage",
        "stego_triage",
    }

    for chain in WORKFLOW_CHAINS:
        chain_dict = get_workflow_chain(chain.chain_id)
        assert chain_dict["steps"]
        for step in chain_dict["steps"]:
            assert step["tool"]
            assert step["purpose"]
            assert step["parameter_templates"]
            assert step["prerequisites"]
            assert step["safety_notes"]
            assert "command" not in step
            assert "execute" not in step


def test_tool_pack_metadata_validates_and_stays_opt_in() -> None:
    assert validate_tool_packs() == []
    assert {pack.pack_id for pack in TOOL_PACKS} == {
        "mobile",
        "cloud",
        "malware",
        "gpu-cracking",
        "osint",
    }

    for pack in TOOL_PACKS:
        assert pack.tools
        assert pack.docker_image_hint.startswith(("ctfsolver/", "ctftoolkit/"))
        assert pack.enabled_by_default is False


def test_tool_pack_validation_reports_invalid_metadata() -> None:
    invalid_pack = ToolPack(
        pack_id="Bad_ID",
        name="Invalid",
        category="test",
        tools=("duplicate", "duplicate", ""),
        docker_image_hint="",
        risk="high",
        install_notes=(),
        build_notes=(),
        enabled_by_default=True,
    )

    errors = validate_tool_packs([invalid_pack, invalid_pack])

    assert any("pack_id must be lowercase kebab-case" in error for error in errors)
    assert any("duplicate pack id" in error for error in errors)
    assert any("tools must be unique" in error for error in errors)
    assert any("tool names must be non-empty" in error for error in errors)
    assert any("docker_image_hint is required" in error for error in errors)
    assert any("install_notes are required" in error for error in errors)
    assert any("build_notes are required" in error for error in errors)
    assert any("medium/high risk packs must be opt-in" in error for error in errors)
