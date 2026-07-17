"""Phase 3 registry security tests.

Asserts the single tool registry cannot be subverted:
  * a known-dangerous binary cannot enter the registry / derived whitelist,
  * every tool has an explicit SecurityLevel and explicit offline flag,
  * derived views stay consistent and round-trip into the layer-1/2 gates.
"""

import sys
from pathlib import Path

import pytest

SRC = Path(__file__).resolve().parent.parent.parent / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from ctf_core.registry import (  # noqa: E402
    TOOL_REGISTRY, ToolEntry, SecurityLevel, DANGEROUS_BINARIES,
    derived_allowed_binaries, derived_tool_images, derived_offline_tools,
)


class TestDangerousBinaryBlocklist:
    @pytest.mark.parametrize("binary", ["rm", "dd", "mkfs", "sh", "zsh", "sudo", "chmod", "mount"])
    def test_dangerous_binary_cannot_be_registered(self, binary):
        with pytest.raises(ValueError, match="dangerous-binary blocklist"):
            ToolEntry(name="evil", binary=binary, image="ctftoolkit/ctf-tools",
                      security_level=SecurityLevel.LOW, offline=True)

    def test_allowed_binaries_disjoint_from_blocklist(self):
        overlap = derived_allowed_binaries() & DANGEROUS_BINARIES
        assert overlap == frozenset(), f"dangerous binaries leaked into whitelist: {overlap}"


class TestExplicitSecurityFields:
    def test_every_tool_has_security_level_enum(self):
        for e in TOOL_REGISTRY:
            assert isinstance(e.security_level, SecurityLevel), e.name

    def test_every_tool_has_explicit_bool_offline(self):
        for e in TOOL_REGISTRY:
            assert isinstance(e.offline, bool), e.name

    def test_security_level_required_no_default(self):
        with pytest.raises(TypeError):
            ToolEntry(name="x", binary="nmap", image="ctftoolkit/ctf-tools",  # type: ignore[call-arg]
                      offline=True)  # security_level omitted

    def test_offline_required_no_default(self):
        with pytest.raises(TypeError):
            ToolEntry(name="x", binary="nmap", image="ctftoolkit/ctf-tools",  # type: ignore[call-arg]
                      security_level=SecurityLevel.MEDIUM)  # offline omitted

    def test_non_bool_offline_rejected(self):
        with pytest.raises(TypeError):
            ToolEntry(name="x", binary="nmap", image="ctftoolkit/ctf-tools",
                      security_level=SecurityLevel.MEDIUM, offline=1)  # type: ignore[arg-type]


class TestRegistryConsistency:
    def test_no_duplicate_tool_names(self):
        names = [e.name for e in TOOL_REGISTRY]
        assert len(names) == len(set(names)), "duplicate tool names in registry"

    def test_every_tool_routes_to_an_image(self):
        images = derived_tool_images()
        for e in TOOL_REGISTRY:
            assert e.name in images and images[e.name], f"{e.name} has no image"

    def test_offline_tools_are_subset_of_known(self):
        offline = derived_offline_tools()
        binaries = {e.binary for e in TOOL_REGISTRY}
        names = {e.name for e in TOOL_REGISTRY}
        assert offline <= (binaries | names)

    def test_derived_whitelist_feeds_command_gate(self):
        # The layer-2 gate must register exactly the registry tools.
        from ctf_core.utils.command_whitelist import get_command_whitelist, SecurityLevel as WLSec
        wl = get_command_whitelist(WLSec.MEDIUM)
        assert set(wl._tools.keys()) == {e.name for e in TOOL_REGISTRY}

    def test_sanitize_allowed_binaries_match_registry(self):
        from ctf_core.utils.sanitize import ALLOWED_BINARIES
        assert ALLOWED_BINARIES == set(derived_allowed_binaries())
