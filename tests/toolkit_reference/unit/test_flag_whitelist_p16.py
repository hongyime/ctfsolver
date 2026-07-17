"""P1-006 regression: nmap spoof/decoy/evasion flags are forbidden.

The single-char flag fallthrough used to allow any short flag not explicitly
forbidden, letting nmap -S/-D/-g (source spoof, decoy, source-port) through.
These are now in nmap's forbidden_flags (checked before the fallthrough).
"""

import pytest

from src.ctf_core.utils.command_whitelist import get_command_whitelist


def _valid(tool, args):
    is_valid, _err, _args = get_command_whitelist().validate_command(tool, args)
    return is_valid


class TestNmapDangerousFlagsP1_6:
    @pytest.mark.parametrize("flag,val", [
        ("-S", "1.2.3.4"),       # spoof source IP
        ("-D", "RND:10"),        # decoy
        ("-g", "53"),            # spoof source port
        ("--spoof-mac", "0"),    # spoof MAC
        ("--source-port", "53"),
        ("--proxies", "http://x"),
    ])
    def test_spoof_flags_blocked(self, flag, val):
        assert _valid("nmap", [flag, val, "scanme.nmap.org"]) is False

    @pytest.mark.parametrize("args", [
        ["-sV", "-sC", "scanme.nmap.org"],
        ["-p", "1-1000", "scanme.nmap.org"],
        ["-sS", "-Pn", "scanme.nmap.org"],
    ])
    def test_legit_flags_allowed(self, args):
        assert _valid("nmap", args) is True
