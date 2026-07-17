"""Regression tests for Sprint-3 parser accuracy fixes (P4-*)."""

from src.ctf_core.parsers.hydra_parser import parse_hydra_output
from src.ctf_core.parsers.nikto_parser import parse_nikto_output
from src.ctf_core.parsers.hashcat_parser import parse_hashcat_output
from src.ctf_core.parsers.nmap_parser import parse_nmap_xml
from src.ctf_core.parsers.generic_parser import parse_generic_output
from src.ctf_core.parsers.sqlmap_parser import parse_sqlmap_output
from src.ctf_core.parsers.masscan_parser import parse_masscan_xml


class TestHydraParserP4_2:
    """P4-002: service field must be the real service, not the [DATA] log tag."""

    def test_service_is_real_not_data_tag(self):
        output = (
            "[DATA] max 16 tasks per 1 server, overall 16 tasks, 14344399 login tries\n"
            "[DATA] attacking ssh://10.10.10.5:22/\n"
            "[22][ssh] host: 10.10.10.5   login: root   password: toor\n"
            "1 of 1 target successfully completed, 1 valid password found\n"
        )
        r = parse_hydra_output(output)
        assert r["service"] == "ssh", f"expected ssh, got {r['service']!r}"
        assert r["target"] == "10.10.10.5"
        assert r["success"] is True
        assert {"username": "root", "password": "toor"} in r["credentials"]

    def test_fallback_service_from_attacking_line(self):
        output = "[DATA] attacking ftp://192.168.1.10:21/\n[STATUS] 100.00 tries/min\n"
        r = parse_hydra_output(output)
        assert r["service"] == "ftp"
        assert r["target"] == "192.168.1.10"
        assert r["credentials"] == []

    def test_no_false_service_on_empty(self):
        r = parse_hydra_output("[ERROR] could not connect\n")
        assert r["service"] is None
        assert r["success"] is False


class TestNiktoParserP4_5:
    """P4-005: info header lines are not vulns; ERROR lines parsed (was EERROR typo)."""

    def test_info_lines_excluded_from_vulns(self):
        output = (
            "+ Target IP: 10.0.0.1\n"
            "+ Target Port: 80\n"
            "+ Server: nginx/1.18.0\n"
            "+ Start Time: 2026-01-01\n"
            "+ OSVDB-3092: /admin/: This might be interesting\n"
            "+ /backup/: Directory indexing found\n"
        )
        r = parse_nikto_output(output)
        msgs = [v["message"] for v in r["vulnerabilities"]]
        assert any("OSVDB-3092" in m for m in msgs)
        assert any("Directory indexing" in m for m in msgs)
        assert not any(m.startswith("Server:") or m.startswith("Target IP") for m in msgs)
        assert len(r["vulnerabilities"]) == 2

    def test_error_line_parsed(self):
        r = parse_nikto_output("ERROR: Host not found\n")
        assert any("Host not found" in e for e in r["errors"])


class TestHashcatParserP4_6:
    """P4-006: no div-by-zero on empty progress; cracked pattern beyond lowercase hex."""

    def test_progress_zero_denominator_no_crash(self):
        r = parse_hashcat_output("Progress.........: 0/0 (0.00%)\n")
        assert r["progress"] == 0.0

    def test_cracked_uppercase_hex_and_bcrypt(self):
        output = (
            "DEADBEEF1234567890ABCDEF12345678:password1\n"
            "$2a$10$abcdefghijklmnopqrstuv:hunter2\n"
        )
        r = parse_hashcat_output(output)
        plains = [c["plaintext"] for c in r["cracked_passwords"]]
        assert "password1" in plains
        assert "hunter2" in plains


class TestNmapParserP4_7:
    """P4-007: guard int(port_id) and reject XXE/DTD; normal parse intact."""

    _GOOD = (
        '<?xml version="1.0"?><nmaprun><host>'
        '<address addr="10.0.0.1" addrtype="ipv4"/>'
        '<ports><port protocol="tcp" portid="22">'
        '<state state="open"/><service name="ssh" product="OpenSSH"/>'
        '</port></ports></host></nmaprun>'
    )

    def test_normal_parse_intact(self):
        r = parse_nmap_xml(self._GOOD)
        assert r["hosts"][0]["services"][0]["port"] == 22

    def test_xxe_dtd_rejected(self):
        xxe = '<?xml version="1.0"?><!DOCTYPE x [<!ENTITY a "boom">]><nmaprun></nmaprun>'
        r = parse_nmap_xml(xxe)
        assert r["hosts"] == [] and "error" in r

    def test_non_numeric_portid_skipped(self):
        bad = (
            '<?xml version="1.0"?><nmaprun><host>'
            '<address addr="10.0.0.2" addrtype="ipv4"/>'
            '<ports><port protocol="tcp" portid="abc">'
            '<state state="open"/></port></ports></host></nmaprun>'
        )
        r = parse_nmap_xml(bad)
        assert r["hosts"][0]["services"] == []


class TestGenericParserP4_4:
    """P4-004: hash matches exact lengths; port requires the 'port' label."""

    def test_hash_and_port_precision(self):
        g = parse_generic_output("md5 deadbeefdeadbeefdeadbeefdeadbeef and port 8080 and bare 12345")
        assert "deadbeefdeadbeefdeadbeefdeadbeef" in g["extracted"].get("hash", [])
        assert g["extracted"].get("port", []) == ["8080"]


class TestSqlmapParserP4_3:
    """P4-003: DB list extracted without ReDoS; log 'key: value' lines are not hashes."""

    _OUT = (
        "[INFO] target: http://x/p?id=1\n"
        "available databases [3]:\n"
        "[*] information_schema\n"
        "[*] mysql\n"
        "[*] webapp\n"
        "\n"
        "database management system users password hashes:\n"
        "admin:5f4dcc3b5aa765d61d8327deb882cf99\n"
    )

    def test_databases_extracted(self):
        r = parse_sqlmap_output(self._OUT)
        assert r["databases"] == ["information_schema", "mysql", "webapp"]

    def test_real_hash_extracted(self):
        r = parse_sqlmap_output(self._OUT)
        pairs = [(h["username"], h["password_hash"]) for h in r["password_hashes"]]
        assert ("admin", "5f4dcc3b5aa765d61d8327deb882cf99") in pairs

    def test_log_line_not_hash(self):
        r = parse_sqlmap_output(self._OUT)
        assert not any(h["username"] == "target" for h in r["password_hashes"])


class TestMasscanParserP4_7b:
    """P4-007b: guard int(port_id); reject XXE/DTD."""

    def test_normal_parse(self):
        good = (
            '<?xml version="1.0"?><nmaprun><host>'
            '<address addr="10.0.0.1" addrtype="ipv4"/>'
            '<ports><port protocol="tcp" portid="443">'
            '<state state="open"/></port></ports></host></nmaprun>'
        )
        assert parse_masscan_xml(good)["hosts"][0]["ports"][0]["port"] == 443

    def test_bad_portid_skipped(self):
        bad = (
            '<?xml version="1.0"?><nmaprun><host>'
            '<address addr="10.0.0.2" addrtype="ipv4"/>'
            '<ports><port protocol="tcp" portid="zz">'
            '<state state="open"/></port></ports></host></nmaprun>'
        )
        assert parse_masscan_xml(bad)["hosts"] == []

    def test_xxe_rejected(self):
        r = parse_masscan_xml('<!DOCTYPE x [<!ENTITY a "b">]><nmaprun></nmaprun>')
        assert "error" in r
