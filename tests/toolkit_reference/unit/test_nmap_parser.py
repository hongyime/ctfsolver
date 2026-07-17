"""Unit tests for Nmap XML parser."""

import pytest
from src.ctf_core.parsers.nmap_parser import (
    parse_nmap_xml,
    parse_host,
    parse_port,
    format_for_database,
    generate_summary,
)


SAMPLE_NMAP_XML = """<?xml version="1.0"?>
<nmaprun scanner="nmap" args="nmap -sV 10.10.10.10">
  <host starttime="1234567890" endtime="1234567890">
    <status state="up"/>
    <address addr="10.10.10.10" addrtype="ipv4"/>
    <hostnames>
      <hostname name="target.local" type="user"/>
    </hostnames>
    <ports>
      <port protocol="tcp" portid="22">
        <state state="open"/>
        <service name="ssh" product="OpenSSH" version="7.2p2"/>
      </port>
      <port protocol="tcp" portid="80">
        <state state="open"/>
        <service name="http" product="Apache" version="2.4.18"/>
      </port>
      <port protocol="tcp" portid="443">
        <state state="closed"/>
      </port>
    </ports>
  </host>
</nmaprun>"""


class TestParseNmapXML:
    """Tests for parse_nmap_xml function."""
    
    def test_parses_valid_xml(self):
        """Test parsing valid Nmap XML."""
        result = parse_nmap_xml(SAMPLE_NMAP_XML)
        assert len(result["hosts"]) == 1
        assert result["hosts"][0]["ip_address"] == "10.10.10.10"
    
    def test_extracts_hostname(self):
        """Test hostname extraction."""
        result = parse_nmap_xml(SAMPLE_NMAP_XML)
        assert result["hosts"][0]["hostname"] == "target.local"
    
    def test_only_includes_open_ports(self):
        """Test that closed ports are excluded."""
        result = parse_nmap_xml(SAMPLE_NMAP_XML)
        services = result["hosts"][0]["services"]
        assert len(services) == 2  # Only open ports
        ports = [s["port"] for s in services]
        assert 22 in ports
        assert 80 in ports
        assert 443 not in ports  # Closed port excluded
    
    def test_handles_invalid_xml(self):
        """Test handling of invalid XML."""
        result = parse_nmap_xml("not valid xml")
        assert "error" in result
        assert len(result["hosts"]) == 0
    
    def test_handles_empty_xml(self):
        """Test handling of empty XML."""
        result = parse_nmap_xml("")
        assert "error" in result or len(result["hosts"]) == 0


class TestParsePort:
    """Tests for parse_port function."""
    
    def test_parses_open_port(self):
        """Test parsing an open port."""
        port_data = {
            "@protocol": "tcp",
            "@portid": "22",
            "state": {"@state": "open"},
            "service": {"@name": "ssh", "@product": "OpenSSH"}
        }
        result = parse_port(port_data)
        assert result is not None
        assert result["port"] == 22
        assert result["protocol"] == "tcp"
        assert result["service_name"] == "ssh"
    
    def test_skips_closed_port(self):
        """Test that closed ports return None."""
        port_data = {
            "@protocol": "tcp",
            "@portid": "443",
            "state": {"@state": "closed"},
        }
        result = parse_port(port_data)
        assert result is None
    
    def test_skips_filtered_port(self):
        """Test that filtered ports return None."""
        port_data = {
            "@protocol": "tcp",
            "@portid": "8080",
            "state": {"@state": "filtered"},
        }
        result = parse_port(port_data)
        assert result is None


class TestGenerateSummary:
    """Tests for generate_summary function."""
    
    def test_generates_readable_summary(self):
        """Test that summary is human-readable."""
        parsed = {
            "hosts": [{
                "ip_address": "10.10.10.10",
                "hostname": "target.local",
                "os_type": "Linux",
                "services": [
                    {"port": 22, "protocol": "tcp", "service_name": "ssh", "banner": "OpenSSH 7.2"},
                    {"port": 80, "protocol": "tcp", "service_name": "http", "banner": "Apache 2.4.18"},
                ]
            }]
        }
        summary = generate_summary(parsed)
        assert "10.10.10.10" in summary
        assert "22/tcp" in summary
        assert "80/tcp" in summary
    
    def test_handles_no_hosts(self):
        """Test handling of empty hosts list."""
        summary = generate_summary({"hosts": []})
        assert "No hosts found" in summary
