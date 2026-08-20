"""Unit tests for scanner adapter output parsers (no live tool execution)."""
import json

from app.scanners.nmap_adapter import NmapAdapter
from app.scanners.nuclei_adapter import NucleiAdapter


NMAP_XML = """<?xml version="1.0"?>
<nmaprun>
  <host>
    <address addr="192.168.56.101" addrtype="ipv4"/>
    <ports>
      <port protocol="tcp" portid="21">
        <state state="open" reason="syn-ack"/>
        <service name="ftp" product="vsftpd" version="2.3.4" method="probed" conf="10"/>
      </port>
      <port protocol="tcp" portid="22">
        <state state="closed"/>
        <service name="ssh"/>
      </port>
    </ports>
  </host>
  <host>
    <address addr="192.168.56.102" addrtype="ipv4"/>
    <ports>
      <port protocol="tcp" portid="80">
        <state state="open"/>
        <service name="http" product="Apache" version="2.2.8"/>
      </port>
    </ports>
  </host>
</nmaprun>"""


def test_nmap_parse_standard_output():
    findings = NmapAdapter().parse_output(NMAP_XML)
    assert len(findings) == 2
    ftp = next(f for f in findings if f.affected_service == "ftp")
    assert ftp.asset_key == "192.168.56.101"
    assert ftp.affected_port == 21
    assert ftp.severity == "medium"  # ftp is a medium-risk fingerprint
    assert "vsftpd" in ftp.title


def test_nmap_parse_rejects_bad_xml():
    assert NmapAdapter().parse_output("<not xml") == []


def test_nmap_parse_empty():
    assert NmapAdapter().parse_output("") == []


def test_nuclei_parse_jsonl():
    lines = [
        json.dumps({
            "template-id": "CVE-2011-2523",
            "info": {
                "name": "vsftpd 2.3.4 Backdoor",
                "severity": "critical",
                "classification": {"cve-id": "CVE-2011-2523", "cwe-id": "CWE-78",
                                   "cvss-score": 9.8, "cvss-metrics": "AV:N/AC:L/Au:N/C:C/I:C/A:C"},
                "remediation": "Upgrade vsftpd.",
            },
            "host": "192.168.56.101",
            "matched-at": "192.168.56.101:21",
            "type": "http",
        }),
        "this is not json",
    ]
    findings = NucleiAdapter().parse_output("\n".join(lines))
    assert len(findings) == 1
    f = findings[0]
    assert f.severity == "critical"
    assert f.cve == "CVE-2011-2523"
    assert f.cwe == "CWE-78"
    assert f.cvss_score == 9.8
    assert f.remediation == "Upgrade vsftpd."
    assert f.affected_service == "http"