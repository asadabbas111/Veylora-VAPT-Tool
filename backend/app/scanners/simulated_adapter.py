"""Realistic simulated lab scanner.

Produces realistic, deterministic findings for deliberately vulnerable lab
targets (Metasploitable / DVWA style hosts) so the full platform workflow can be
demonstrated in an isolated lab without external scanner dependencies.

The generated data mirrors well-known vulnerable-lab services and CVEs and is
used ONLY as a controlled, in-scope simulation source. Real Nmap/Nuclei adapters
are provided alongside this adapter for production usage.
"""

from app.scanners.base import AdapterConfig, RawFinding, ScanTarget, SecurityToolAdapter
from app.services.scope_service import normalize_host

# (port, protocol, service, product, version)
_LAB_PROFILE_BEFORE = [
    (21, "tcp", "ftp", "vsftpd", "2.3.4"),
    (22, "tcp", "ssh", "OpenSSH", "5.1p1 Debian 5"),
    (23, "tcp", "telnet", "Linux telnetd", "0.17"),
    (25, "tcp", "smtp", "Postfix", "2.4.5"),
    (53, "tcp", "domain", "ISC BIND", "9.4.2"),
    (80, "tcp", "http", "Apache httpd", "2.2.8"),
    (111, "tcp", "rpcbind", "rpcbind", "2"),
    (139, "tcp", "netbios-ssn", "Samba smbd", "3.0.20-Debian"),
    (443, "tcp", "https", "Apache httpd (SSL)", "2.2.8"),
    (445, "tcp", "microsoft-ds", "Samba smbd", "3.0.20-Debian"),
    (3306, "tcp", "mysql", "MySQL", "5.0.51a-3ubuntu5"),
    (5432, "tcp", "postgresql", "PostgreSQL", "8.3.1"),
    (8009, "tcp", "ajp13", "Apache Tomcat", "5.5"),
    (8080, "tcp", "http-proxy", "Apache Tomcat", "5.5"),
]

_LAB_VULNS = [
    # title, cve, cwe, severity, cvss, affected service, port, description, remediation, fp-risk, mitre
    {
        "title": "vsftpd 2.3.4 Backdoor Command Execution",
        "cve": "CVE-2011-2523",
        "cwe": "CWE-78",
        "severity": "critical",
        "cvss": 10.0,
        "service": "ftp",
        "port": 21,
        "desc": "vsftpd 2.3.4 contains a backdoor that executes arbitrary commands on port 6200 when a username ending with ':)' is supplied.",
        "fix": "Upgrade vsftpd or remove the FTP service entirely.",
        "fp": 12,
        "technique": ["T1190", "T1210"],
    },
    {
        "title": "OpenSSH 5.1 Cleartext Credential Transmission",
        "cve": "CVE-2008-0166",
        "cwe": "CWE-327",
        "severity": "high",
        "cvss": 8.0,
        "service": "ssh",
        "port": 22,
        "desc": "Predictable random number generator allows key recovery and cleartext credential exposure.",
        "fix": "Upgrade OpenSSH and regenerate host keys.",
        "fp": 35,
        "technique": [],
    },
    {
        "title": "Telnet Protocol Cleartext Traffic",
        "cve": None,
        "cwe": "CWE-319",
        "severity": "high",
        "cvss": 7.5,
        "service": "telnet",
        "port": 23,
        "desc": "Telnet transmits all traffic including credentials in cleartext.",
        "fix": "Disable telnet and enforce SSH.",
        "fp": 10,
        "technique": ["T1040"],
    },
    {
        "title": "Postfix SMTP Mail Header Injection",
        "cve": "CVE-2008-0592",
        "cwe": "CWE-93",
        "severity": "medium",
        "cvss": 5.0,
        "service": "smtp",
        "port": 25,
        "desc": "Postfix before 2.5.2 allows mail header injection via crafted messages.",
        "fix": "Upgrade Postfix to a patched release.",
        "fp": 45,
        "technique": [],
    },
    {
        "title": "BIND 9.4.2 Cache Poisoning Vulnerability",
        "cve": "CVE-2008-1447",
        "cwe": "CWE-345",
        "severity": "medium",
        "cvss": 6.4,
        "service": "domain",
        "port": 53,
        "desc": "Insufficient source port randomization allows DNS cache poisoning.",
        "fix": "Upgrade BIND and enable source port randomization.",
        "fp": 30,
        "technique": [],
    },
    {
        "title": "Apache HTTP Server 2.2.8 Directory Traversal",
        "cve": "CVE-2008-2938",
        "cwe": "CWE-22",
        "severity": "high",
        "cvss": 7.8,
        "service": "http",
        "port": 80,
        "desc": "Apache mod_negotiation allows directory traversal when MultiViews enabled with wildcard mappings.",
        "fix": "Upgrade Apache and disable MultiViews.",
        "fp": 20,
        "technique": ["T1190", "T1083"],
    },
    {
        "title": "Samba 3.0.20 Remote Command Execution (CVE-2007-2447)",
        "cve": "CVE-2007-2447",
        "cwe": "CWE-94",
        "severity": "critical",
        "cvss": 10.0,
        "service": "netbios-ssn",
        "port": 139,
        "desc": "Samba 3.0.20 allows remote attackers to execute arbitrary commands via crafted username to the smbd service.",
        "fix": "Upgrade Samba beyond 3.0.26; restrict SMB exposure.",
        "fp": 18,
        "technique": ["T1210"],
    },
    {
        "title": "MySQL 5.0.51a Unauthenticated Root Access",
        "cve": "CVE-2008-2079",
        "cwe": "CWE-287",
        "severity": "high",
        "cvss": 7.7,
        "service": "mysql",
        "port": 3306,
        "desc": "MySQL allows unauthenticated access to the MySQL database when the empty password root account is enabled.",
        "fix": "Set strong root credentials and restrict MySQL bind address.",
        "fp": 15,
        "technique": ["T1213"],
    },
    {
        "title": "PostgreSQL 8.3.1 Intranet Daemon Remote Code Execution",
        "cve": "CVE-2007-6600",
        "cwe": "CWE-78",
        "severity": "critical",
        "cvss": 9.0,
        "service": "postgresql",
        "port": 5432,
        "desc": "PostgreSQL allows remote code execution as the postgres user via a crafted IMPALIB details argument.",
        "fix": "Upgrade PostgreSQL and configure trust authentication.",
        "fp": 22,
        "technique": ["T1210"],
    },
    {
        "title": "Apache Tomcat 5.5 Default Credentials on Manager Console",
        "cve": None,
        "cwe": "CWE-798",
        "severity": "high",
        "cvss": 7.5,
        "service": "http-proxy",
        "port": 8080,
        "desc": "Tomcat manager interface exposed with default admin/admin credentials.",
        "fix": "Remove default credentials and restrict manager access.",
        "fp": 15,
        "technique": ["T1078"],
    },
]

_SERVICE_VERSION_BY_PORT = {
    21: ("ftp", "vsftpd", "2.3.4"),
    22: ("ssh", "OpenSSH", "5.1p1 Debian 5"),
    23: ("telnet", "Linux telnetd", "0.17"),
    25: ("smtp", "Postfix", "2.4.5"),
    53: ("domain", "ISC BIND", "9.4.2"),
    80: ("http", "Apache httpd", "2.2.8"),
    111: ("rpcbind", "rpcbind", "2"),
    139: ("netbios-ssn", "Samba smbd", "3.0.20-Debian"),
    443: ("https", "Apache httpd (SSL)", "2.2.8"),
    445: ("microsoft-ds", "Samba smbd", "3.0.20-Debian"),
    3306: ("mysql", "MySQL", "5.0.51a-3ubuntu5"),
    5432: ("postgresql", "PostgreSQL", "8.3.1"),
    8009: ("ajp13", "Apache Tomcat", "5.5"),
    8080: ("http-proxy", "Apache Tomcat", "5.5"),
}

# Web-application findings for HTTP (80) and HTTPS (443) endpoints, so reports
# cover both cleartext and TLS-protected web surfaces like a web scanner does.
# (scheme, port, title, cve, cwe, severity, cvss, desc, fix, fp-risk, mitre, url_path)
_LAB_WEB_VULNS = [
    {
        "scheme": "http", "port": 80,
        "title": "Reflected Cross-Site Scripting in Application Search Parameter",
        "cve": None, "cwe": "CWE-79", "severity": "medium", "cvss": 6.1,
        "desc": "The web application reflects user-supplied input in the search results page without proper "
                "output encoding, allowing an attacker to inject and execute arbitrary HTML/JavaScript in a "
                "victim's browser (stored session may also be at risk).",
        "fix": "Encode all dynamic output contextually, adopt a Content-Security-Policy and validate input on the server.",
        "fp": 12, "technique": ["T1059.007", "T1189"],
        "url_path": "/dvwa/vulnerabilities/xss_r/?name=<script>alert(1)</script>",
    },
    {
        "scheme": "http", "port": 80,
        "title": "SQL Injection in User Lookup Parameter",
        "cve": None, "cwe": "CWE-89", "severity": "high", "cvss": 8.6,
        "desc": "A user-controlled parameter is concatenated into a SQL query without parameterization, enabling "
                "an unauthenticated attacker to read, modify or delete database contents and potentially obtain "
                "a web-application shell.",
        "fix": "Use parameterized queries / ORM bindings, apply least-privilege DB accounts and sanitize input.",
        "fp": 8, "technique": ["T1190", "T1213"],
        "url_path": "/dvwa/vulnerabilities/sqli/?id=1' OR '1'='1",
    },
    {
        "scheme": "http", "port": 80,
        "title": "Apache HTTP Server Range Header Denial of Service (CVE-2011-3192)",
        "cve": "CVE-2011-3192", "cwe": "CWE-400", "severity": "high", "cvss": 7.8,
        "desc": "Apache httpd 2.2.x before 2.2.21 does not properly limit the number of 'Range' headers, allowing "
                "an attacker to send many overlapping ranges and exhaust server memory (byteserving memory DoS).",
        "fix": "Upgrade Apache to a patched release (>= 2.2.21) or restrict the MaxRanges directive.",
        "fp": 15, "technique": ["T1499"],
        "url_path": "/",
    },
    {
        "scheme": "http", "port": 80,
        "title": "Missing Security Headers on Web Application",
        "cve": None, "cwe": "CWE-693", "severity": "low", "cvss": 4.3,
        "desc": "Responses do not set hardening headers (X-Frame-Options, X-Content-Type-Options, "
                "Content-Security-Policy). This increases the risk of clickjacking, MIME-sniffing and "
                "injected-content attacks.",
        "fix": "Set X-Frame-Options: DENY, X-Content-Type-Options: nosniff and a strict Content-Security-Policy.",
        "fp": 5, "technique": ["T1189"],
        "url_path": "/dvwa/",
    },
    {
        "scheme": "https", "port": 443,
        "title": "Deprecated TLS 1.0/1.1 Protocols Enabled on HTTPS Service",
        "cve": None, "cwe": "CWE-327", "severity": "medium", "cvss": 5.9,
        "desc": "The HTTPS endpoint negotiates TLS 1.0 and TLS 1.1 in addition to newer versions. These legacy "
                "protocols use weak ciphers that allow downgrade (POODLE/BEAST style) attacks.",
        "fix": "Disable TLS 1.0/1.1 and enforce TLS 1.2+ with a modern cipher suite.",
        "fp": 10, "technique": ["T1557"],
        "url_path": "/",
    },
    {
        "scheme": "https", "port": 443,
        "title": "Self-Signed TLS Certificate Not Trusted",
        "cve": None, "cwe": "CWE-295", "severity": "medium", "cvss": 6.5,
        "desc": "The server presents a self-signed certificate that is not chained to a trusted root CA. Clients "
                "cannot authenticate the server identity, enabling man-in-the-middle interception.",
        "fix": "Replace the certificate with one issued by a trusted CA (or internal PKI trusted by all clients).",
        "fp": 25, "technique": ["T1557"],
        "url_path": "/",
    },
    {
        "scheme": "https", "port": 443,
        "title": "Missing HTTP Strict-Transport-Security Header",
        "cve": None, "cwe": "CWE-319", "severity": "low", "cvss": 4.0,
        "desc": "The HTTPS response omits the Strict-Transport-Security header, leaving browsers vulnerable to "
                "SSL stripping and first-visit downgrade attacks.",
        "fix": "Serve HSTS (max-age>=31536000; includeSubDomains) on HTTPS and preload via hstspreload.org.",
        "fp": 10, "technique": ["T1557"],
        "url_path": "/",
    },
]


def _approx_cvss_vector(cvss: float) -> str:
    """Build a plausible CVSS:3.1 vector from a numerical score (lab data)."""
    if cvss >= 9.5:
        vec = "AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"
    elif cvss >= 8.5:
        vec = "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N"
    elif cvss >= 7.5:
        vec = "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N"
    elif cvss >= 6.5:
        vec = "AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:L/A:N"
    elif cvss >= 5.5:
        vec = "AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:N"
    elif cvss >= 4.0:
        vec = "AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:L/A:N"
    else:
        vec = "AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"
    return f"CVSS:3.1/{vec}"


class SimulatedLabAdapter(SecurityToolAdapter):
    """Deterministic simulated scanner for controlled lab demonstrations."""

    name = "simulated-lab"
    version = "1.0.0"

    def validate_configuration(self) -> tuple[bool, str]:
        return True, "simulated lab adapter always available"

    def run(self, targets: list[ScanTarget]) -> list[RawFinding]:
        findings: list[RawFinding] = []
        for t in targets:
            host = normalize_host(t.value)
            findings.extend(self._scan_host(host))
        return findings

    def _scan_host(self, host: str) -> list[RawFinding]:
        out: list[RawFinding] = []
        for port, _protocol, service, product, version in _LAB_PROFILE_BEFORE:
            for v in _LAB_VULNS:
                if v["port"] == port:
                    out.append(
                        RawFinding(
                            source=self.name,
                            asset_key=host,
                            title=v["title"],
                            description=v["desc"],
                            severity=v["severity"],
                            cvss_score=v["cvss"],
                            cvss_vector=_approx_cvss_vector(v["cvss"]),
                            cve=v["cve"],
                            cwe=v["cwe"],
                            affected_service=service,
                            affected_port=port,
                            protocol="tcp",
                            evidence=[
                                f"{service} banner: SSH-2.0-{product} {version}",
                                f"Service detected on port {port}/tcp via version fingerprint",
                            ],
                            remediation=v["fix"],
                            confidence=100 - v["fp"],
                            metadata={"techniques": v["technique"]},
                        )
                    )

        # Web-application findings for HTTP (80) and HTTPS (443).
        for v in _LAB_WEB_VULNS:
            scheme = v["scheme"]
            base = f"{scheme}://{host}"
            url = f"{base}{v['url_path']}"
            out.append(
                RawFinding(
                    source=self.name,
                    asset_key=host,
                    title=v["title"],
                    description=v["desc"],
                    severity=v["severity"],
                    cvss_score=v["cvss"],
                    cvss_vector=_approx_cvss_vector(v["cvss"]),
                    cve=v["cve"],
                    cwe=v["cwe"],
                    affected_service="https" if scheme == "https" else "http",
                    affected_port=v["port"],
                    protocol="tcp",
                    evidence=[
                        f"Request: {v.get('method', 'GET')} {url}",
                        f"Affected endpoint captured on {scheme.upper()} ({host}:{v['port']}/tcp)",
                    ],
                    remediation=v["fix"],
                    confidence=100 - v["fp"],
                    metadata={"techniques": v["technique"], "url": url, "web_scheme": scheme},
                )
            )
        return out