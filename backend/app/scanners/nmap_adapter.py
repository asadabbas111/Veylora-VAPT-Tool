import shutil
import subprocess
from xml.etree import ElementTree

from app.scanners.base import AdapterConfig, RawFinding, ScanTarget, SecurityToolAdapter

_SERVICE_SEVERITY = {
    "ftp": "medium",
    "telnet": "high",
    "smtp": "low",
    "http": "low",
    "https": "low",
    "microsoft-ds": "medium",
    "netbios-ssn": "medium",
    "mysql": "medium",
    "postgresql": "medium",
    "ajp13": "medium",
}
_DEFAULT_EXTRA_ARGS = ["--host-timeout", "30s", "--max-retries", "1"]


class NmapAdapter(SecurityToolAdapter):
    """Nmap host/service discovery adapter.

    Runs `nmap -sV -oX - <targets>` and converts the XML output into raw
    findings. Requires nmap to be installed and every active target to be inside
    the authorized assessment scope (verified by the engine before calling run).
    """

    name = "nmap"
    version = "7.x"

    def validate_configuration(self) -> tuple[bool, str]:
        path = self.config.binary_path or shutil.which("nmap")
        if not path:
            return False, "nmap binary not found on PATH"
        return True, f"nmap available at {path}"

    def run(self, targets: list[ScanTarget]) -> list[RawFinding]:
        ok, msg = self.validate_configuration()
        if not ok:
            raise RuntimeError(msg)
        binary = self.config.binary_path or shutil.which("nmap")
        extra = self.config.extra_args or _DEFAULT_EXTRA_ARGS
        cmd = [binary, "-sV", "-Pn", "-T4", "-oX", "-", *extra, *[t.value for t in targets]]
        self.log(f"running: {' '.join(cmd)}")
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=self.config.timeout_seconds)
        if proc.returncode not in (0, 1):  # 1 is a normal nmap 'no host up' partial scan result
            raise RuntimeError(f"nmap failed: {proc.stderr[-500:]}")
        findings = self.parse_output(proc.stdout)
        if not findings:
            self.log("nmap produced no service findings")
        return findings

    def parse_output(self, output: str) -> list[RawFinding]:
        findings: list[RawFinding] = []
        try:
            root = ElementTree.fromstring(output)
        except ElementTree.ParseError:
            return findings
        for host in root.findall("host"):
            addr_el = host.find("address")
            host_ip = addr_el.get("addr") if addr_el is not None else None
            if not host_ip:
                continue
            for port in host.findall("ports/port"):
                portid = int(port.get("portid", "0"))
                protocol = port.get("protocol", "tcp")
                state_el = port.find("state")
                state = state_el.get("state") if state_el is not None else None
                if state != "open":
                    continue
                svc = port.find("service")
                service_name = svc.get("name", "") if svc is not None else ""
                product = svc.get("product", "") if svc is not None else ""
                version = svc.get("version", "") if svc is not None else ""
                if not service_name:
                    continue
                severity = _SERVICE_SEVERITY.get(service_name, "low")
                title = f"{product or service_name} {version} exposed on {service_name}/{protocol}".strip()
                findings.append(
                    RawFinding(
                        source=self.name,
                        asset_key=host_ip,
                        title=title,
                        description=f"Open {protocol} port {portid} running {product} {version} (service fingerprint).",
                        severity=severity,
                        affected_service=service_name,
                        affected_port=portid,
                        protocol=protocol,
                        evidence=[f"nmap service fingerprint: {product} {version} on {host_ip}:{portid}/{protocol}"],
                        confidence=60.0,
                        metadata={"port": portid, "product": product, "version": version},
                    )
                )
        return findings