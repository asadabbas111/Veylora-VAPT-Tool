import json
import shutil
import subprocess

from app.scanners.base import AdapterConfig, RawFinding, ScanTarget, SecurityToolAdapter

_SEVERITY = {"critical": "critical", "high": "high", "medium": "medium", "low": "low", "info": "info"}


class NucleiAdapter(SecurityToolAdapter):
    """Nuclei vulnerability scanner adapter (ProjectDiscovery).

    Runs JSON-mode template scans against scope-validated targets and maps each
    template match into the common RawFinding schema.
    """

    name = "nuclei"
    version = "3.x"

    def validate_configuration(self) -> tuple[bool, str]:
        path = self.config.binary_path or shutil.which("nuclei")
        if not path:
            return False, "nuclei binary not found on PATH"
        return True, f"nuclei available at {path}"

    def run(self, targets: list[ScanTarget]) -> list[RawFinding]:
        ok, msg = self.validate_configuration()
        if not ok:
            raise RuntimeError(msg)
        binary = self.config.binary_path or shutil.which("nuclei")
        cmd = [
            binary, "-jsonl", "-silent",
            *self.config.extra_args,
            *[t.value for t in targets],
        ]
        self.log(f"running: {binary} against {len(targets)} target(s)")
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=self.config.timeout_seconds)
        if proc.returncode not in (0, 1):
            raise RuntimeError(f"nuclei failed: {proc.stderr[-500:]}")
        return self.parse_output(proc.stdout)

    def parse_output(self, output: str) -> list[RawFinding]:
        findings: list[RawFinding] = []
        for line in output.splitlines():
            if not line.strip():
                continue
            try:
                rec = json.loads(line)
            except json.JSONDecodeError:
                continue
            info = rec.get("info", {})
            severity = _SEVERITY.get(str(info.get("severity", "info")).lower(), "info")
            matchers = info.get("matcher-name") or []
            finding = RawFinding(
                source=self.name,
                asset_key=str(rec.get("host") or rec.get("ip") or ""),
                title=str(info.get("name") or rec.get("template-id") or "Nuclei finding"),
                description=str(rec.get("matched-at", "")),
                severity=severity,
                cvss_score=info.get("classification", {}).get("cvss-score"),
                cvss_vector=info.get("classification", {}).get("cvss-metrics"),
                cve=info.get("classification", {}).get("cve-id"),
                cwe=info.get("classification", {}).get("cwe-id"),
                affected_service="http" if "http" in str(rec.get("type", "")).lower() else None,
                evidence=[str(rec.get("matched-at", "")), str(rec.get("curl-command", ""))],
                remediation=info.get("remediation") or info.get("recommendation"),
                confidence=75.0 if not matchers else 60.0,
                metadata={"template_id": rec.get("template-id"), "tags": info.get("tags", [])},
            )
            findings.append(finding)
        return findings