from app.config import settings
from app.scanners.base import RawFinding, ScanResult, ScanTarget
from app.scanners.nmap_adapter import NmapAdapter
from app.scanners.nuclei_adapter import NucleiAdapter
from app.scanners.simulated_adapter import SimulatedLabAdapter
from app.security.kill_switch import kill_switch


class ScanEngine:
    """Selects and runs scanner adapters against scope-validated targets."""

    def __init__(self) -> None:
        self.adapters = {
            "nmap": NmapAdapter(),
            "nuclei": NucleiAdapter(),
            "simulated-lab": SimulatedLabAdapter(),
        }
        # In a fresh deployment without external tools installed, the simulated
        # lab scanner is what makes the platform demonstrable out of the box.
        self.default_order = ["simulated-lab", "nmap", "nuclei"]

    def available_adapters(self) -> list[str]:
        return [name for name in self.default_order if self.adapters[name].validate_configuration()[0]]

    def scan(self, targets: list[ScanTarget], adapters: list[str] | None = None) -> list[ScanResult]:
        """Run every enabled adapter over in-scope targets. Honors the kill switch."""
        kill_switch.check()
        if adapters:
            chosen = [a for a in adapters if a in self.adapters]
        else:
            chosen = [a for a in settings.DEFAULT_SCAN_ADAPTERS.split(",") if a.strip() in self.adapters]
            if not chosen:
                chosen = self.available_adapters()
        results: list[ScanResult] = []
        for name in chosen:
            adapter = self.adapters[name]
            ok, msg = adapter.validate_configuration()
            if not ok:
                results.append(ScanResult(adapter=name, raw_findings=[], logs=[f"adapter unavailable: {msg}"]))
                continue
            try:
                findings = adapter.run(targets)
                results.append(ScanResult(adapter=name, raw_findings=findings, logs=adapter.logs))
            except Exception as exc:  # noqa: BLE001
                results.append(ScanResult(adapter=name, raw_findings=[], logs=[f"adapter error: {exc}"]))
        return results


scan_engine = ScanEngine()