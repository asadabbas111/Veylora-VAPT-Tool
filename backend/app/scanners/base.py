from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any


@dataclass
class AdapterConfig:
    """Configuration a tool adapter needs before running."""
    binary_path: str | None = None
    extra_args: list[str] = field(default_factory=list)
    timeout_seconds: int = 300
    enabled: bool = True


@dataclass
class ScanTarget:
    """A scope-validated target the adapter is allowed to act against."""
    value: str
    target_type: str  # ipv4|ipv6|cidr|hostname|domain|url


@dataclass
class RawFinding:
    """Tool-agnostic output that the normalization layer converts to findings."""
    source: str
    asset_key: str                     # ip or hostname the finding applies to
    title: str
    description: str | None = None
    severity: str = "info"             # critical|high|medium|low|info
    cvss_score: float | None = None
    cvss_vector: str | None = None
    cve: str | None = None
    cwe: str | None = None
    affected_service: str | None = None
    affected_port: int | None = None
    protocol: str | None = None
    evidence: list[str] = field(default_factory=list)
    remediation: str | None = None
    confidence: float = 70.0
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass
class ScanResult:
    adapter: str
    raw_findings: list[RawFinding] = field(default_factory=list)
    logs: list[str] = field(default_factory=list)


class SecurityToolAdapter(ABC):
    """Generic interface every scanner adapter must implement."""

    name: str = "base"
    version: str = "0.0.0"

    def __init__(self, config: AdapterConfig | None = None) -> None:
        self.config = config or AdapterConfig()
        self.logs: list[str] = []

    def log(self, message: str) -> None:
        self.logs.append(message)

    def validate_configuration(self) -> tuple[bool, str]:
        """Return (ok, message). Must be called before run()."""
        return True, "no configuration required"

    def health_check(self) -> tuple[bool, str]:
        return self.validate_configuration()

    @abstractmethod
    def run(self, targets: list[ScanTarget]) -> list[RawFinding]:
        """Execute the tool against scope-validated targets only."""

    def parse_output(self, output: str) -> list[RawFinding]:  # pragma: no cover - optional
        return []