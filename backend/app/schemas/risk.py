from typing import Any, Literal

from pydantic import BaseModel

Severity = Literal["critical", "high", "medium", "low", "info"]


class RiskInput(BaseModel):
    cvss: float | None = None
    criticality: float = 1.0
    cwe: str | None = None
    cve: str | None = None
    ip: str | None = None
    hostname: str | None = None
    port: int | None = None
    confidence: float = 50.0
    attack_path_importance: float = 0.0
    false_positive_likelihood: float = 0.0


class RiskBreakdown(BaseModel):
    cvss: float
    asset_criticality: float
    exploitability: float
    exposure: float
    confidence: float
    attack_path: float


class RiskOut(BaseModel):
    score: float
    classification: Severity
    formula: str
    breakdown: dict[str, Any]


class RiskSummaryOut(BaseModel):
    total_findings: int
    severity_counts: dict[str, int]
    avg_risk: float
    max_risk: float
    open_findings: int
    validated: int
    remediation_progress: float