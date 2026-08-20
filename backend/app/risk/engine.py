"""Explainable, configurable risk engine.

The platform does not rely on CVSS alone. Every finding receives a context-aware
0-100 risk score with a documented breakdown so the UI can display WHY a score
was assigned.

Weights::

    WA  (CVSS weight)         0..40
    WAC (Asset criticality)   0..15
    WE  (Exploitability)      0..10
    WX  (Exposure)            0..20
    WC  (Detection confidence)0..5
    WAP (Attack-path position)0..10
    Total                     0..100

Scoring is driven by the RISK_WEIGHTS configuration and can be tuned without
touching the code. The classification bands::

    0-19 Informational, 20-39 Low, 40-59 Medium, 60-79 High, 80-100 Critical
"""

from dataclasses import dataclass, field
from typing import Any

RISK_WEIGHTS: dict[str, float] = {
    "cvss": 40.0,
    "asset_criticality": 15.0,
    "exploitability": 10.0,
    "exposure": 20.0,
    "confidence": 5.0,
    "attack_path": 10.0,
}

# CWE -> exploitability weight (0..10).
CWE_EXPLOITABILITY: dict[str, float] = {
    "CWE-78": 10.0, "CWE-94": 10.0, "CWE-89": 10.0, "CWE-77": 10.0,
    "CWE-22": 9.0, "CWE-434": 9.0, "CWE-287": 8.0, "CWE-798": 8.0,
    "CWE-269": 8.0, "CWE-200": 6.0, "CWE-79": 4.0, "CWE-93": 6.0,
    "CWE-345": 4.0, "CWE-319": 3.0, "CWE-327": 3.0, "CWE-352": 5.0,
}

_DEFAULT_EXPLOITABILITY = 5.0

# Known highly exploitable CVEs (public exploit availability adds weight).
HIGHLY_EXPLOITABLE_CVES = {
    "CVE-2011-2523",  # vsftpd backdoor
    "CVE-2007-2447",  # Samba usermap_script
    "CVE-2007-6600",  # PostgreSQL IMPALIB
}

PRIVATE_NETWORKS = ("10.", "192.168.", "172.16.", "172.17.", "172.18.", "172.19.",
                    "172.2", "172.3", "172.4", "172.5", "172.6", "172.7", "172.8", "172.9")


def classify_severity(score: float) -> str:
    if score >= 80:
        return "critical"
    if score >= 60:
        return "high"
    if score >= 40:
        return "medium"
    if score >= 20:
        return "low"
    return "info"


def classify_cvss(cvss: float | None) -> str:
    if cvss is None:
        return "info"
    if cvss >= 9.0:
        return "critical"
    if cvss >= 7.0:
        return "high"
    if cvss >= 4.0:
        return "medium"
    if cvss >= 0.1:
        return "low"
    return "info"


def cvss_component(cvss: float | None) -> float:
    """Map CVSS 0..10 onto the 0..40 weight component."""
    if cvss is None:
        return 0.0
    return round(min(max(cvss, 0.0), 10.0) * RISK_WEIGHTS["cvss"] / 10.0, 2)


def asset_criticality_component(criticality: float) -> float:
    """Map asset criticality 0..10 onto 0..15."""
    return round(min(max(criticality, 0.0), 10.0) * RISK_WEIGHTS["asset_criticality"] / 10.0, 2)


def exploitability_component(cwe: str | None, cve: str | None) -> float:
    base = CWE_EXPLOITABILITY.get(cwe or "", _DEFAULT_EXPLOITABILITY)
    if cve and cve.upper() in HIGHLY_EXPLOITABLE_CVES:
        base = min(10.0, base + 2.0)
    return round(base, 2)


def exposure_component(ip: str | None, hostname: str | None, port: int | None) -> float:
    """Estimate exposure: public / DMZ hosts get the most weight, isolated lab
    hosts get less, localhost the least. Academic-lab IP ranges are treated as
    internal so results stay meaningful in an isolated course network."""
    if not ip and not hostname:
        return round(RISK_WEIGHTS["exposure"] * 0.6, 2)
    host = (ip or hostname or "").lower()
    if host.startswith("127.") or host == "localhost":
        return round(RISK_WEIGHTS["exposure"] * 0.15, 2)
    if host.startswith(PRIVATE_NETWORKS) or "internal" in host or host.endswith(".lab"):
        return round(RISK_WEIGHTS["exposure"] * 0.5, 2)
    if port and port in (80, 443, 8080, 8000, 8443):
        return RISK_WEIGHTS["exposure"]  # public web services fully exposed
    return round(RISK_WEIGHTS["exposure"] * 0.8, 2)


def confidence_component(confidence: float) -> float:
    """Map detection confidence 0..100 onto 0..5."""
    return round(min(max(confidence, 0.0), 100.0) / 20.0, 2)


def attack_path_component(path_importance: float) -> float:
    """Adds up to 10 points for the finding's position on a real attack path."""
    return round(min(max(path_importance, 0.0), 10.0), 2)


@dataclass
class RiskResult:
    score: float
    classification: str
    breakdown: dict[str, Any] = field(default_factory=dict)

    @property
    def formula(self) -> str:
        parts = []
        for key in ("cvss", "asset_criticality", "exploitability", "exposure", "confidence", "attack_path"):
            parts.append(f"{key.title().replace('_', ' ')}: +{self.breakdown.get(key, 0)}")
        return " + ".join(parts) + f" = {self.score}/100"


def calculate_risk(
    cvss: float | None,
    criticality: float,
    cwe: str | None,
    cve: str | None,
    ip: str | None,
    hostname: str | None,
    port: int | None,
    confidence: float,
    attack_path_importance: float = 0.0,
    false_positive_likelihood: float = 0.0,
    weights: dict[str, float] | None = None,
) -> RiskResult:
    """Compute the contextual risk score with an explainable breakdown."""
    w = weights or RISK_WEIGHTS

    comps = {
        "cvss": cvss_component(cvss) * (w["cvss"] / RISK_WEIGHTS["cvss"]),
        "asset_criticality": asset_criticality_component(criticality) * (w["asset_criticality"] / RISK_WEIGHTS["asset_criticality"]),
        "exploitability": exploitability_component(cwe, cve) * (w["exploitability"] / RISK_WEIGHTS["exploitability"]),
        "exposure": exposure_component(ip, hostname, port) * (w["exposure"] / RISK_WEIGHTS["exposure"]),
        "confidence": confidence_component(confidence) * (w["confidence"] / RISK_WEIGHTS["confidence"]),
        "attack_path": attack_path_component(attack_path_importance) * (w["attack_path"] / RISK_WEIGHTS["attack_path"]),
    }

    # False-positive likelihood reduces the total (evidence quality correction).
    penalty = min(25.0, comps["confidence"] * (false_positive_likelihood / 100.0))
    total = sum(comps.values()) - penalty
    score = round(min(max(total, 0.0), 100.0), 2)

    return RiskResult(
        score=score,
        classification=classify_severity(score),
        breakdown={k: round(v, 2) for k, v in comps.items()},
    )