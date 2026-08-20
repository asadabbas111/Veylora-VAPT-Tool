"""Unit tests for the explainable risk engine."""
from app.risk.engine import (
    RISK_WEIGHTS,
    classify_severity,
    calculate_risk,
    cvss_component,
    exposure_component,
)


def test_severity_bands():
    assert classify_severity(85) == "critical"
    assert classify_severity(65) == "high"
    assert classify_severity(45) == "medium"
    assert classify_severity(25) == "low"
    assert classify_severity(5) == "info"


def test_cvss_component_range():
    assert cvss_component(10.0) == RISK_WEIGHTS["cvss"]
    assert cvss_component(None) == 0.0
    assert cvss_component(5.0) == RISK_WEIGHTS["cvss"] / 2


def test_calculate_risk_high_impact():
    res = calculate_risk(
        cvss=9.8, criticality=10.0, cwe="CWE-78", cve="CVE-2011-2523",
        ip="192.168.56.10", hostname=None, port=21, confidence=95.0,
        attack_path_importance=10.0,
    )
    assert res.classification == "critical"
    assert res.score >= 80
    assert res.breakdown  # breakdown always populated for explainability
    assert "cvss" in res.formula.lower()


def test_calculate_risk_info_for_benign():
    res = calculate_risk(
        cvss=0.0, criticality=1.0, cwe=None, cve=None,
        ip="127.0.0.1", hostname=None, port=8080, confidence=90.0,
    )
    assert res.classification in ("info", "low")
    assert res.score < 20


def test_false_positive_reduces_score():
    base = calculate_risk(cvss=8.0, criticality=8.0, cwe="CWE-89", cve=None,
                          ip="192.168.56.1", hostname=None, port=80,
                          confidence=90.0, false_positive_likelihood=0.0)
    noisy = calculate_risk(cvss=8.0, criticality=8.0, cwe="CWE-89", cve=None,
                           ip="192.168.56.1", hostname=None, port=80,
                           confidence=90.0, false_positive_likelihood=80.0)
    assert noisy.score < base.score
    assert 0 <= noisy.score <= 100


def test_exposure_public_vs_local():
    public = exposure_component("203.0.113.5", None, 443)
    local = exposure_component("127.0.0.1", None, 443)
    assert public > local


def test_custom_weights_respected():
    w = dict(RISK_WEIGHTS)
    w["cvss"] = 10.0
    res = calculate_risk(cvss=10.0, criticality=0.0, cwe=None, cve=None,
                         ip=None, hostname=None, port=None, confidence=0.0,
                         weights=w)
    assert abs(res.breakdown["cvss"] - 10.0) < 1e-6