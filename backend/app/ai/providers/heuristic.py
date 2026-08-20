"""Deterministic, offline, fully explainable heuristic AI provider.

Used as the default provider so the platform works without network/API keys.
It derives its conclusions strictly from the structured finding context and the
risk breakdown, which keeps every claim traceable to underlying evidence.
"""

from app.ai.providers.base import AIProvider

PRIORITY_DEADLINES = {
    "P1": "Fix immediately",
    "P2": "Fix within 7 days",
    "P3": "Fix within 30 days",
    "P4": "Fix within 90 days",
}

_REM_BY_CWE = {
    "CWE-78": "Apply the vendor patch, disable the service if unused, and restrict shell access with firewalling and privilege separation.",
    "CWE-94": "Upgrade to a supported version, sanitize inputs, and disable unnecessary dynamic code execution features.",
    "CWE-89": "Use parameterized queries / prepared statements and validate all user input on the server side.",
    "CWE-22": "Normalize and validate all file paths; block traversal sequences and restrict web server document roots.",
    "CWE-287": "Enforce strong authentication, disable default/blank credentials, and enable MFA where possible.",
    "CWE-798": "Replace default credentials with strong unique secrets and rotate them.",
    "CWE-319": "Migrate the service to an encrypted protocol (SSH/TLS) and disable cleartext alternatives.",
    "CWE-327": "Upgrade cryptographic libraries and regenerate keys/host keys.",
    "CWE-93": "Canonicalize and encode user-controlled input before inserting into email headers.",
    "CWE-345": "Deploy integrity controls and randomized source ports as recommended by the vendor.",
    "CWE-200": "Restrict information disclosure by configuration hardening and access control.",
    "CWE-79": "Encode output contextually and adopt a Content-Security-Policy.",
    "CWE-434": "Restrict upload types, store uploads outside the web root, and scan files.",
    "CWE-269": "Remove unnecessary privileges and apply the principle of least privilege.",
    "CWE-352": "Use CSRF tokens, SameSite cookies, and validate origin headers.",
}


class HeuristicProvider(AIProvider):
    name = "rule"

    def available(self) -> tuple[bool, str]:
        return True, "heuristic provider always available"

    def analyze(self, context: dict) -> dict:
        f = context.get("finding", {})
        asset = context.get("asset", {})
        risk = context.get("risk_breakdown", {}) or {}
        score = float(risk.get("total_score", f.get("risk_score", 0)) or 0)
        severity = f.get("severity", "info")
        cwe = (f.get("cwe") or "").upper()
        cve = f.get("cve")
        attack_path_imp = risk.get("attack_path", 0) or 0
        fp_likelihood = float(f.get("confidence_fp", 0) or 0)

        # Severity
        if score >= 80:
            severity = "critical"
        elif score >= 60:
            severity = "high"
        elif score >= 40:
            severity = "medium"
        elif score >= 20:
            severity = "low"
        else:
            severity = "info"

        # Priority
        if severity == "critical" or score >= 75:
            priority, deadline = "P1", PRIORITY_DEADLINES["P1"]
        elif severity == "high" or score >= 55:
            priority, deadline = "P2", PRIORITY_DEADLINES["P2"]
        elif severity == "medium" or score >= 35:
            priority, deadline = "P3", PRIORITY_DEADLINES["P3"]
        else:
            priority, deadline = "P4", PRIORITY_DEADLINES["P4"]

        # Confidence derived from evidence quality + detection confidence
        confidence = float(f.get("confidence", 70) or 70)
        evidence_count = len(context.get("evidence", []))
        confidence = min(97.0, confidence + evidence_count * 4)
        if fp_likelihood > 50:
            confidence = max(40.0, confidence - (fp_likelihood - 50) * 0.5)

        # False positive assessment
        if fp_likelihood >= 50:
            fp_assessment = (
                f"Potential False Positive (likelihood {fp_likelihood:.0f}%): "
                "The finding is based on version fingerprinting and the vulnerable "
                "configuration could not be fully confirmed with the available evidence."
            )
            fp_verdict = "potential_false_positive"
        elif fp_likelihood >= 30:
            fp_assessment = (
                f"Likely True Positive but low confidence ({fp_likelihood:.0f}% false-positive "
                "likelihood): version-based detection with partial corroborating evidence."
            )
            fp_verdict = "likely_true"
        else:
            fp_assessment = (
                f"Likely True Positive (false-positive likelihood {fp_likelihood:.0f}%): "
                "service fingerprint and configuration evidence are consistent with the advertised vulnerability."
            )
            fp_verdict = "likely_true"

        # Explanations
        tech = (
            f"The {asset.get('host','host')} runs {f.get('affected_service') or 'a service'} that "
            f"matches the vulnerable fingerprint for {cve or cwe or 'a known weakness'}. "
            "The detection is based on service version enumeration and the evidence recorded "
            "by the scanning adapter."
        )

        risk_text = (
            f"Risk score {score:.0f}/100 ({severity.upper()}) from "
            f"CVSS weighting (+{risk.get('cvss', 0)}) + asset criticality (+{risk.get('asset_criticality', 0)}) + "
            f"exploitability (+{risk.get('exploitability', 0)}) + exposure (+{risk.get('exposure', 0)}) + "
            f"detection confidence (+{risk.get('confidence', 0)}) + attack-path position (+{risk.get('attack_path', 0)})."
        )

        if attack_path_imp > 0:
            path_text = (
                f"This finding participates in an active attack path toward a critical asset "
                f"(attack-path importance contribution +{attack_path_imp} points). Exploiting it "
                "provides a stepping stone toward higher-value targets."
            )
        else:
            path_text = "No active attack path currently passes through this finding."

        context_refs = [str(k) for k in context.get("basis_refs", [])]
        rem = f.get("remediation") or _REM_BY_CWE.get(cwe, "Review the vendor advisory and apply the relevant security fix.")

        return {
            "provider": self.name,
            "severity": severity,
            "confidence": round(confidence, 1),
            "priority": priority,
            "priority_deadline": deadline,
            "executive_summary": (
                f"{severity.upper()} severity weakness affecting {asset.get('host','a lab host')}. "
                f"{'It is part of an attack path to a critical asset. ' if attack_path_imp > 0 else ''}"
                f"Immediate remediation is recommended to reduce exposure."
            ),
            "technical_explanation": tech,
            "risk_explanation": risk_text,
            "attack_path_explanation": path_text,
            "false_positive_assessment": fp_assessment,
            "false_positive_likelihood": round(fp_likelihood, 1),
            "recommended_remediation": rem,
            "basis": [r for r in context_refs[:10]]
        }