from sqlalchemy.orm import Session

from app.ai.providers import get_provider
from app.models.ai import AIAnalysis
from app.models.asset import Asset
from app.models.evidence import Evidence
from app.models.finding import Finding
from app.models.remediation import RemediationTask


class AIAnalyst:
    """Builds a structured context from a finding and calls the configured AI
    provider. Persists the analysis and refreshes the finding's priority."""

    def analyze_finding(self, db: Session, finding: Finding, analysis_type: str = "finding_analysis") -> AIAnalysis:
        asset = db.get(Asset, finding.asset_id)
        evidence_items = db.query(Evidence).filter(Evidence.finding_id == finding.id).all()
        remediation = db.query(RemediationTask).filter(
            RemediationTask.finding_id == finding.id, RemediationTask.status.in_(["open", "in_progress"])
        ).first()

        context = {
            "finding": {
                "id": finding.id,
                "title": finding.title,
                "description": finding.description,
                "cve": finding.cve,
                "cwe": finding.cwe,
                "cvss": finding.cvss_score,
                "severity": finding.severity,
                "affected_service": finding.affected_service,
                "affected_port": finding.affected_port,
                "risk_score": finding.risk_score,
                "confidence": finding.confidence,
                "detection_source": finding.detection_source,
                "remediation": finding.remediation,
                "confidence_fp": self._fp_estimate(finding),
            },
            "asset": {
                "host": asset.ip_address or asset.hostname or f"asset-{asset.id}",
                "hostname": asset.hostname,
                "os": asset.os_name,
                "criticality": asset.criticality,
                "asset_risk": asset.risk_score,
            },
            "risk_breakdown": dict(finding.risk_breakdown or {}),
            "evidence": [{"id": e.id, "category": e.category, "source": e.source, "sha256": e.sha256} for e in evidence_items],
            "remediation_task": {
                "status": remediation.status if remediation else None,
                "plan": remediation.remediation_plan if remediation else None,
            } if remediation else None,
            "analysis_type": analysis_type,
            "basis_refs": [
                f"evidence:{e.id} ({e.category})" for e in evidence_items
            ] + [f"risk_breakdown:{k}" for k in (finding.risk_breakdown or {})],
        }

        provider = get_provider()
        decision = provider.analyze(context)

        analysis = AIAnalysis(
            finding_id=finding.id,
            assessment_id=finding.assessment_id,
            analysis_type=analysis_type,
            provider=decision.get("provider", provider.name),
            model=decision.get("model"),
            severity=decision.get("severity", finding.severity),
            confidence=float(decision.get("confidence", 50) or 50),
            priority=decision.get("priority"),
            priority_deadline=decision.get("priority_deadline"),
            executive_summary=decision.get("executive_summary"),
            technical_explanation=decision.get("technical_explanation"),
            risk_explanation=decision.get("risk_explanation"),
            attack_path_explanation=decision.get("attack_path_explanation"),
            false_positive_assessment=decision.get("false_positive_assessment"),
            false_positive_likelihood=decision.get("false_positive_likelihood"),
            recommended_remediation=decision.get("recommended_remediation"),
            basis=decision.get("basis", []),
        )
        db.add(analysis)

        # Refresh finding with AI-derived priority and remediation
        if decision.get("recommended_remediation") and not finding.remediation:
            finding.remediation = decision["recommended_remediation"]
        finding.risk_breakdown = dict(finding.risk_breakdown or {})
        finding.risk_breakdown["ai_priority"] = decision.get("priority")
        db.add(finding)
        db.flush()
        return analysis

    def analyze_assessment(self, db: Session, assessment_id: int) -> list[AIAnalysis]:
        findings = db.query(Finding).filter(Finding.assessment_id == assessment_id).order_by(Finding.risk_score.desc()).all()
        results = []
        for f in findings:
            results.append(self.analyze_finding(db, f))
            db.commit()
        return results

    @staticmethod
    def _fp_estimate(finding: Finding) -> float:
        """Heuristic false-positive likelihood from confidence and evidence."""
        base = 100 - finding.confidence
        if not finding.evidence or len(finding.evidence) == 0:
            base += 20
        return min(95.0, max(5.0, base))


ai_analyst = AIAnalyst()