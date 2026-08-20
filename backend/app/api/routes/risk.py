from fastapi import APIRouter, HTTPException

from app.deps import CurrentUser, DbDep
from app.models.asset import Asset
from app.models.finding import Finding
from app.models.remediation import RemediationTask
from app.risk.engine import calculate_risk, RISK_WEIGHTS
from app.schemas.risk import RiskInput, RiskOut, RiskSummaryOut
from app.services.audit_service import audit

router = APIRouter(prefix="/risk", tags=["risk"])


@router.post("/calculate", response_model=RiskOut)
def calculate(payload: RiskInput, db: DbDep, user: CurrentUser):
    result = calculate_risk(
        cvss=payload.cvss, criticality=payload.criticality, cwe=payload.cwe, cve=payload.cve,
        ip=payload.ip, hostname=payload.hostname, port=payload.port,
        confidence=payload.confidence, attack_path_importance=payload.attack_path_importance,
        false_positive_likelihood=payload.false_positive_likelihood,
    )
    return RiskOut(score=result.score, classification=result.classification, formula=result.formula, breakdown=result.breakdown)


@router.get("/weights")
def weights(db: DbDep, user: CurrentUser):
    return {
        "weights": RISK_WEIGHTS,
        "max_score": 100,
        "bands": {"critical": "80-100", "high": "60-79", "medium": "40-59", "low": "20-39", "info": "0-19"},
        "formula": "CVSS(<=40) + Asset Criticality(<=15) + Exploitability(<=10) + Exposure(<=20) + Confidence(<=5) + Attack Path(<=10) - FalsePositivePenalty",
    }


@router.get("/assessment/{assessment_id}/summary", response_model=RiskSummaryOut)
def assessment_risk_summary(assessment_id: int, db: DbDep, user: CurrentUser):
    findings = db.query(Finding).filter(Finding.assessment_id == assessment_id).all()
    if not findings:
        return RiskSummaryOut(total_findings=0, severity_counts={}, avg_risk=0, max_risk=0, open_findings=0, validated=0, remediation_progress=0)
    sev = {}
    for f in findings:
        sev[f.severity] = sev.get(f.severity, 0) + 1
    open_f = sum(1 for f in findings if f.status in ("open", "acknowledged", "in_progress", "retest_required"))
    tasks = db.query(RemediationTask).filter(RemediationTask.assessment_id == assessment_id).all()
    done = sum(1 for t in tasks if t.status in ("fixed", "verified"))
    return RiskSummaryOut(
        total_findings=len(findings),
        severity_counts=sev,
        avg_risk=round(sum(f.risk_score for f in findings) / len(findings), 2),
        max_risk=round(max(f.risk_score for f in findings), 2),
        open_findings=open_f,
        validated=sum(1 for f in findings if f.confidence >= 80),
        remediation_progress=round(done / len(tasks) * 100, 1) if tasks else 0.0,
    )


@router.get("/assets/{asset_id}/breakdown")
def asset_risk_breakdown(asset_id: int, db: DbDep, user: CurrentUser):
    """Explain the risk of an asset and every one of its findings."""
    asset = db.get(Asset, asset_id)
    if not asset:
        raise HTTPException(status_code=404, detail="Asset not found.")
    findings = db.query(Finding).filter(Finding.asset_id == asset_id).all()
    return {
        "asset": {"id": asset.id, "ip": asset.ip_address, "hostname": asset.hostname, "risk": asset.risk_score,
                  "criticality": asset.criticality},
        "findings": [
            {"id": f.id, "title": f.title, "risk": f.risk_score, "severity": f.severity,
             "breakdown": f.risk_breakdown, "formula": " + ".join(f"+{v}" for v in (f.risk_breakdown or {}).values() if isinstance(v, (int, float)) and v != 0)}
            for f in findings
        ],
    }