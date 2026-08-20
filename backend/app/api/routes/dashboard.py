from datetime import datetime, timedelta

from fastapi import APIRouter
from sqlalchemy import func
from sqlalchemy.orm import Session

from app.deps import CurrentUser, DbDep
from app.models.assessment import Assessment
from app.models.asset import Asset
from app.models.finding import Finding
from app.models.graph import AttackPath
from app.models.remediation import RemediationTask

router = APIRouter(prefix="/dashboard", tags=["dashboard"])


def _bucket(dt: datetime) -> str:
    return dt.strftime("%Y-%m-%d")


@router.get("/summary")
def summary(db: DbDep, user: CurrentUser):
    # Dashboard only ever reflects the current user's OWN assessments. This keeps
    # the dashboard honest: counts stay zero, in-and-out until the user defines a
    # scope, runs scans and builds findings. Admins explicitly opt in to see
    # everything via the assessments list, not the dashboard.
    q_a = db.query(Assessment).filter(Assessment.owner_id == user.id)
    assessments = q_a.order_by(Assessment.created_at.desc()).all()
    assessment_ids = [a.id for a in assessments] or [0]

    assets = db.query(Asset).filter(Asset.assessment_id.in_(assessment_ids)).count()
    findings = db.query(Finding).filter(Finding.assessment_id.in_(assessment_ids)).all()
    sev: dict[str, int] = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for f in findings:
        sev[f.severity] = sev.get(f.severity, 0) + 1

    open_f = sum(1 for f in findings if f.status in ("open", "acknowledged", "in_progress", "retest_required"))
    paths = db.query(AttackPath).filter(AttackPath.assessment_id.in_(assessment_ids), AttackPath.is_current.is_(True)).count()
    max_risk = max((f.risk_score for f in findings), default=0.0)

    tasks = db.query(RemediationTask).filter(RemediationTask.assessment_id.in_(assessment_ids)).all()
    done = sum(1 for t in tasks if t.status in ("fixed", "verified"))
    rem_progress = round(done / len(tasks) * 100, 1) if tasks else 0.0
    validated = sum(1 for f in findings if f.confidence >= 80)

    # Vulnerability trend by day (last 14 days)
    trend: dict[str, int] = {}
    for f in findings:
        day = _bucket(f.first_seen)
        trend[day] = trend.get(day, 0) + 1

    # Risk by asset (top 12)
    risk_by_asset = (
        db.query(Asset.ip_address, Asset.hostname, Asset.risk_score, Asset.criticality)
        .filter(Asset.assessment_id.in_(assessment_ids))
        .order_by(Asset.risk_score.desc()).limit(12).all()
    )

    # Acquisition by severity for charts
    active_assessments = sum(1 for a in assessments if a.status in ("running", "scoping"))
    completed = sum(1 for a in assessments if a.status == "completed")

    return {
        "cards": {
            "total_assets": assets,
            "open_vulnerabilities": open_f,
            "critical_findings": sev.get("critical", 0),
            "high_findings": sev.get("high", 0),
            "attack_paths": paths,
            "validated_findings": validated,
            "max_risk": round(max_risk, 1),
            "remediation_progress": rem_progress,
            "total_findings": len(findings),
            "assessments": len(assessments),
            "active_assessments": active_assessments,
            "completed_assessments": completed,
        },
        "charts": {
            "severity_distribution": [
                {"key": k, "value": v} for k, v in sev.items()
            ],
            "risk_by_asset": [
                {"label": (ip or host or f"asset-{[x for x in ['id']]}"), "value": r, "criticality": c}
                for (ip, host, r, c) in risk_by_asset
            ],
            "vulnerability_trend": [{"date": k, "findings": v} for k, v in sorted(trend.items())],
            "remediation_status": _remediation_chart(tasks),
        },
        "recent_assessments": [
            {"id": a.id, "name": a.name, "status": a.status, "progress": a.progress, "stage": a.stage, "created_at": a.created_at}
            for a in assessments[:8]
        ],
    }


def _remediation_chart(tasks: list[RemediationTask]) -> list[dict]:
    statuses = {"open": 0, "acknowledged": 0, "in_progress": 0, "fixed": 0, "retest_required": 0,
                "verified": 0, "false_positive": 0, "risk_accepted": 0}
    for t in tasks:
        if t.status in statuses:
            statuses[t.status] += 1
    return [{"key": k, "value": v} for k, v in statuses.items()]