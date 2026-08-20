from fastapi import APIRouter, HTTPException

from app.ai.analyst import ai_analyst
from app.ai.providers import available_providers, get_provider
from app.config import settings


from app.ai.analyst import ai_analyst
from app.ai.providers import available_providers, get_provider
from app.config import settings
from app.deps import CurrentUser, DbDep, require_permission, RequirePermission
from app.models.ai import AIAnalysis
from app.models.assessment import Assessment
from app.models.finding import Finding
from app.schemas.finding import AIAnalysisOut
from app.services.audit_service import audit
from app.tasks.manager import task_manager
from app.models.job import Job

router = APIRouter(prefix="/ai", tags=["ai"])


@router.post("/analyze/{finding_id}", response_model=AIAnalysisOut)
def analyze_finding(finding_id: int, db: DbDep, user: RequirePermission("run_ai")):
    f = db.get(Finding, finding_id)
    if not f:
        raise HTTPException(status_code=404, detail="Finding not found.")
    analysis = ai_analyst.analyze_finding(db, f)
    db.commit()
    db.refresh(analysis)
    audit(db, user.id, "AI analysis generated", assessment_id=f.assessment_id,
          object_type="finding", object_id=finding_id, result="success")
    return analysis


@router.post("/analyze-assessment/{assessment_id}", status_code=202)
def analyze_assessment(assessment_id: int, db: DbDep, user: RequirePermission("run_ai")):
    a = db.get(Assessment, assessment_id)
    if not a:
        raise HTTPException(status_code=404, detail="Assessment not found.")
    from app.tasks.pipeline import stage_ai_analysis

    job = Job(assessment_id=assessment_id, task_type="ai_analysis", status="pending", started_by=user.id)
    db.add(job)
    db.commit()
    db.refresh(job)
    task_manager.submit(job.id, stage_ai_analysis, assessment_id)
    audit(db, user.id, "AI analysis requested", assessment_id=assessment_id, object_type="job", object_id=job.id, result="success")
    return {"job_id": job.id, "message": "AI analysis started for all findings"}


@router.get("/providers")
def list_providers(db: DbDep, user: CurrentUser):
    return {
        "configured": settings.AI_PROVIDER,
        "providers": available_providers(),
    }


@router.get("/prioritization")
def prioritization(assessment_id: int, db: DbDep, user: CurrentUser):
    """Ranked priority queue (P1..P4) using AI/context-aware scoring."""
    findings = db.query(Finding).filter(Finding.assessment_id == assessment_id).order_by(Finding.risk_score.desc()).all()
    rank = []
    for i, f in enumerate(findings, start=1):
        rd = f.rank_breakdown if hasattr(f, "rank_breakdown") and f.rank_breakdown else f.risk_breakdown or {}
        priority = (rd or {}).get("ai_priority") or _priority_for(f.risk_score)
        rank.append({
            "rank": i, "finding_id": f.id, "title": f.title, "risk": f.risk_score,
            "severity": f.severity, "priority": priority,
            "deadline": _deadline_for(priority),
            "asset": f.asset.ip_address if f.asset else None,
            "status": f.status,
            "breakdown": rd,
        })
    return {"total": len(rank), "items": rank}


def _priority_for(score: float) -> str:
    if score >= 75: return "P1"
    if score >= 55: return "P2"
    if score >= 35: return "P3"
    return "P4"


def _deadline_for(priority: str) -> str:
    return {
        "P1": "Fix immediately", "P2": "Fix within 7 days",
        "P3": "Fix within 30 days", "P4": "Fix within 90 days",
    }.get(priority, "-")