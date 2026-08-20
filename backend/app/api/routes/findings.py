from fastapi import APIRouter, HTTPException, Query
from sqlalchemy.orm import Session


from sqlalchemy.orm import Session

from app.deps import CurrentUser, DbDep, require_permission, RequirePermission
from app.models.ai import AIAnalysis
from app.models.asset import Asset
from app.models.finding import Finding
from app.models.graph import AttackPath
from app.models.remediation import RemediationTask
from app.schemas.finding import (
    AIAnalysisOut, FindingDetail, FindingOut, FindingStatusUpdate,
    RemediationIn, RemediationOut, ValidationTaskOut,
)
from app.services.audit_service import audit

router = APIRouter(prefix="/findings", tags=["findings"])


@router.get("", response_model=dict)
def list_findings(
    assessment_id: int,
    db: DbDep,
    user: CurrentUser,
    severity: str | None = None,
    status: str | None = None,
    search: str | None = None,
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=200),
):
    q = db.query(Finding).filter(Finding.assessment_id == assessment_id)
    if severity:
        q = q.filter(Finding.severity == severity)
    if status:
        q = q.filter(Finding.status == status)
    if search:
        like = f"%{search}%"
        q = q.filter((Finding.title.like(like)) | (Finding.cve.like(like)) | (Finding.description.like(like)))
    total = q.count()
    items = q.order_by(Finding.risk_score.desc()).offset((page - 1) * page_size).limit(page_size).all()
    return {
        "items": [FindingOut.model_validate(i) for i in items],
        "total": total, "page": page, "page_size": page_size,
    }


@router.get("/{finding_id}", response_model=FindingDetail)
def get_finding(finding_id: int, db: DbDep, user: CurrentUser):
    f = db.get(Finding, finding_id)
    if not f:
        raise HTTPException(status_code=404, detail="Finding not found.")
    detail = FindingDetail.model_validate(f)
    detail.evidence = [{"id": e.id, "category": e.category, "filename": e.filename, "sha256": e.sha256,
                        "source": e.source, "captured_at": e.captured_at, "immutable": e.immutable,
                        "content": (e.content or "")[:4000]} for e in f.evidence]
    detail.mitre_techniques = [{"technique_id": t.technique_id, "name": t.name, "tactic": t.tactic} for t in (f.mitre_techniques or [])]
    detail.ai_priority = (f.risk_breakdown or {}).get("ai_priority")
    return detail


@router.patch("/{finding_id}", response_model=FindingOut)
def update_finding(finding_id: int, payload: FindingStatusUpdate, db: DbDep, user: RequirePermission("manage_findings")):
    f = db.get(Finding, finding_id)
    if not f:
        raise HTTPException(status_code=404, detail="Finding not found.")
    f.status = payload.status
    db.add(f)
    db.commit()
    db.refresh(f)
    audit(db, user.id, "Finding status updated", assessment_id=f.assessment_id,
          object_type="finding", object_id=f.id, result="success", detail=payload.status)
    return f


@router.get("/{finding_id}/analyses", response_model=list[AIAnalysisOut])
def finding_analyses(finding_id: int, db: DbDep, user: CurrentUser):
    return db.query(AIAnalysis).filter(AIAnalysis.finding_id == finding_id).order_by(AIAnalysis.created_at.desc()).all()


@router.get("/{finding_id}/attack-paths", response_model=list[dict])
def finding_attack_paths(finding_id: int, db: DbDep, user: CurrentUser):
    f = db.get(Finding, finding_id)
    if not f:
        raise HTTPException(status_code=404, detail="Finding not found.")
    paths = db.query(AttackPath).filter(AttackPath.assessment_id == f.assessment_id, AttackPath.is_current.is_(True)).all()
    out = []
    for p in paths:
        present = any(n.get("id") == f"vuln:{finding_id}" for n in (p.nodes_json or []))
        if present:
            out.append({
                "id": p.id, "name": p.name, "path_length": p.path_length,
                "cumulative_risk": p.cumulative_risk, "confidence": p.confidence,
                "steps": [str(n.get("label")) for n in (p.nodes_json or [])],
            })
    return out


@router.post("/{finding_id}/remediation", response_model=RemediationOut, status_code=201)
def create_remediation(finding_id: int, payload: RemediationIn, db: DbDep, user: RequirePermission("manage_remediation")):
    f = db.get(Finding, finding_id)
    if not f:
        raise HTTPException(status_code=404, detail="Finding not found.")
    existing = db.query(RemediationTask).filter(RemediationTask.finding_id == finding_id).first()
    if existing:
        raise HTTPException(status_code=409, detail="Remediation task already exists for this finding.")
    task = RemediationTask(
        finding_id=finding_id, assessment_id=f.assessment_id,
        remediation_plan=payload.plan, assignee_name=payload.assigned_to_name,
        deadline=payload.deadline, retest_before_score=f.risk_score,
        status="open",
    )
    db.add(task)
    db.commit()
    db.refresh(task)
    f.status = "acknowledged"
    db.add(f)
    db.commit()
    audit(db, user.id, "Remediation task created", assessment_id=f.assessment_id,
          object_type="finding", object_id=finding_id, result="success")
    return task


@router.get("/{finding_id}/validation-tasks", response_model=list[ValidationTaskOut])
def validation_tasks(finding_id: int, db: DbDep, user: CurrentUser):
    from app.models.validation import ValidationTask
    return db.query(ValidationTask).filter(ValidationTask.finding_id == finding_id).order_by(ValidationTask.created_at.desc()).all()