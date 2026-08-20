from fastapi import APIRouter, HTTPException, Query
from sqlalchemy.orm import Session


from sqlalchemy.orm import Session

from app.deps import CurrentUser, DbDep, require_permission, RequirePermission
from app.models.assessment import Assessment, AssessmentScope, AssessmentTarget
from app.models.job import Job
from app.schemas.assessment import (
    AssessmentCreate, AssessmentDetail, AssessmentOut, AssessmentUpdate,
    JobOut, ScopeIn, ScopeOut, TargetIn, TargetOut, WorkflowStart,
)
from app.services.audit_service import audit
from app.services.scope_service import classify_target, validate_target_against_scopes
from app.tasks.manager import task_manager
from app.tasks.pipeline import PIPELINE_STAGES, run_full_workflow

router = APIRouter(prefix="/assessments", tags=["assessments"])


def _delete_assessment_rows(db: Session, assessment_id: int) -> None:
    """Delete every row that belongs to an assessment, in FK-safe order.

    Hand-rolled instead of trusting ORM cascades because several child tables
    have NOT NULL columns whose ORM relationships would otherwise be nulled by
    SQLAlchemy (e.g. findings.asset_id) before the DELETE is emitted.
    """
    from app.models.ai import AIAnalysis
    from app.models.asset import Asset, Service
    from app.models.evidence import Evidence
    from app.models.finding import Finding
    from app.models.graph import AttackPath, AttackPathEdge, AttackPathNode
    from app.models.mitre import finding_mitre
    from app.models.remediation import RemediationTask
    from app.models.validation import ValidationResult, ValidationTask

    fids = db.query(Finding.id).filter(Finding.assessment_id == assessment_id).all()
    fids = [r[0] for r in fids] or [0]

    db.query(finding_mitre).filter(finding_mitre.c.finding_id.in_(fids)).delete(synchronize_session=False)
    from app.models.audit import AuditLog

    db.query(AuditLog).filter(AuditLog.assessment_id == assessment_id).update(
        {AuditLog.assessment_id: None}, synchronize_session=False
    )  # append-only logs are kept, only the FK reference is released
    db.query(AIAnalysis).filter(AIAnalysis.finding_id.in_(fids)).delete(synchronize_session=False)
    db.query(ValidationResult).filter(ValidationResult.finding_id.in_(fids)).delete(synchronize_session=False)
    db.query(RemediationTask).filter(RemediationTask.assessment_id == assessment_id).delete(synchronize_session=False)
    db.query(Evidence).filter(Evidence.assessment_id == assessment_id).delete(synchronize_session=False)
    db.query(ValidationTask).filter(ValidationTask.assessment_id == assessment_id).delete(synchronize_session=False)
    db.query(Finding).filter(Finding.assessment_id == assessment_id).delete(synchronize_session=False)

    path_ids = db.query(AttackPath.id).filter(AttackPath.assessment_id == assessment_id).all()
    path_ids = [r[0] for r in path_ids] or [0]
    db.query(AttackPathNode).filter(AttackPathNode.path_id.in_(path_ids)).delete(synchronize_session=False)
    db.query(AttackPathEdge).filter(AttackPathEdge.path_id.in_(path_ids)).delete(synchronize_session=False)
    db.query(AttackPath).filter(AttackPath.assessment_id == assessment_id).delete(synchronize_session=False)

    db.query(Job).filter(Job.assessment_id == assessment_id).delete(synchronize_session=False)
    from app.models.report import ReportRecord

    db.query(ReportRecord).filter(ReportRecord.assessment_id == assessment_id).delete(synchronize_session=False)
    db.query(Service).filter(Service.asset_id.in_(
        db.query(Asset.id).filter(Asset.assessment_id == assessment_id)
    )).delete(synchronize_session=False)
    db.query(Asset).filter(Asset.assessment_id == assessment_id).delete(synchronize_session=False)
    db.query(AssessmentScope).filter(AssessmentScope.assessment_id == assessment_id).delete(synchronize_session=False)
    db.query(AssessmentTarget).filter(AssessmentTarget.assessment_id == assessment_id).delete(synchronize_session=False)
    db.query(Assessment).filter(Assessment.id == assessment_id).delete(synchronize_session=False)

_STAGE_TO_JOB = {
    "asset_discovery": PIPELINE_STAGES["asset_discovery"],
    "vulnerability_scan": PIPELINE_STAGES["vulnerability_scan"],
    "risk_calculation": PIPELINE_STAGES["risk_calculation"],
    "attack_path_analysis": PIPELINE_STAGES["attack_path_analysis"],
    "ai_analysis": PIPELINE_STAGES["ai_analysis"],
    "report_generation": PIPELINE_STAGES["report_generation"],
    "full": run_full_workflow,
}


@router.post("", response_model=AssessmentOut, status_code=201)
def create_assessment(payload: AssessmentCreate, db: DbDep, user: RequirePermission("create_assessment")):
    if len(payload.name) < 2:
        raise HTTPException(status_code=422, detail="Assessment name is too short.")
    assessment = Assessment(
        name=payload.name,
        description=payload.description,
        client_name=payload.client_name,
        assessment_type=payload.assessment_type,
        start_date=payload.start_date,
        end_date=payload.end_date,
        rules_of_engagement=payload.rules_of_engagement,
        validation_level=payload.validation_level or 1,
        owner_id=user.id,
        status="draft",
        stage="created",
        stage_log={},
    )
    db.add(assessment)
    db.commit()
    db.refresh(assessment)
    audit(db, user.id, "Assessment created", assessment_id=assessment.id,
          object_type="assessment", object_id=assessment.id, result="success")
    return assessment


@router.get("", response_model=list[AssessmentOut])
def list_assessments(db: DbDep, user: CurrentUser):
    q = db.query(Assessment).order_by(Assessment.created_at.desc())
    if user.role == "viewer":
        q = q.filter(Assessment.owner_id == user.id)
    return q.all()


@router.get("/{assessment_id}", response_model=AssessmentDetail)
def get_assessment(assessment_id: int, db: DbDep, user: CurrentUser):
    a = db.get(Assessment, assessment_id)
    if not a:
        raise HTTPException(status_code=404, detail="Assessment not found.")
    detail = AssessmentDetail.model_validate(a)
    detail.scopes = [ScopeOut.model_validate(s) for s in a.scopes]
    detail.targets = [TargetOut.model_validate(t) for t in db.query(AssessmentTarget).filter(AssessmentTarget.assessment_id == assessment_id).all()]
    return detail


@router.patch("/{assessment_id}", response_model=AssessmentOut)
def update_assessment(assessment_id: int, payload: AssessmentUpdate, db: DbDep, user: RequirePermission("edit_assessment")):
    a = db.get(Assessment, assessment_id)
    if not a:
        raise HTTPException(status_code=404, detail="Assessment not found.")
    for field, value in payload.model_dump(exclude_unset=True).items():
        if value is not None:
            setattr(a, field, value)
    db.add(a)
    db.commit()
    db.refresh(a)
    audit(db, user.id, "Assessment updated", assessment_id=assessment_id, result="success")
    return a


@router.delete("/{assessment_id}", status_code=204)
def delete_assessment(assessment_id: int, db: DbDep, user: RequirePermission("edit_assessment")):
    a = db.get(Assessment, assessment_id)
    if not a:
        raise HTTPException(status_code=404, detail="Assessment not found.")
    db.delete(a)
    db.commit()
    audit(db, user.id, "Assessment deleted", assessment_id=assessment_id, result="success")


@router.post("/{assessment_id}/scopes", response_model=ScopeOut, status_code=201)
def add_scope(assessment_id: int, payload: ScopeIn, db: DbDep, user: RequirePermission("edit_assessment")):
    a = db.get(Assessment, assessment_id)
    if not a:
        raise HTTPException(status_code=404, detail="Assessment not found.")
    target_type = payload.target_type or classify_target(payload.target)
    existing = db.query(AssessmentScope).filter(
        AssessmentScope.assessment_id == assessment_id, AssessmentScope.target == payload.target
    ).first()
    if existing:
        raise HTTPException(status_code=409, detail="Scope entry already exists.")
    scope = AssessmentScope(
        assessment_id=assessment_id, target=payload.target, target_type=target_type,
        description=payload.description, created_by=user.id,
    )
    db.add(scope)
    db.commit()
    db.refresh(scope)
    audit(db, user.id, "Scope added", assessment_id=assessment_id, object_type="scope", object_id=scope.id, result="success", detail=payload.target)
    return scope


@router.get("/{assessment_id}/scopes", response_model=list[ScopeOut])
def list_scopes(assessment_id: int, db: DbDep, user: CurrentUser):
    return db.query(AssessmentScope).filter(AssessmentScope.assessment_id == assessment_id).all()


@router.post("/{assessment_id}/scope-check")
def scope_check(assessment_id: int, payload: TargetIn, db: DbDep, user: CurrentUser):
    """Server-side scope validation BEFORE any target runs."""
    a = db.get(Assessment, assessment_id)
    if not a:
        raise HTTPException(status_code=404, detail="Assessment not found.")
    scopes = db.query(AssessmentScope).filter(AssessmentScope.assessment_id == assessment_id).all()
    if not scopes:
        raise HTTPException(status_code=400, detail="No authorized scope defined yet.")
    result = validate_target_against_scopes(payload.target, scopes)
    return {"target": result.target, "target_type": result.target_type, "in_scope": result.in_scope,
            "matched_scope": result.matched_scope, "reason": result.reason}


@router.post("/{assessment_id}/targets", response_model=TargetOut, status_code=201)
def add_target(assessment_id: int, payload: TargetIn, db: DbDep, user: RequirePermission("edit_assessment")):
    """Registers a target. Performs mandatory server-side scope validation and
    blocks targets outside the authorized assessment scope."""
    a = db.get(Assessment, assessment_id)
    if not a:
        raise HTTPException(status_code=404, detail="Assessment not found.")
    scopes = db.query(AssessmentScope).filter(AssessmentScope.assessment_id == assessment_id).all()
    if not scopes:
        raise HTTPException(status_code=400, detail="No authorized scope defined yet. Add a scope first.")

    target_type = payload.target_type or classify_target(payload.target)
    check = validate_target_against_scopes(payload.target, scopes)
    if not check.in_scope:
        audit(db, user.id, "Target blocked (out of scope)", assessment_id=assessment_id,
              object_type="target", result="blocked", detail=f"{payload.target}: {check.reason}")
        raise HTTPException(status_code=403, detail=f"BLOCKED: {check.reason}")

    target = AssessmentTarget(
        assessment_id=assessment_id, target=payload.target, target_type=target_type,
        in_scope=True, validation_note=check.reason, added_by=user.id,
    )
    db.add(target)
    db.commit()
    db.refresh(target)
    audit(db, user.id, "Target added (in scope)", assessment_id=assessment_id,
          object_type="target", object_id=target.id, result="success", detail=payload.target)
    return target


@router.get("/{assessment_id}/targets", response_model=list[TargetOut])
def list_targets(assessment_id: int, db: DbDep, user: CurrentUser):
    return db.query(AssessmentTarget).filter(AssessmentTarget.assessment_id == assessment_id).all()


@router.get("/{assessment_id}/jobs", response_model=list[JobOut])
def list_jobs(assessment_id: int, db: DbDep, user: CurrentUser):
    return db.query(Job).filter(Job.assessment_id == assessment_id).order_by(Job.created_at.desc()).all()


@router.post("/{assessment_id}/workflow", status_code=202)
def start_workflow(assessment_id: int, payload: WorkflowStart, db: DbDep, user: RequirePermission("run_scan")):
    """Start a workflow stage (or the full workflow) as a background job."""
    a = db.get(Assessment, assessment_id)
    if not a:
        raise HTTPException(status_code=404, detail="Assessment not found.")
    scopes = db.query(AssessmentScope).filter(AssessmentScope.assessment_id == assessment_id).count()
    if scopes == 0:
        raise HTTPException(status_code=400, detail="Define an authorized scope before running a workflow.")
    if a.status == "cancelled":
        raise HTTPException(status_code=400, detail="Assessment is cancelled.")

    in_scope_targets = db.query(AssessmentTarget).filter(AssessmentTarget.assessment_id == assessment_id, AssessmentTarget.in_scope.is_(True)).count()
    if payload.stage in ("full", "asset_discovery", "vulnerability_scan") and in_scope_targets == 0:
        raise HTTPException(status_code=400, detail="Add at least one in-scope target before scanning.")

    job = Job(assessment_id=assessment_id, task_type=payload.stage, status="pending", started_by=user.id,
              params_json={"stage": payload.stage, "adapters": payload.adapters or []})
    db.add(job)
    db.commit()
    db.refresh(job)

    if a.status == "draft":
        a.status = "running"
        db.add(a)
        db.commit()

    if payload.stage == "vulnerability_scan":
        from app.scanners.engine import scan_engine
        enabled = [x for x in (payload.adapters or []) if x in scan_engine.adapters]
        if enabled:
            # preserve user-selected adapters via params
            job.params_json = {**job.params_json, "adapters": enabled}
    db.add(job)
    db.commit()

    task_manager.submit(job.id, _STAGE_TO_JOB[payload.stage], assessment_id)
    audit(db, user.id, "Workflow started", assessment_id=assessment_id,
          object_type="job", object_id=job.id, result="success", detail=payload.stage)
    return {"job_id": job.id, "stage": payload.stage, "status": "started"}


@router.post("/{assessment_id}/pause", status_code=202)
def pause_assessment(assessment_id: int, db: DbDep, user: RequirePermission("run_scan")):
    jobs = db.query(Job).filter(Job.assessment_id == assessment_id, Job.status.in_(["pending", "running"])).all()
    for j in jobs:
        task_manager.pause(j.id)
        j.status = "paused"
    a = db.get(Assessment, assessment_id)
    if a:
        a.status = "paused"
        db.add(a)
    db.commit()
    audit(db, user.id, "Assessment paused", assessment_id=assessment_id, result="success")
    return {"message": "Assessment paused"}


@router.post("/{assessment_id}/resume", status_code=202)
def resume_assessment(assessment_id: int, db: DbDep, user: RequirePermission("run_scan")):
    jobs = db.query(Job).filter(Job.assessment_id == assessment_id, Job.status.in_(["paused"])).all()
    for j in jobs:
        task_manager.resume(j.id)
        j.status = "pending"
    a = db.get(Assessment, assessment_id)
    if a:
        a.status = "running"
        db.add(a)
    db.commit()
    audit(db, user.id, "Assessment resumed", assessment_id=assessment_id, result="success")
    return {"message": "Assessment resumed"}


@router.post("/bulk-delete", status_code=200)
def bulk_delete_assessments(payload: dict, db: DbDep, user: RequirePermission("delete_assessment")):
    """Delete several assessments at once. Expected payload: {"ids": [1, 2, ...]}."""
    ids = payload.get("ids") or []
    if not ids:
        return {"deleted": 0}
    from pathlib import Path

    from app.models.report import ReportRecord

    rows = db.query(Assessment).filter(Assessment.id.in_(ids)).all()
    for a in rows:
        for r in db.query(ReportRecord).filter(ReportRecord.assessment_id == a.id).all():
            if r.file_path:
                try:
                    Path(r.file_path).unlink(missing_ok=True)
                except OSError:
                    pass
    for a in rows:
        _delete_assessment_rows(db, a.id)
    db.commit()
    for a in rows:
        audit(db, user.id, "Assessment deleted", object_type="assessment", object_id=a.id, result="success", detail=a.name)
    return {"deleted": len(rows)}


@router.delete("/{assessment_id}", status_code=200)
def delete_assessment(assessment_id: int, db: DbDep, user: RequirePermission("delete_assessment")):
    a = db.get(Assessment, assessment_id)
    if not a:
        raise HTTPException(status_code=404, detail="Assessment not found.")
    from pathlib import Path

    from app.models.report import ReportRecord

    for r in db.query(ReportRecord).filter(ReportRecord.assessment_id == assessment_id).all():
        if r.file_path:
            try:
                Path(r.file_path).unlink(missing_ok=True)
            except OSError:
                pass
    _delete_assessment_rows(db, assessment_id)
    db.commit()
    audit(db, user.id, "Assessment deleted", object_type="assessment", object_id=assessment_id, result="success", detail=a.name)
    return {"message": "Assessment deleted"}


@router.post("/{assessment_id}/cancel", status_code=202)
def cancel_assessment(assessment_id: int, db: DbDep, user: RequirePermission("edit_assessment")):
    jobs = db.query(Job).filter(Job.assessment_id == assessment_id, Job.status.in_(["pending", "running", "paused"])).all()
    for j in jobs:
        task_manager.stop(j.id)
        j.status = "cancelled"
    a = db.get(Assessment, assessment_id)
    if a:
        a.status = "cancelled"
        db.add(a)
    db.commit()
    audit(db, user.id, "Assessment cancelled", assessment_id=assessment_id, result="success")
    return {"message": "Assessment cancelled"}


@router.get("/{assessment_id}/overview")
def assessment_overview(assessment_id: int, db: DbDep, user: CurrentUser):
    from app.models.asset import Asset
    from app.models.finding import Finding
    from app.models.graph import AttackPath
    from app.models.remediation import RemediationTask

    a = db.get(Assessment, assessment_id)
    if not a:
        raise HTTPException(status_code=404, detail="Assessment not found.")
    assets = db.query(Asset).filter(Asset.assessment_id == assessment_id).count()
    findings = db.query(Finding).filter(Finding.assessment_id == assessment_id).all()
    sev: dict[str, int] = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for f in findings:
        sev[f.severity] = sev.get(f.severity, 0) + 1
    open_f = sum(1 for f in findings if f.status in ("open", "acknowledged", "in_progress", "retest_required"))
    paths = db.query(AttackPath).filter(AttackPath.assessment_id == assessment_id, AttackPath.is_current).count()
    top_risk = max((f.risk_score for f in findings), default=0.0)
    tasks = db.query(RemediationTask).filter(RemediationTask.assessment_id == assessment_id).all()
    done = sum(1 for t in tasks if t.status in ("fixed", "verified"))
    progress = round(done / len(tasks) * 100, 1) if tasks else 0.0
    services = db.query(Asset).filter(Asset.assessment_id == assessment_id).all()
    svc_total = sum(len(s.services) for s in services)
    validated = db.query(Finding).filter(Finding.assessment_id == assessment_id, Finding.confidence >= 80).count()
    return {
        "assessment": AssessmentOut.model_validate(a),
        "assets": assets,
        "services": svc_total,
        "findings": len(findings),
        "severity": sev,
        "open_findings": open_f,
        "attack_paths": paths,
        "max_risk": round(top_risk, 1),
        "remediation_progress": progress,
        "validated_findings": validated,
    }