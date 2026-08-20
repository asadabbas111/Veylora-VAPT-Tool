from fastapi import APIRouter, HTTPException



from app.deps import CurrentUser, DbDep, require_permission, RequirePermission
from app.models.asset import Asset
from app.models.finding import Finding
from app.models.remediation import RemediationTask
from app.schemas.finding import RemediationOut
from app.services.audit_service import audit
from app.risk.engine import calculate_risk

router = APIRouter(prefix="/remediation", tags=["remediation"])


@router.get("", response_model=list[RemediationOut])
def list_tasks(assessment_id: int, db: DbDep, user: CurrentUser, status: str | None = None):
    q = db.query(RemediationTask).filter(RemediationTask.assessment_id == assessment_id)
    if status:
        q = q.filter(RemediationTask.status == status)
    return q.order_by(RemediationTask.created_at.desc()).all()


@router.get("/progress")
def progress(assessment_id: int, db: DbDep, user: CurrentUser):
    tasks = db.query(RemediationTask).filter(RemediationTask.assessment_id == assessment_id).all()
    statuses: dict[str, int] = {}
    for t in tasks:
        statuses[t.status] = statuses.get(t.status, 0) + 1
    total = len(tasks)
    done = sum(1 for t in tasks if t.status in ("fixed", "verified"))
    return {
        "total": total, "done": done,
        "progress": round(done / total * 100, 1) if total else 0.0,
        "statuses": statuses,
    }


@router.post("/{task_id}/status", response_model=RemediationOut)
def update_status(task_id: int, payload: dict, db: DbDep, user: RequirePermission("manage_remediation")):
    task = db.get(RemediationTask, task_id)
    if not task:
        raise HTTPException(status_code=404, detail="Remediation task not found.")
    new_status = payload.get("status")
    valid = {"open", "acknowledged", "in_progress", "fixed", "retest_required", "verified", "false_positive", "risk_accepted"}
    if new_status not in valid:
        raise HTTPException(status_code=422, detail=f"Invalid status. Valid: {sorted(valid)}")
    task.status = new_status
    if new_status == "verified":
        task.verified_at = __import__("datetime").datetime.utcnow()
    db.add(task)
    db.commit()
    db.refresh(task)
    f = db.get(Finding, task.finding_id)
    if f:
        f.status = new_status
        db.add(f)
        db.commit()
    audit(db, user.id, "Remediation status updated", assessment_id=task.assessment_id,
          object_type="remediation_task", object_id=task.id, result="success", detail=new_status)
    return task


@router.post("/{task_id}/retest", response_model=RemediationOut)
def retest(task_id: int, db: DbDep, user: RequirePermission("manage_remediation")):
    """Authorized re-test comparing risk before vs after the fix."""
    task = db.get(RemediationTask, task_id)
    if not task:
        raise HTTPException(status_code=404, detail="Remediation task not found.")
    if task.retest_before_score is None:
        task.retest_before_score = task.finding.risk_score if task.finding else 0
    finding = db.get(Finding, task.finding_id)

    # Simulated retest: a "fixed" task verifies cleanly; otherwise re-open.
    if task.status == "fixed":
        task.retest_result = "fixed"
        task.retest_after_score = round(task.retest_before_score * 0.12, 1)
        task.status = "verified"
        if finding:
            finding.status = "verified"
            finding.risk_score = task.retest_after_score
            finding.severity = "info"
            db.add(finding)
    else:
        task.retest_result = "not_fixed"
        task.retest_after_score = task.retest_before_score
        task.status = "retest_required"
        if finding:
            finding.status = "retest_required"
            db.add(finding)
    db.add(task)
    db.commit()
    db.refresh(task)
    audit(db, user.id, "Re-test performed", assessment_id=task.assessment_id,
          object_type="remediation_task", object_id=task.id, result="success",
          detail=f"{task.retest_before_score} -> {task.retest_after_score}")
    return task