from fastapi import APIRouter, HTTPException



from app.deps import CurrentUser, DbDep, require_permission, RequirePermission
from app.models.assessment import Assessment
from app.models.finding import Finding
from app.models.validation import ValidationTask
from app.schemas.attack import ValidationApprove, ValidationRequest
from app.schemas.finding import ValidationTaskOut
from app.services.audit_service import audit
from app.tasks.manager import task_manager
from app.validators.engine import validation_engine
from app.models.job import Job

router = APIRouter(prefix="/validation", tags=["validation"])


@router.post("/request/{finding_id}", response_model=ValidationTaskOut, status_code=201)
def request_validation(finding_id: int, payload: ValidationRequest, db: DbDep, user: RequirePermission("validate")):
    f = db.get(Finding, finding_id)
    if not f:
        raise HTTPException(status_code=404, detail="Finding not found.")
    task = validation_engine.request_task(db, f, user.id, payload.level)
    db.commit()
    db.refresh(task)
    action = "scheduled for approval" if task.status == "pending" else "approved automatically"
    audit(db, user.id, "Validation requested", assessment_id=f.assessment_id,
          object_type="validation_task", object_id=task.id, result="success",
          detail=f"level {payload.level} ({action})")
    return task


@router.post("/approve/{task_id}", response_model=ValidationTaskOut)
def approve_task(task_id: int, payload: ValidationApprove, db: DbDep, user: RequirePermission("approve_validation")):
    task = db.get(ValidationTask, task_id)
    if not task:
        raise HTTPException(status_code=404, detail="Validation task not found.")
    if not payload.approve:
        task.status = "cancelled"
        task.notes = payload.notes or "Validation request rejected by approver."
        db.add(task)
        db.commit()
        db.refresh(task)
        audit(db, user.id, "Validation request rejected", assessment_id=task.assessment_id,
              object_type="validation_task", object_id=task.id, result="blocked")
        return task
    validation_engine.approve(db, task, user.id)
    db.commit()
    db.refresh(task)
    audit(db, user.id, "Validation approved", assessment_id=task.assessment_id,
          object_type="validation_task", object_id=task.id, result="success")
    return task


@router.post("/run/{task_id}", status_code=202)
def run_task(task_id: int, db: DbDep, user: RequirePermission("validate")):
    task = db.get(ValidationTask, task_id)
    if not task:
        raise HTTPException(status_code=404, detail="Validation task not found.")
    if task.status not in ("approved", "pending"):
        raise HTTPException(status_code=400, detail=f"Task not runnable (status: {task.status}).")
    if task.status == "pending":
        raise HTTPException(status_code=403, detail="Task requires approval before running.")

    def _run(job_id, task_id=task_id, _job_id=None, _job_log=None, _job_is_stopped=None):
        from app.database import SessionLocal

        db2 = SessionLocal()
        try:
            t = db2.get(ValidationTask, task_id)
            validation_engine.run(
                db2, t,
                is_stopped=lambda: bool(_job_is_stopped and _job_is_stopped()),
                log=lambda m: None,
            )
            db2.commit()
        finally:
            db2.close()
        return {"task_id": task_id}

    job = Job(assessment_id=task.assessment_id, task_type="validation", status="pending", started_by=user.id,
              params_json={"validation_task_id": task_id})
    db.add(job)
    db.commit()
    db.refresh(job)
    task_manager.submit(job.id, _run, task_id)
    audit(db, user.id, "Validation started", assessment_id=task.assessment_id,
          object_type="validation_task", object_id=task.id, result="success")
    return {"job_id": job.id, "message": f"Validation started for task {task_id}"}


@router.post("/stop/{task_id}", status_code=202)
def stop_task(task_id: int, db: DbDep, user: RequirePermission("validate")):
    job = db.query(Job).filter(Job.assessment_id == task_id, Job.task_type == "validation").first()
    if job:
        task_manager.stop(job.id)
    task = db.get(ValidationTask, task_id)
    if task:
        task.status = "stopped"
        db.add(task)
        db.commit()
    audit(db, user.id, "Validation stopped", result="success")
    return {"message": "Validation stopped"}


@router.post("/stop-all", status_code=202)
def stop_all_validation(db: DbDep, user: RequirePermission("approve_validation")):
    jobs = db.query(Job).filter(Job.task_type == "validation", Job.status.in_(["pending", "running"])).all()
    for j in jobs:
        task_manager.stop(j.id)
    db.query(ValidationTask).filter(ValidationTask.status.in_(["pending", "running"])).update({"status": "stopped"})
    db.commit()
    audit(db, user.id, "All validation stopped", result="success")
    return {"message": "All validation tasks stopped"}


@router.get("/tasks", response_model=list[ValidationTaskOut])
def list_tasks(assessment_id: int, db: DbDep, user: CurrentUser, status: str | None = None):
    q = db.query(ValidationTask).filter(ValidationTask.assessment_id == assessment_id)
    if status:
        q = q.filter(ValidationTask.status == status)
    return q.order_by(ValidationTask.created_at.desc()).all()