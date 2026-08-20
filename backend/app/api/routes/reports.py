from fastapi import APIRouter, HTTPException
from fastapi.responses import FileResponse


from fastapi.responses import FileResponse

from app.deps import CurrentUser, DbDep, require_permission, RequirePermission
from app.models.assessment import Assessment
from app.models.report import ReportRecord
from app.reports import generator
from app.services.audit_service import audit
from app.tasks.manager import task_manager
from app.models.job import Job

router = APIRouter(prefix="/reports", tags=["reports"])


@router.get("")
def list_reports(assessment_id: int, db: DbDep, user: CurrentUser):
    reports = db.query(ReportRecord).filter(ReportRecord.assessment_id == assessment_id).order_by(ReportRecord.generated_at.desc()).all()
    return [
        {"id": r.id, "assessment_id": r.assessment_id, "report_type": r.report_type,
         "file_path": r.file_path, "file_sha256": r.file_sha256, "file_size": r.file_size,
         "generated_at": r.generated_at}
        for r in reports
    ]


@router.post("/generate/{assessment_id}", status_code=202)
def generate(assessment_id: int, db: DbDep, user: RequirePermission("generate_report"),
             report_type: str = "full"):
    a = db.get(Assessment, assessment_id)
    if not a:
        raise HTTPException(status_code=404, detail="Assessment not found.")

    from app.tasks.pipeline import stage_report_generation

    job = Job(assessment_id=assessment_id, task_type="report_generation", status="pending", started_by=user.id,
              params_json={"report_type": report_type})
    db.add(job)
    db.commit()
    db.refresh(job)
    task_manager.submit(job.id, stage_report_generation, assessment_id, report_type)
    audit(db, user.id, "Report generation requested", assessment_id=assessment_id,
          object_type="job", object_id=job.id, result="success", detail=report_type)
    return {"job_id": job.id, "message": f"Generating {report_type} report..."}


@router.get("/download/{report_id}")
def download(report_id: int, db: DbDep, user: CurrentUser):
    r = db.get(ReportRecord, report_id)
    if not r or not r.file_path:
        raise HTTPException(status_code=404, detail="Report not found.")
    import os

    if not os.path.exists(r.file_path):
        raise HTTPException(status_code=404, detail="Report file is missing on disk.")
    audit(db, user.id, "Report downloaded", assessment_id=r.assessment_id, object_type="report", object_id=report_id, result="success")
    return FileResponse(r.file_path, filename=r.file_path.split("/")[-1].split("\\")[-1])


@router.delete("/{report_id}", status_code=200)
def delete_report(report_id: int, db: DbDep, user: RequirePermission("delete_report")):
    r = db.get(ReportRecord, report_id)
    if not r:
        raise HTTPException(status_code=404, detail="Report not found.")
    import os

    if r.file_path and os.path.exists(r.file_path):
        try:
            os.remove(r.file_path)
        except OSError:
            pass
    db.delete(r)
    db.commit()
    audit(db, user.id, "Report deleted", assessment_id=r.assessment_id, object_type="report", object_id=report_id, result="success")
    return {"message": "Report deleted"}


@router.post("/bulk-delete", status_code=200)
def bulk_delete_reports(payload: dict, db: DbDep, user: RequirePermission("delete_report")):
    """Delete several reports at once. Expected payload: {"ids": [1, 2, ...]}."""
    ids = payload.get("ids") or []
    if not ids:
        return {"deleted": 0}
    rows = db.query(ReportRecord).filter(ReportRecord.id.in_(ids)).all()
    import os

    for r in rows:
        if r.file_path and os.path.exists(r.file_path):
            try:
                os.remove(r.file_path)
            except OSError:
                pass
    for r in rows:
        db.delete(r)
        audit(db, user.id, "Report deleted", assessment_id=r.assessment_id, object_type="report", object_id=r.id, result="success")
    db.commit()
    return {"deleted": len(rows)}