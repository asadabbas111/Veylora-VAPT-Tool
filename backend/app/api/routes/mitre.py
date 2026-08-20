from fastapi import APIRouter, HTTPException

from app.deps import CurrentUser, DbDep
from app.models.finding import Finding
from app.services.mitre_service import coverage_stats, map_finding, seed_techniques

router = APIRouter(prefix="/mitre", tags=["mitre"])


@router.get("/coverage")
def coverage(assessment_id: int, db: DbDep, user: CurrentUser):
    seed_techniques(db)
    db.commit()
    return coverage_stats(db, assessment_id)


@router.get("/findings/{finding_id}")
def finding_mitre(finding_id: int, db: DbDep, user: CurrentUser):
    f = db.get(Finding, finding_id)
    if not f:
        raise HTTPException(status_code=404, detail="Finding not found.")
    map_finding(db, f)
    db.commit()
    return [{"technique_id": t.technique_id, "name": t.name, "tactic": t.tactic} for t in f.mitre_techniques or []]