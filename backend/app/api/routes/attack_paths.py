from fastapi import APIRouter, HTTPException



from app.deps import CurrentUser, DbDep, require_permission, RequirePermission
from app.attack_graph.engine import build_graph, propagate_path_importance
from app.attack_graph.neo4j_adapter import neo4j_adapter
from app.models.assessment import Assessment
from app.models.graph import AttackPath
from app.schemas.attack import AttackPathOut, GraphSummaryOut
from app.services.audit_service import audit
from app.tasks.manager import task_manager
from app.models.job import Job

router = APIRouter(prefix="/attack-paths", tags=["attack-paths"])


@router.get("", response_model=list[AttackPathOut])
def list_paths(assessment_id: int, db: DbDep, user: CurrentUser):
    return db.query(AttackPath).filter(
        AttackPath.assessment_id == assessment_id, AttackPath.is_current.is_(True)
    ).order_by(AttackPath.cumulative_risk.desc()).all()


@router.get("/{path_id}", response_model=AttackPathOut)
def get_path(path_id: int, db: DbDep, user: CurrentUser):
    p = db.get(AttackPath, path_id)
    if not p:
        raise HTTPException(status_code=404, detail="Path not found.")
    return p


@router.post("/build", status_code=202)
def build(assessment_id: int, db: DbDep, user: RequirePermission("run_scan")):
    a = db.get(Assessment, assessment_id)
    if not a:
        raise HTTPException(status_code=404, detail="Assessment not found.")
    # mark existing paths as historical
    db.query(AttackPath).filter(AttackPath.assessment_id == assessment_id).update({"is_current": False})
    db.commit()

    from app.tasks.pipeline import stage_attack_paths

    job = Job(assessment_id=assessment_id, task_type="attack_path_analysis", status="pending", started_by=user.id)
    db.add(job)
    db.commit()
    db.refresh(job)
    task_manager.submit(job.id, stage_attack_paths, assessment_id)
    audit(db, user.id, "Attack-path analysis requested", assessment_id=assessment_id, object_type="job", object_id=job.id, result="success")
    return {"job_id": job.id, "message": "Attack-path rebuild started"}


@router.post("/rebuild-sync")
def rebuild_sync(assessment_id: int, db: DbDep, user: RequirePermission("run_scan")):
    """Synchronous rebuild - used by tests and CLI utilities."""
    a = db.get(Assessment, assessment_id)
    if not a:
        raise HTTPException(status_code=404, detail="Assessment not found.")
    db.query(AttackPath).filter(AttackPath.assessment_id == assessment_id).update({"is_current": False})
    db.commit()
    result = build_graph(db, a)
    propagate_path_importance(db, assessment_id)
    return {"paths": result.info.path_count, "nodes": result.info.node_count, "info": result.info.summary}


@router.get("/graph/summary", response_model=GraphSummaryOut)
def graph_summary(assessment_id: int, db: DbDep, user: CurrentUser):
    paths = db.query(AttackPath).filter(AttackPath.assessment_id == assessment_id, AttackPath.is_current.is_(True)).all()
    from app.models.asset import Asset as AssetModel
    from app.models.finding import Finding
    assets = db.query(AssetModel).filter(AssetModel.assessment_id == assessment_id).count()
    flaws = db.query(Finding).filter(Finding.assessment_id == assessment_id).count()
    return GraphSummaryOut(
        node_count=assets + flaws,
        edge_count=max(assets, flaws) * 2,
        path_count=len(paths),
        max_risk=max((p.cumulative_risk for p in paths), default=0.0),
        summary=f"{len(paths)} attack path(s) across {assets} assets and {flaws} findings",
    )


@router.get("/neo4j/health")
def neo4j_health(db: DbDep, user: CurrentUser):
    ok, msg = neo4j_adapter.health_check()
    return {"enabled": neo4j_adapter.enabled, "healthy": ok, "detail": msg}