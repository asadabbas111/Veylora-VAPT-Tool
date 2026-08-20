from fastapi import APIRouter, HTTPException, Query
from sqlalchemy.orm import Session


from sqlalchemy.orm import Session

from app.deps import CurrentUser, DbDep, require_permission, RequirePermission
from app.models.asset import Asset, Service
from app.models.finding import Finding
from app.schemas.asset import AssetDetail, AssetOut, AssetUpdate, ServiceOut
from app.schemas.finding import FindingOut
from app.services.audit_service import audit

router = APIRouter(prefix="/assets", tags=["assets"])


@router.get("", response_model=list[AssetDetail])
def list_assets(assessment_id: int, db: DbDep, user: CurrentUser, search: str | None = None):
    q = db.query(Asset).filter(Asset.assessment_id == assessment_id)
    if search:
        like = f"%{search}%"
        q = q.filter((Asset.ip_address.like(like)) | (Asset.hostname.like(like)) | (Asset.os_name.like(like)))
    return q.order_by(Asset.risk_score.desc()).all()


@router.get("/{asset_id}", response_model=AssetDetail)
def get_asset(asset_id: int, db: DbDep, user: CurrentUser):
    a = db.get(Asset, asset_id)
    if not a:
        raise HTTPException(status_code=404, detail="Asset not found.")
    return a


@router.patch("/{asset_id}", response_model=AssetOut)
def update_asset(asset_id: int, payload: AssetUpdate, db: DbDep, user: RequirePermission("manage_assets")):
    a = db.get(Asset, asset_id)
    if not a:
        raise HTTPException(status_code=404, detail="Asset not found.")
    for field, value in payload.model_dump(exclude_unset=True).items():
        if value is not None:
            setattr(a, field, value)
    db.add(a)
    db.commit()
    db.refresh(a)
    audit(db, user.id, "Asset updated", assessment_id=a.assessment_id, object_type="asset", object_id=a.id, result="success")
    return a


@router.get("/{asset_id}/services", response_model=list[ServiceOut])
def list_services(asset_id: int, db: DbDep, user: CurrentUser):
    return db.query(Service).filter(Service.asset_id == asset_id).all()


@router.get("/{asset_id}/findings", response_model=list[FindingOut])
def asset_findings(asset_id: int, db: DbDep, user: CurrentUser, severity: str | None = None):
    q = db.query(Finding).filter(Finding.asset_id == asset_id)
    if severity:
        q = q.filter(Finding.severity == severity)
    return q.order_by(Finding.risk_score.desc()).all()


@router.get("/services/{service_id}", response_model=dict)
def get_service(service_id: int, db: DbDep, user: CurrentUser):
    s = db.get(Service, service_id)
    if not s:
        raise HTTPException(status_code=404, detail="Service not found.")
    findings = db.query(Finding).filter(Finding.service_id == service_id).all()
    return {
        "id": s.id, "port": s.port, "protocol": s.protocol, "service_name": s.service_name,
        "version": s.version, "product": s.product, "risk_score": s.risk_score,
        "findings": [FindingOut.model_validate(f) for f in findings],
    }