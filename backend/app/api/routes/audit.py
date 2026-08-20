from fastapi import APIRouter, HTTPException, Query



from app.deps import CurrentUser, DbDep, require_permission, RequirePermission
from app.models.audit import AuditLog

router = APIRouter(prefix="/audit", tags=["audit"])


@router.get("")
def list_logs(db: DbDep, user: RequirePermission("view_audit"),
              assessment_id: int | None = None, action: str | None = None,
              user_id: int | None = None, page: int = Query(1, ge=1), page_size: int = Query(50, ge=1, le=500)):
    q = db.query(AuditLog)
    if assessment_id:
        q = q.filter(AuditLog.assessment_id == assessment_id)
    if action:
        q = q.filter(AuditLog.action == action)
    if user_id:
        q = q.filter(AuditLog.user_id == user_id)
    total = q.count()
    items = q.order_by(AuditLog.timestamp.desc()).offset((page - 1) * page_size).limit(page_size).all()
    return {
        "items": [
            {
                "id": a.id, "user_id": a.user_id, "user": a.user.full_name if a.user else None,
                "action": a.action, "assessment_id": a.assessment_id, "object_type": a.object_type,
                "object_id": a.object_id, "result": a.result, "detail": a.detail,
                "ip_address": a.ip_address, "timestamp": a.timestamp,
            }
            for a in items
        ],
        "total": total, "page": page, "page_size": page_size,
    }