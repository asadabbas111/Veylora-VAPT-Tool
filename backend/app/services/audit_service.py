from sqlalchemy.orm import Session

from app.models.audit import AuditLog


def audit(
    db: Session,
    user_id: int | None,
    action: str,
    assessment_id: int | None = None,
    object_type: str | None = None,
    object_id: int | None = None,
    result: str | None = None,
    detail: str | None = None,
    ip_address: str | None = None,
    commit: bool = True,
) -> AuditLog:
    entry = AuditLog(
        user_id=user_id,
        action=action,
        assessment_id=assessment_id,
        object_type=object_type,
        object_id=object_id,
        result=result,
        detail=detail,
        ip_address=ip_address,
    )
    db.add(entry)
    if commit:
        db.commit()
        db.refresh(entry)
    return entry