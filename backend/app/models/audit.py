from datetime import datetime

from sqlalchemy import DateTime, ForeignKey, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database import Base


class AuditLog(Base):
    """Append-only audit record. Rows must never be updated or deleted."""

    __tablename__ = "audit_logs"

    id: Mapped[int] = mapped_column(primary_key=True)
    user_id: Mapped[int | None] = mapped_column(ForeignKey("users.id"), nullable=True)
    action: Mapped[str] = mapped_column(String(120), index=True)
    assessment_id: Mapped[int | None] = mapped_column(ForeignKey("assessments.id"), nullable=True, index=True)
    object_type: Mapped[str | None] = mapped_column(String(60), nullable=True)
    object_id: Mapped[int | None] = mapped_column(nullable=True)
    result: Mapped[str | None] = mapped_column(String(40), nullable=True)  # success|blocked|failed
    detail: Mapped[Text | None] = mapped_column(Text, nullable=True)
    ip_address: Mapped[str | None] = mapped_column(String(64), nullable=True)
    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=datetime.utcnow, index=True)

    user: Mapped["User"] = relationship()  # noqa: F821