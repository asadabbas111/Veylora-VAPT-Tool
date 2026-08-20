from datetime import datetime
from typing import TYPE_CHECKING

from sqlalchemy import JSON, DateTime, Float, ForeignKey, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database import Base

if TYPE_CHECKING:
    from app.models.finding import Finding
    from app.models.validation import ValidationResult


class ValidationTask(Base):
    __tablename__ = "validation_tasks"

    id: Mapped[int] = mapped_column(primary_key=True)
    assessment_id: Mapped[int] = mapped_column(ForeignKey("assessments.id", ondelete="CASCADE"), index=True)
    finding_id: Mapped[int] = mapped_column(ForeignKey("findings.id", ondelete="CASCADE"), index=True)
    level: Mapped[int] = mapped_column(Integer, default=1)  # 0 passive, 1 nondestructive, 2 controlled poc, 3 advanced
    status: Mapped[str] = mapped_column(String(30), default="pending")  # pending|approved|running|paused|stopped|cancelled|completed|failed|blocked
    requested_by: Mapped[int] = mapped_column(ForeignKey("users.id"))
    approved_by: Mapped[int | None] = mapped_column(ForeignKey("users.id"), nullable=True)
    approved_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=datetime.utcnow)  # noqa: F821
    verdict: Mapped[str | None] = mapped_column(String(30), nullable=True)  # confirmed|refuted|inconclusive|not_executed
    notes: Mapped[str | None] = mapped_column(Text, nullable=True)


class ValidationResult(Base):
    __tablename__ = "validation_results"

    id: Mapped[int] = mapped_column(primary_key=True)
    validation_task_id: Mapped[int] = mapped_column(ForeignKey("validation_tasks.id", ondelete="CASCADE"), index=True)
    finding_id: Mapped[int] = mapped_column(ForeignKey("findings.id", ondelete="CASCADE"), index=True)
    verdict: Mapped[str] = mapped_column(String(30))
    confidence: Mapped[float] = mapped_column(Float, default=50.0)
    output: Mapped[Text | None] = mapped_column(Text, nullable=True)
    evidence_refs: Mapped[list] = mapped_column(JSON, default=list)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=datetime.utcnow)

    finding: Mapped["Finding"] = relationship(back_populates="validation_results")