from datetime import date, datetime
from typing import TYPE_CHECKING

from sqlalchemy import Date, DateTime, Float, ForeignKey, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database import Base

if TYPE_CHECKING:
    from app.models.finding import Finding


class RemediationTask(Base):
    __tablename__ = "remediation_tasks"

    id: Mapped[int] = mapped_column(primary_key=True)
    finding_id: Mapped[int] = mapped_column(ForeignKey("findings.id", ondelete="CASCADE"), index=True)
    assessment_id: Mapped[int] = mapped_column(ForeignKey("assessments.id", ondelete="CASCADE"), index=True)
    status: Mapped[str] = mapped_column(String(30), default="open")  # open|acknowledged|in_progress|fixed|retest_required|verified|false_positive|risk_accepted
    assigned_to: Mapped[int | None] = mapped_column(ForeignKey("users.id"), nullable=True)
    assignee_name: Mapped[str | None] = mapped_column(String(120), nullable=True)
    deadline: Mapped[date | None] = mapped_column(Date, nullable=True)
    remediation_plan: Mapped[str | None] = mapped_column(Text, nullable=True)
    notes: Mapped[str | None] = mapped_column(Text, nullable=True)
    retest_before_score: Mapped[float | None] = mapped_column(Float, nullable=True)
    retest_after_score: Mapped[float | None] = mapped_column(Float, nullable=True)
    retest_result: Mapped[str | None] = mapped_column(String(30), nullable=True)  # fixed|partially_fixed|not_fixed|reopened
    verified_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=datetime.utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=datetime.utcnow, onupdate=datetime.utcnow)

    finding: Mapped["Finding"] = relationship(back_populates="remediation_tasks")