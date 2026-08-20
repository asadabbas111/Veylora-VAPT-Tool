from datetime import datetime
from typing import TYPE_CHECKING

from sqlalchemy import JSON, DateTime, ForeignKey, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database import Base

if TYPE_CHECKING:
    from app.models.finding import Finding


class Evidence(Base):
    """Immutable, content-addressed evidence record attached to a finding."""

    __tablename__ = "evidence"

    id: Mapped[int] = mapped_column(primary_key=True)
    assessment_id: Mapped[int] = mapped_column(ForeignKey("assessments.id", ondelete="CASCADE"), index=True)
    finding_id: Mapped[int | None] = mapped_column(ForeignKey("findings.id", ondelete="CASCADE"), nullable=True)
    category: Mapped[str] = mapped_column(String(40), default="scanner_output")  # scanner_output|http|config|validation|screenshot|log|other
    filename: Mapped[str | None] = mapped_column(String(255), nullable=True)
    content: Mapped[Text | None] = mapped_column(Text, nullable=True)
    sha256: Mapped[str] = mapped_column(String(64), index=True)
    source: Mapped[str | None] = mapped_column(String(120), nullable=True)
    metadata_json: Mapped[dict] = mapped_column(JSON, default=dict)
    captured_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=datetime.utcnow)
    immutable: Mapped[bool] = mapped_column(default=False)  # becomes True when assessment completes

    finding: Mapped["Finding | None"] = relationship(back_populates="evidence")