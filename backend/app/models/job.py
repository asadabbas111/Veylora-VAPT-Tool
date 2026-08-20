from datetime import datetime

from sqlalchemy import DateTime, ForeignKey, JSON, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from app.database import Base


class Job(Base):
    """Long-running background job record (asset discovery, scans, etc.)."""

    __tablename__ = "jobs"

    id: Mapped[int] = mapped_column(primary_key=True)
    assessment_id: Mapped[int | None] = mapped_column(ForeignKey("assessments.id", ondelete="CASCADE"), nullable=True, index=True)
    task_type: Mapped[str] = mapped_column(String(60), index=True)  # asset_discovery|vulnerability_scan|...
    status: Mapped[str] = mapped_column(String(20), default="pending", index=True)  # pending|running|paused|completed|failed|cancelled|stopped
    progress: Mapped[float] = mapped_column(default=0.0)  # 0..100
    log: Mapped[Text] = mapped_column(Text, default="")
    error: Mapped[str | None] = mapped_column(Text, nullable=True)
    params_json: Mapped[dict] = mapped_column(JSON, default=dict)
    result_json: Mapped[dict] = mapped_column(JSON, default=dict)
    started_by: Mapped[int | None] = mapped_column(ForeignKey("users.id"), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=datetime.utcnow)
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)