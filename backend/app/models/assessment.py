from datetime import date, datetime
from typing import TYPE_CHECKING

from sqlalchemy import JSON, Date, DateTime, ForeignKey, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database import Base

if TYPE_CHECKING:
    from app.models.asset import Asset
    from app.models.user import User


class Assessment(Base):
    __tablename__ = "assessments"

    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(200), index=True)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    client_name: Mapped[str | None] = mapped_column(String(200), nullable=True)
    assessment_type: Mapped[str] = mapped_column(String(40), default="vulnerability_assessment")
    start_date: Mapped[date] = mapped_column(Date)
    end_date: Mapped[date | None] = mapped_column(Date, nullable=True)
    rules_of_engagement: Mapped[str | None] = mapped_column(Text, nullable=True)
    validation_level: Mapped[int] = mapped_column(default=1)
    status: Mapped[str] = mapped_column(String(30), default="draft", index=True)  # draft|scoping|running|paused|completed|cancelled
    progress: Mapped[float] = mapped_column(default=0.0)  # 0..100
    stage: Mapped[str] = mapped_column(String(50), default="created")  # current workflow stage
    stage_log: Mapped[dict] = mapped_column(JSON, default=dict)  # {stage: {status, started_at, ...}}
    owner_id: Mapped[int] = mapped_column(ForeignKey("users.id"), index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=datetime.utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=datetime.utcnow, onupdate=datetime.utcnow)

    owner: Mapped["User"] = relationship(back_populates="assessments")
    scopes: Mapped[list["AssessmentScope"]] = relationship(back_populates="assessment", cascade="all, delete-orphan")  # noqa: F821
    assets: Mapped[list["Asset"]] = relationship(back_populates="assessment", cascade="all, delete-orphan")

    def __repr__(self) -> str:
        return f"<Assessment {self.name} [{self.status}]>"


class AssessmentScope(Base):
    __tablename__ = "assessment_scopes"

    id: Mapped[int] = mapped_column(primary_key=True)
    assessment_id: Mapped[int] = mapped_column(ForeignKey("assessments.id", ondelete="CASCADE"), index=True)
    target: Mapped[str] = mapped_column(String(255))  # IP, CIDR, hostname, domain, URL, range
    target_type: Mapped[str] = mapped_column(String(20))  # ipv4|ipv6|cidr|hostname|domain|url|range
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_by: Mapped[int] = mapped_column(ForeignKey("users.id"))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=datetime.utcnow)

    assessment: Mapped[Assessment] = relationship(back_populates="scopes")


class AssessmentTarget(Base):
    """Explicit target inside the authorized scope. Subject to scope validation."""

    __tablename__ = "assessment_targets"

    id: Mapped[int] = mapped_column(primary_key=True)
    assessment_id: Mapped[int] = mapped_column(ForeignKey("assessments.id", ondelete="CASCADE"), index=True)
    target: Mapped[str] = mapped_column(String(255))
    target_type: Mapped[str] = mapped_column(String(20))
    in_scope: Mapped[bool] = mapped_column(default=False)
    validation_note: Mapped[str | None] = mapped_column(Text, nullable=True)
    added_by: Mapped[int] = mapped_column(ForeignKey("users.id"))
    added_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=datetime.utcnow)