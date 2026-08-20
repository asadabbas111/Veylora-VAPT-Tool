from datetime import datetime
from typing import TYPE_CHECKING

from sqlalchemy import JSON, DateTime, Float, ForeignKey, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database import Base

if TYPE_CHECKING:
    from app.models.asset import Asset, Service
    from app.models.evidence import Evidence
    from app.models.validation import ValidationResult
    from app.models.ai import AIAnalysis
    from app.models.remediation import RemediationTask


class Finding(Base):
    """Normalized vulnerability finding from any scanner source."""

    __tablename__ = "findings"

    id: Mapped[int] = mapped_column(primary_key=True)
    assessment_id: Mapped[int] = mapped_column(ForeignKey("assessments.id", ondelete="CASCADE"), index=True)
    asset_id: Mapped[int] = mapped_column(ForeignKey("assets.id", ondelete="CASCADE"), index=True)
    service_id: Mapped[int | None] = mapped_column(ForeignKey("services.id"), nullable=True)

    external_id: Mapped[str | None] = mapped_column(String(255), nullable=True)  # scanner-specific id
    title: Mapped[str] = mapped_column(String(300), index=True)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    cve: Mapped[str | None] = mapped_column(String(40), nullable=True, index=True)
    cwe: Mapped[str | None] = mapped_column(String(40), nullable=True, index=True)
    cvss_score: Mapped[float | None] = mapped_column(Float, nullable=True)
    cvss_vector: Mapped[str | None] = mapped_column(String(120), nullable=True)
    severity: Mapped[str] = mapped_column(String(20), default="info", index=True)  # critical|high|medium|low|info
    affected_service: Mapped[str | None] = mapped_column(String(80), nullable=True)
    affected_port: Mapped[int | None] = mapped_column(Integer, nullable=True)
    protocol: Mapped[str | None] = mapped_column(String(10), nullable=True)
    risk_score: Mapped[float] = mapped_column(Float, default=0.0)  # 0..100
    risk_breakdown: Mapped[dict] = mapped_column(JSON, default=dict)  # explainable breakdown
    status: Mapped[str] = mapped_column(String(30), default="open", index=True)  # open|acknowledged|in_progress|fixed|retest_required|verified|false_positive|risk_accepted
    confidence: Mapped[float] = mapped_column(Float, default=50.0)  # 0..100
    detection_source: Mapped[str | None] = mapped_column(String(80), nullable=True)  # scanner name
    remediation: Mapped[str | None] = mapped_column(Text, nullable=True)
    metadata_json: Mapped[dict] = mapped_column(JSON, default=dict)  # adapter-specific extras
    first_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=datetime.utcnow)
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=datetime.utcnow)
    fingerprint: Mapped[str | None] = mapped_column(String(128), nullable=True, index=True)  # dedup key

    asset: Mapped["Asset"] = relationship(back_populates="findings")
    service: Mapped["Service | None"] = relationship(back_populates="findings")
    evidence: Mapped[list["Evidence"]] = relationship(back_populates="finding", cascade="all, delete-orphan")  # noqa: F821
    validation_results: Mapped[list["ValidationResult"]] = relationship(back_populates="finding")  # noqa: F821
    analyses: Mapped[list["AIAnalysis"]] = relationship(back_populates="finding")  # noqa: F821
    remediation_tasks: Mapped[list["RemediationTask"]] = relationship(back_populates="finding")  # noqa: F821
    mitre_techniques: Mapped[list["MitreTechnique"]] = relationship(  # noqa: F821
        secondary="finding_mitre", back_populates="findings"
    )