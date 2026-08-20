from datetime import datetime
from typing import TYPE_CHECKING

from sqlalchemy import JSON, Boolean, DateTime, Float, ForeignKey, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database import Base

if TYPE_CHECKING:
    from app.models.finding import Finding


class AIAnalysis(Base):
    __tablename__ = "ai_analyses"

    id: Mapped[int] = mapped_column(primary_key=True)
    finding_id: Mapped[int] = mapped_column(ForeignKey("findings.id", ondelete="CASCADE"), index=True)
    assessment_id: Mapped[int] = mapped_column(ForeignKey("assessments.id", ondelete="CASCADE"), index=True)
    analysis_type: Mapped[str] = mapped_column(String(30), default="finding_analysis")  # finding_analysis|prioritization|false_positive|executive
    provider: Mapped[str] = mapped_column(String(40), default="rule")
    model: Mapped[str | None] = mapped_column(String(80), nullable=True)
    severity: Mapped[str | None] = mapped_column(String(20), nullable=True)
    confidence: Mapped[float] = mapped_column(Float, default=50.0)
    priority: Mapped[str | None] = mapped_column(String(20), nullable=True)  # P1/P2/P3/P4
    priority_deadline: Mapped[str | None] = mapped_column(String(40), nullable=True)
    executive_summary: Mapped[Text | None] = mapped_column(Text, nullable=True)
    technical_explanation: Mapped[Text | None] = mapped_column(Text, nullable=True)
    risk_explanation: Mapped[Text | None] = mapped_column(Text, nullable=True)
    attack_path_explanation: Mapped[Text | None] = mapped_column(Text, nullable=True)
    false_positive_assessment: Mapped[Text | None] = mapped_column(Text, nullable=True)
    false_positive_likelihood: Mapped[float | None] = mapped_column(Float, nullable=True)
    recommended_remediation: Mapped[Text | None] = mapped_column(Text, nullable=True)
    basis: Mapped[list] = mapped_column(JSON, default=list)  # evidence references
    is_final: Mapped[bool] = mapped_column(Boolean, default=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=datetime.utcnow)

    finding: Mapped["Finding"] = relationship(back_populates="analyses")