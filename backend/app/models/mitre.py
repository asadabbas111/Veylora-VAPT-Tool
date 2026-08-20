from datetime import datetime
from typing import TYPE_CHECKING

from sqlalchemy import DateTime, ForeignKey, String, Table, Column
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database import Base

if TYPE_CHECKING:
    from app.models.finding import Finding

finding_mitre = Table(
    "finding_mitre",
    Base.metadata,
    Column("finding_id", ForeignKey("findings.id", ondelete="CASCADE"), primary_key=True),
    Column("technique_id", ForeignKey("mitre_techniques.id", ondelete="CASCADE"), primary_key=True),
)


class MitreTechnique(Base):
    __tablename__ = "mitre_techniques"

    id: Mapped[int] = mapped_column(primary_key=True)
    technique_id: Mapped[str] = mapped_column(String(16), index=True)  # e.g. T1190
    name: Mapped[str] = mapped_column(String(200))
    tactic: Mapped[str] = mapped_column(String(80), index=True)  # Initial Access, Execution, ...
    url: Mapped[str | None] = mapped_column(String(300), nullable=True)
    findings: Mapped[list["Finding"]] = relationship(  # noqa: F821
        secondary=finding_mitre, back_populates="mitre_techniques"
    )