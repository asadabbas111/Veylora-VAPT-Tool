from datetime import datetime
from typing import TYPE_CHECKING

from sqlalchemy import JSON, DateTime, Float, ForeignKey, Integer, String
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database import Base

if TYPE_CHECKING:
    from app.models.assessment import Assessment
    from app.models.finding import Finding


class Asset(Base):
    __tablename__ = "assets"

    id: Mapped[int] = mapped_column(primary_key=True)
    assessment_id: Mapped[int] = mapped_column(ForeignKey("assessments.id", ondelete="CASCADE"), index=True)
    ip_address: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)
    ip_version: Mapped[str] = mapped_column(String(4), default="4")
    hostname: Mapped[str | None] = mapped_column(String(255), nullable=True, index=True)
    mac_address: Mapped[str | None] = mapped_column(String(32), nullable=True)
    os_name: Mapped[str | None] = mapped_column(String(120), nullable=True)
    os_version: Mapped[str | None] = mapped_column(String(120), nullable=True)
    criticality: Mapped[float] = mapped_column(Float, default=1.0)  # 0..10
    risk_score: Mapped[float] = mapped_column(Float, default=0.0)  # 0..100
    last_seen: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    metadata_json: Mapped[dict] = mapped_column(JSON, default=dict)
    first_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=datetime.utcnow)

    assessment: Mapped["Assessment"] = relationship(back_populates="assets")
    services: Mapped[list["Service"]] = relationship(back_populates="asset", cascade="all, delete-orphan")  # noqa: F821
    findings: Mapped[list["Finding"]] = relationship(back_populates="asset")  # noqa: F821


class Service(Base):
    __tablename__ = "services"

    id: Mapped[int] = mapped_column(primary_key=True)
    asset_id: Mapped[int] = mapped_column(ForeignKey("assets.id", ondelete="CASCADE"), index=True)
    port: Mapped[int] = mapped_column(Integer)
    protocol: Mapped[str] = mapped_column(String(10), default="tcp")
    service_name: Mapped[str | None] = mapped_column(String(80), nullable=True, index=True)
    version: Mapped[str | None] = mapped_column(String(120), nullable=True)
    product: Mapped[str | None] = mapped_column(String(120), nullable=True)
    risk_score: Mapped[float] = mapped_column(Float, default=0.0)
    metadata_json: Mapped[dict] = mapped_column(JSON, default=dict)
    state: Mapped[str] = mapped_column(String(20), default="open")

    asset: Mapped["Asset"] = relationship(back_populates="services")
    findings: Mapped[list["Finding"]] = relationship(back_populates="service")  # noqa: F821