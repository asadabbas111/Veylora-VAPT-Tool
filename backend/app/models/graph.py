from datetime import datetime

from sqlalchemy import Boolean, DateTime, Float, ForeignKey, Integer, JSON, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database import Base


class AttackPath(Base):
    __tablename__ = "attack_paths"

    id: Mapped[int] = mapped_column(primary_key=True)
    assessment_id: Mapped[int] = mapped_column(ForeignKey("assessments.id", ondelete="CASCADE"), index=True)
    name: Mapped[str] = mapped_column(String(200))
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    start_node: Mapped[str | None] = mapped_column(String(255), nullable=True)
    end_node: Mapped[str | None] = mapped_column(String(255), nullable=True)
    end_node_type: Mapped[str] = mapped_column(String(40), default="critical_asset")
    path_length: Mapped[int] = mapped_column(Integer, default=0)
    cumulative_risk: Mapped[float] = mapped_column(Float, default=0.0)  # 0..100
    confidence: Mapped[float] = mapped_column(Float, default=50.0)
    vulnerability_count: Mapped[int] = mapped_column(Integer, default=0)
    nodes_json: Mapped[list] = mapped_column(JSON, default=list)  # ordered node list
    edges_json: Mapped[list] = mapped_column(JSON, default=list)  # ordered edge list
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=datetime.utcnow)
    is_current: Mapped[bool] = mapped_column(Boolean, default=True)

    nodes: Mapped[list["AttackPathNode"]] = relationship(
        cascade="all, delete-orphan", backref="path"
    )
    edges: Mapped[list["AttackPathEdge"]] = relationship(
        cascade="all, delete-orphan", backref="path"
    )


class AttackPathNode(Base):
    __tablename__ = "attack_path_nodes"

    id: Mapped[int] = mapped_column(primary_key=True)
    path_id: Mapped[int] = mapped_column(ForeignKey("attack_paths.id", ondelete="CASCADE"), index=True)
    node_type: Mapped[str] = mapped_column(String(40))  # asset|service|vulnerability|credential|privilege|critical_asset
    label: Mapped[str] = mapped_column(String(255))
    ref_id: Mapped[int | None] = mapped_column(Integer, nullable=True)  # DB id of the referenced object
    props: Mapped[dict] = mapped_column(JSON, default=dict)
    order: Mapped[int] = mapped_column(Integer, default=0)


class AttackPathEdge(Base):
    __tablename__ = "attack_path_edges"

    id: Mapped[int] = mapped_column(primary_key=True)
    path_id: Mapped[int] = mapped_column(ForeignKey("attack_paths.id", ondelete="CASCADE"), index=True)
    rel_type: Mapped[str] = mapped_column(String(40))  # HOSTS|RUNS|AFFECTED_BY|CAN_ACCESS|LEADS_TO|HAS_PRIVILEGE|CONNECTS_TO|CONTAINS
    from_node: Mapped[str] = mapped_column(String(255))
    to_node: Mapped[str] = mapped_column(String(255))
    order: Mapped[int] = mapped_column(Integer, default=0)