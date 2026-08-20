from datetime import datetime

from sqlalchemy import Boolean, DateTime, ForeignKey, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database import Base


class User(Base):
    __tablename__ = "users"

    id: Mapped[int] = mapped_column(primary_key=True)
    full_name: Mapped[str] = mapped_column(String(120))
    email: Mapped[str] = mapped_column(String(255), unique=True, index=True)
    password_hash: Mapped[str] = mapped_column(String(255))
    role: Mapped[str] = mapped_column(String(20), default="viewer", index=True)  # admin|analyst|viewer
    is_active: Mapped[bool] = mapped_column(Boolean, default=False)  # becomes True after email verification
    is_verified: Mapped[bool] = mapped_column(Boolean, default=False)
    disabled: Mapped[bool] = mapped_column(Boolean, default=False)
    otp_hash: Mapped[str | None] = mapped_column(String(128), nullable=True)
    otp_expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=datetime.utcnow)
    last_login_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    assessments: Mapped[list["Assessment"]] = relationship(  # noqa: F821
        back_populates="owner", foreign_keys="Assessment.owner_id"
    )
    audit_logs: Mapped[list["AuditLog"]] = relationship(back_populates="user")  # noqa: F821

    def __repr__(self) -> str:
        return f"<User {self.email} ({self.role})>"