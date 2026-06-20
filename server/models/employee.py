from server.database import Base
from sqlalchemy.orm import Mapped, mapped_column
from sqlalchemy import String, Boolean, DateTime, Float, Integer, Text, func
import uuid


class Employee(Base):
    __tablename__ = "employees"

    id: Mapped[str] = mapped_column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    email: Mapped[str] = mapped_column(String, unique=True, nullable=False, index=True)
    full_name: Mapped[str] = mapped_column(String, nullable=False, default="")
    department: Mapped[str] = mapped_column(String, nullable=False, default="")
    job_title: Mapped[str] = mapped_column(String, nullable=False, default="")

    # Risk scoring
    risk_score: Mapped[float] = mapped_column(Float, default=0.0)
    risk_level: Mapped[str] = mapped_column(String, default="CLEAN")  # CLEAN | LOW | MEDIUM | HIGH
    high_violations_7d: Mapped[int] = mapped_column(Integer, default=0)
    medium_violations_7d: Mapped[int] = mapped_column(Integer, default=0)
    total_events_30d: Mapped[int] = mapped_column(Integer, default=0)

    # Flagging
    is_flagged: Mapped[bool] = mapped_column(Boolean, default=False)
    flag_reason: Mapped[str] = mapped_column(Text, default="")
    flagged_at: Mapped[DateTime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    flagged_by: Mapped[str] = mapped_column(String, default="")

    # Envelope encryption DEK (encrypted with master key)
    encrypted_dek: Mapped[str] = mapped_column(Text, nullable=False, default="")

    # Per-employee monitoring controls (toggled by admin per employee)
    monitor_clipboard: Mapped[bool] = mapped_column(Boolean, default=True)
    monitor_usb: Mapped[bool] = mapped_column(Boolean, default=True)
    monitor_webmail: Mapped[bool] = mapped_column(Boolean, default=True)
    monitor_file_scan: Mapped[bool] = mapped_column(Boolean, default=True)

    # PIN authentication (hashed, set by admin, changed by employee on first login)
    pin_hash: Mapped[str | None] = mapped_column(String, nullable=True, default=None)
    pin_set: Mapped[bool] = mapped_column(Boolean, default=False)

    created_at: Mapped[DateTime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    updated_at: Mapped[DateTime] = mapped_column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())
