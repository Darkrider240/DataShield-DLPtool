from server.database import Base
from sqlalchemy.orm import Mapped, mapped_column
from sqlalchemy import String, DateTime, Float, Text, JSON, func
import uuid


class DLPEvent(Base):
    __tablename__ = "dlp_events"

    id: Mapped[str] = mapped_column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    employee_id: Mapped[str] = mapped_column(String, nullable=False, index=True)
    agent_id: Mapped[str] = mapped_column(String, nullable=False, index=True)

    channel: Mapped[str] = mapped_column(String, nullable=False)  # FILE | EMAIL | WEBMAIL | CLIPBOARD | USB
    action_taken: Mapped[str] = mapped_column(String, nullable=False)  # ALLOW | BLOCK | WARN
    justification: Mapped[str] = mapped_column(Text, default="")

    risk_level: Mapped[str] = mapped_column(String, nullable=False)  # CLEAN | LOW | MEDIUM | HIGH
    risk_score: Mapped[float] = mapped_column(Float, default=0.0)

    # Sensitive fields — stored AES-256-GCM encrypted with employee DEK
    file_path_encrypted: Mapped[str] = mapped_column(Text, default="")
    ai_explanation_encrypted: Mapped[str] = mapped_column(Text, default="")

    # Non-sensitive metadata
    matched_value_redacted: Mapped[str] = mapped_column(Text, default="")
    pattern_names: Mapped[dict] = mapped_column(JSON, default=list)   # list[str]
    regulation_tags: Mapped[dict] = mapped_column(JSON, default=list)  # list[str]

    # Email attribution (WEBMAIL / EMAIL channel only)
    sender_email:     Mapped[str | None] = mapped_column(String, nullable=True, default=None)
    recipient_emails: Mapped[str | None] = mapped_column(Text,   nullable=True, default=None)
    email_subject:    Mapped[str | None] = mapped_column(String,  nullable=True, default=None)

    occurred_at: Mapped[DateTime] = mapped_column(DateTime(timezone=True), nullable=False)
    ingested_at: Mapped[DateTime] = mapped_column(DateTime(timezone=True), server_default=func.now())
