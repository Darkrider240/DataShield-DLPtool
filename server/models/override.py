from server.database import Base
from sqlalchemy.orm import Mapped, mapped_column
from sqlalchemy import String, DateTime, Text, Boolean, func
import uuid


class OverrideRequest(Base):
    __tablename__ = "override_requests"

    id: Mapped[str] = mapped_column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    employee_id:   Mapped[str] = mapped_column(String, nullable=False, index=True)
    agent_id:      Mapped[str] = mapped_column(String, default="")
    event_channel: Mapped[str] = mapped_column(String, nullable=False)
    event_detail:  Mapped[str] = mapped_column(Text, default="")
    pattern:       Mapped[str] = mapped_column(String, default="")
    justification: Mapped[str] = mapped_column(Text, nullable=False)
    status:        Mapped[str] = mapped_column(String, default="PENDING", index=True)  # PENDING|APPROVED|DENIED
    admin_note:    Mapped[str | None] = mapped_column(Text, nullable=True, default=None)
    reviewed_by:   Mapped[str | None] = mapped_column(String, nullable=True, default=None)
    created_at:    Mapped[DateTime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    reviewed_at:   Mapped[DateTime | None] = mapped_column(DateTime(timezone=True), nullable=True, default=None)
    # Tracks whether the agent GUI has already shown the approval/denial notification
    agent_notified: Mapped[bool] = mapped_column(Boolean, default=False, server_default="false")
