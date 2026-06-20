from server.database import Base
from sqlalchemy.orm import Mapped, mapped_column
from sqlalchemy import String, Boolean, DateTime, func
import uuid


class Agent(Base):
    __tablename__ = "agents"

    id: Mapped[str] = mapped_column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    hostname: Mapped[str] = mapped_column(String, nullable=False)
    employee_id: Mapped[str | None] = mapped_column(String, nullable=True, index=True)
    employee_email: Mapped[str] = mapped_column(String, nullable=False, index=True)
    # Denormalised for fast display in admin console without a JOIN
    employee_name: Mapped[str] = mapped_column(String, nullable=False, default="")
    platform: Mapped[str] = mapped_column(String, nullable=False, default="")   # win32 | linux | darwin
    agent_version: Mapped[str] = mapped_column(String, nullable=False, default="")
    policy_version: Mapped[str] = mapped_column(String, nullable=False, default="")
    policy_update_available: Mapped[bool] = mapped_column(Boolean, default=False)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    registered_at: Mapped[DateTime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    last_heartbeat: Mapped[DateTime | None] = mapped_column(DateTime(timezone=True), nullable=True)
