from server.database import Base
from sqlalchemy.orm import Mapped, mapped_column
from sqlalchemy import String, DateTime, Float, Text, JSON, func
import uuid


class Policy(Base):
    __tablename__ = "policies"

    id: Mapped[str] = mapped_column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    name: Mapped[str] = mapped_column(String, nullable=False, unique=True)
    category: Mapped[str] = mapped_column(String, nullable=False)          # PII | FINANCIAL | SECRETS | HEALTH
    pattern: Mapped[str] = mapped_column(Text, nullable=False)
    base_weight: Mapped[float] = mapped_column(Float, default=1.0)
    regulation_tags: Mapped[dict] = mapped_column(JSON, default=list)
    description: Mapped[str] = mapped_column(Text, default="")
    is_active: Mapped[bool] = mapped_column(default=True)
    version: Mapped[str] = mapped_column(String, default="1")
    created_at: Mapped[DateTime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    updated_at: Mapped[DateTime] = mapped_column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())
