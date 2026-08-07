"""SQLAlchemy ORM models."""

from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import JSON, DateTime, Integer, String, Text, Uuid, func
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from app.db.session import Base

_JSONVariant = JSON().with_variant(JSONB(), "postgresql")


class Case(Base):
    """A persisted analysis result. The raw email itself is never stored here — only
    `raw_email_path`, a pointer to a file on disk that is subject to a retention window
    (see app.storage.raw_email_store)."""

    __tablename__ = "cases"

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    filename: Mapped[str] = mapped_column(String, nullable=False)
    verdict: Mapped[str] = mapped_column(String, nullable=False)
    score: Mapped[int] = mapped_column(Integer, nullable=False)
    from_addr: Mapped[str | None] = mapped_column(String, nullable=True)
    subject: Mapped[str | None] = mapped_column(String, nullable=True)
    indicators: Mapped[list] = mapped_column(_JSONVariant, nullable=False, default=list)
    framework_mappings: Mapped[dict] = mapped_column(_JSONVariant, nullable=False, default=dict)
    analyst_narrative: Mapped[str | None] = mapped_column(Text, nullable=True)
    analyst_model: Mapped[str | None] = mapped_column(String, nullable=True)
    raw_email_path: Mapped[str | None] = mapped_column(String, nullable=True)
