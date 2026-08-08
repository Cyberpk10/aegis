"""SQLAlchemy ORM models."""

from __future__ import annotations

import uuid
from datetime import datetime, timezone

from sqlalchemy import JSON, DateTime, ForeignKey, Integer, String, Text, Uuid, func
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship

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
    # Recipient addresses (ParsedEmail.to_addresses) — needed for per-recipient targeting
    # (M4 Stage 3). Not persisted before this stage.
    to_addresses: Mapped[list] = mapped_column(_JSONVariant, nullable=False, default=list)
    indicators: Mapped[list] = mapped_column(_JSONVariant, nullable=False, default=list)
    framework_mappings: Mapped[dict] = mapped_column(_JSONVariant, nullable=False, default=dict)
    analyst_narrative: Mapped[str | None] = mapped_column(Text, nullable=True)
    analyst_model: Mapped[str | None] = mapped_column(String, nullable=True)
    raw_email_path: Mapped[str | None] = mapped_column(String, nullable=True)

    labels: Mapped[list["Label"]] = relationship(
        back_populates="case", cascade="all, delete-orphan"
    )


class Label(Base):
    """An analyst's verdict on a case. Rows are append-only — relabeling inserts a new
    row rather than updating the old one, so the full labeling history is preserved."""

    __tablename__ = "labels"

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    case_id: Mapped[uuid.UUID] = mapped_column(
        Uuid, ForeignKey("cases.id", ondelete="CASCADE"), nullable=False
    )
    analyst_verdict: Mapped[str] = mapped_column(String, nullable=False)
    note: Mapped[str | None] = mapped_column(Text, nullable=True)
    labeled_by: Mapped[str] = mapped_column(String, nullable=False)
    # Python-side default (not server_default=func.now()): SQLite's CURRENT_TIMESTAMP only
    # has 1-second resolution, and relabeling the same case in quick succession needs
    # unambiguous ordering to determine the "latest" label.
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False
    )

    case: Mapped[Case] = relationship(back_populates="labels")


class AuditReport(Base):
    """Metadata + file pointers for a generated Audit Mode evidence pack. The PDF/JSON
    files themselves live on disk (see app.storage.audit_report_store) — this row is what
    makes a generated pack listable and re-downloadable later."""

    __tablename__ = "audit_reports"

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    framework_key: Mapped[str] = mapped_column(String, nullable=False)
    period_start: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    period_end: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    total_controls: Mapped[int] = mapped_column(Integer, nullable=False)
    operating_controls: Mapped[int] = mapped_column(Integer, nullable=False)
    total_supporting_cases: Mapped[int] = mapped_column(Integer, nullable=False)
    pdf_path: Mapped[str] = mapped_column(String, nullable=False)
    json_path: Mapped[str] = mapped_column(String, nullable=False)


class RemediationAction(Base):
    """An operator's approval/completion of a recommended playbook step. Rows are
    append-only — same audit-trail pattern as Label: re-acting on a step inserts a new
    row rather than overwriting the previous one, so the full action history is
    preserved. Aegis never executes the step itself; this only records that a human did.
    """

    __tablename__ = "remediation_actions"

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    case_id: Mapped[uuid.UUID] = mapped_column(
        Uuid, ForeignKey("cases.id", ondelete="CASCADE"), nullable=False
    )
    step_id: Mapped[str] = mapped_column(String, nullable=False)
    status: Mapped[str] = mapped_column(String, nullable=False)  # "approved" | "done"
    actor: Mapped[str] = mapped_column(String, nullable=False)
    note: Mapped[str | None] = mapped_column(Text, nullable=True)
    # Python-side default, same reasoning as Label.created_at: SQLite's CURRENT_TIMESTAMP
    # only has 1-second resolution, and a step can be approved then marked done in quick
    # succession.
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False
    )


class TrainingRecommendation(Base):
    """Current micro-training recommendation for a repeatedly-targeted recipient — one
    row per recipient (upserted as GET /api/targets recomputes), not an append-only log.
    No LMS integration; this is just the stored recommendation for one to plug in later.
    """

    __tablename__ = "training_recommendations"

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    recipient: Mapped[str] = mapped_column(String, nullable=False, unique=True)
    hit_count: Mapped[int] = mapped_column(Integer, nullable=False)
    top_indicator_id: Mapped[str] = mapped_column(String, nullable=False)
    top_indicator_title: Mapped[str] = mapped_column(String, nullable=False)
    recommendation: Mapped[str] = mapped_column(Text, nullable=False)
    first_flagged_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        onupdate=lambda: datetime.now(timezone.utc),
        nullable=False,
    )
