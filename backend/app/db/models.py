"""SQLAlchemy ORM models."""

from __future__ import annotations

import uuid
from datetime import datetime, timezone

from sqlalchemy import (
    JSON,
    BigInteger,
    Boolean,
    CheckConstraint,
    DateTime,
    Float,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
    Uuid,
    func,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.session import Base

_JSONVariant = JSON().with_variant(JSONB(), "postgresql")


class Account(Base):
    """An organization/tenant (M8 Stage 2) — every User belongs to exactly one Account, and
    all other data (cases, incidents, events, labels, autonomy policy/actions, ...) is
    scoped to one via an `account_id` FK. Replaces the earlier stub tenant_id string
    (M6 Stage 1) with a real row."""

    __tablename__ = "accounts"

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    name: Mapped[str] = mapped_column(String, nullable=False)
    # Opaque per-account slug used in the inbound-email forwarding address
    # (pilot-<inbound_token>@<settings.inbound_email_domain>, M8 Stage 3) — deliberately not
    # the account's own id, so the address typed into mail clients/tickets/screenshots never
    # exposes the real internal identifier. See app.auth.security.generate_inbound_token.
    inbound_token: Mapped[str] = mapped_column(String, nullable=False, unique=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )


class User(Base):
    """A login identity belonging to exactly one Account (M8 Stage 2). `email` is globally
    unique — login is by email alone, then the account is resolved from the user, not the
    other way around. `role` ("admin" | "analyst") gates privileged actions — see
    app.auth.dependencies.require_admin."""

    __tablename__ = "users"

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    account_id: Mapped[uuid.UUID] = mapped_column(
        Uuid, ForeignKey("accounts.id", ondelete="CASCADE"), nullable=False
    )
    email: Mapped[str] = mapped_column(String, nullable=False, unique=True)
    password_hash: Mapped[str] = mapped_column(String, nullable=False)
    role: Mapped[str] = mapped_column(String, nullable=False, default="analyst")
    is_active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    last_login_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class RefreshToken(Base):
    """A hashed, revocable refresh token (M8 Stage 2) — the raw token is only ever seen by
    the client; only its hash is stored, same principle as password storage. Rotates on
    every use (`replaced_by_id` chains the rotation); presenting an already-rotated token
    is a strong signal of theft and revokes the whole chain (see app.auth.security)."""

    __tablename__ = "refresh_tokens"

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    user_id: Mapped[uuid.UUID] = mapped_column(
        Uuid, ForeignKey("users.id", ondelete="CASCADE"), nullable=False
    )
    token_hash: Mapped[str] = mapped_column(String, nullable=False, unique=True)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    replaced_by_id: Mapped[uuid.UUID | None] = mapped_column(
        Uuid, ForeignKey("refresh_tokens.id", ondelete="SET NULL"), nullable=True
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )


class PasswordResetToken(Base):
    """A hashed, single-use, expiring password-reset token (M8 Stage 2). Email delivery is
    stubbed for this stage — the raw token/link is returned directly in the API response
    (see app.api.routes.auth) rather than actually emailed."""

    __tablename__ = "password_reset_tokens"

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    user_id: Mapped[uuid.UUID] = mapped_column(
        Uuid, ForeignKey("users.id", ondelete="CASCADE"), nullable=False
    )
    token_hash: Mapped[str] = mapped_column(String, nullable=False, unique=True)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    used_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )


class Invite(Base):
    """A pending teammate invite (M8 Stage 2) — same stubbed-email-delivery note as
    PasswordResetToken. Accepting one (POST /api/auth/invite/accept) creates the User row
    under `account_id` with `role`."""

    __tablename__ = "invites"

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    account_id: Mapped[uuid.UUID] = mapped_column(
        Uuid, ForeignKey("accounts.id", ondelete="CASCADE"), nullable=False
    )
    email: Mapped[str] = mapped_column(String, nullable=False)
    role: Mapped[str] = mapped_column(String, nullable=False, default="analyst")
    token_hash: Mapped[str] = mapped_column(String, nullable=False, unique=True)
    invited_by_user_id: Mapped[uuid.UUID] = mapped_column(
        Uuid, ForeignKey("users.id", ondelete="CASCADE"), nullable=False
    )
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    accepted_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )


class AuditLogEntry(Base):
    """Append-only audit trail of logins and privileged actions (M8 Stage 2) — a distinct
    concept from AuditReport/Audit Mode above (detection-control coverage evidence, not
    "who did what to this account"). `account_id`/`user_id` are nullable since a failed
    login may not resolve either."""

    __tablename__ = "audit_log_entries"

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    account_id: Mapped[uuid.UUID | None] = mapped_column(
        Uuid, ForeignKey("accounts.id", ondelete="CASCADE"), nullable=True
    )
    user_id: Mapped[uuid.UUID | None] = mapped_column(
        Uuid, ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    event_type: Mapped[str] = mapped_column(String, nullable=False)
    detail: Mapped[dict | None] = mapped_column(_JSONVariant, nullable=True)
    ip_address: Mapped[str | None] = mapped_column(String, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )


class Case(Base):
    """A persisted analysis result. The raw email itself is never stored here — only
    `raw_email_path`, a pointer to a file on disk that is subject to a retention window
    (see app.storage.raw_email_store)."""

    __tablename__ = "cases"
    __table_args__ = (
        Index("ix_cases_account_content_hash", "account_id", "content_hash"),
    )

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    account_id: Mapped[uuid.UUID] = mapped_column(
        Uuid, ForeignKey("accounts.id", ondelete="CASCADE"), nullable=False
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    filename: Mapped[str] = mapped_column(String, nullable=False)
    # "email" | "slack" | "teams" (app.channels.message.Channel) — M7 Stage B. Defaults to
    # "email" so every pre-existing row and the email analyze path are unaffected.
    channel: Mapped[str] = mapped_column(String, nullable=False, default="email", server_default="email")
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
    # sha256 hex of the final (post-unwrap) raw email bytes — only ever set by the inbound
    # webhook (M8 Stage 3), used to dedupe a provider retry or a duplicate forward against
    # the same account. Null for every other intake path (manual upload, chat messages).
    content_hash: Mapped[str | None] = mapped_column(String, nullable=True)

    labels: Mapped[list["Label"]] = relationship(
        back_populates="case", cascade="all, delete-orphan"
    )


class Label(Base):
    """An analyst's verdict on a case OR an incident (M5 Stage 1 — exactly one of
    case_id/incident_id is set, enforced by a CHECK constraint). Rows are append-only —
    relabeling inserts a new row rather than updating the old one, so the full labeling
    history is preserved."""

    __tablename__ = "labels"
    __table_args__ = (
        CheckConstraint(
            "(case_id IS NOT NULL) != (incident_id IS NOT NULL)",
            name="ck_labels_exactly_one_parent",
        ),
    )

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    account_id: Mapped[uuid.UUID] = mapped_column(
        Uuid, ForeignKey("accounts.id", ondelete="CASCADE"), nullable=False
    )
    case_id: Mapped[uuid.UUID | None] = mapped_column(
        Uuid, ForeignKey("cases.id", ondelete="CASCADE"), nullable=True
    )
    incident_id: Mapped[uuid.UUID | None] = mapped_column(
        Uuid, ForeignKey("incidents.id", ondelete="CASCADE"), nullable=True
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

    case: Mapped[Case | None] = relationship(back_populates="labels")
    incident: Mapped["Incident | None"] = relationship(back_populates="labels")


class AuditReport(Base):
    """Metadata + file pointers for a generated Audit Mode evidence pack. The PDF/JSON
    files themselves live on disk (see app.storage.audit_report_store) — this row is what
    makes a generated pack listable and re-downloadable later."""

    __tablename__ = "audit_reports"

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    account_id: Mapped[uuid.UUID] = mapped_column(
        Uuid, ForeignKey("accounts.id", ondelete="CASCADE"), nullable=False
    )
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
    """An operator's approval/completion of a recommended playbook step, for a case OR an
    incident (M5 Stage 1 — exactly one of case_id/incident_id is set, enforced by a CHECK
    constraint). Rows are append-only — same audit-trail pattern as Label: re-acting on a
    step inserts a new row rather than overwriting the previous one, so the full action
    history is preserved. Aegis never executes the step itself; this only records that a
    human did.
    """

    __tablename__ = "remediation_actions"
    __table_args__ = (
        CheckConstraint(
            "(case_id IS NOT NULL) != (incident_id IS NOT NULL)",
            name="ck_remediation_actions_exactly_one_parent",
        ),
    )

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    account_id: Mapped[uuid.UUID] = mapped_column(
        Uuid, ForeignKey("accounts.id", ondelete="CASCADE"), nullable=False
    )
    case_id: Mapped[uuid.UUID | None] = mapped_column(
        Uuid, ForeignKey("cases.id", ondelete="CASCADE"), nullable=True
    )
    incident_id: Mapped[uuid.UUID | None] = mapped_column(
        Uuid, ForeignKey("incidents.id", ondelete="CASCADE"), nullable=True
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
    __table_args__ = (
        UniqueConstraint("account_id", "recipient", name="uq_training_recommendations_account_recipient"),
    )

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    account_id: Mapped[uuid.UUID] = mapped_column(
        Uuid, ForeignKey("accounts.id", ondelete="CASCADE"), nullable=False
    )
    recipient: Mapped[str] = mapped_column(String, nullable=False)
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


class Incident(Base):
    """A persisted intrusion/data-exfiltration detection result (M5 Stage 1) —
    structurally parallel to Case (verdict/score/findings/framework_mappings) but for
    activity-event telemetry instead of email. Unlike Case, a row is only created when
    the fused verdict for an actor's event window is non-safe — see
    app.api.routes.events.ingest_events; there is no "safe incident" row, since events
    are continuous telemetry rather than one-artifact-per-analysis."""

    __tablename__ = "incidents"

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    account_id: Mapped[uuid.UUID] = mapped_column(
        Uuid, ForeignKey("accounts.id", ondelete="CASCADE"), nullable=False
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    title: Mapped[str] = mapped_column(String, nullable=False)
    actor: Mapped[str] = mapped_column(String, nullable=False)
    verdict: Mapped[str] = mapped_column(String, nullable=False)
    score: Mapped[int] = mapped_column(Integer, nullable=False)
    detection_types: Mapped[list] = mapped_column(_JSONVariant, nullable=False, default=list)
    findings: Mapped[list] = mapped_column(_JSONVariant, nullable=False, default=list)
    framework_mappings: Mapped[dict] = mapped_column(_JSONVariant, nullable=False, default=dict)
    window_start: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    window_end: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)

    events: Mapped[list["Event"]] = relationship(back_populates="incident")
    labels: Mapped[list["Label"]] = relationship(
        back_populates="incident", cascade="all, delete-orphan"
    )


class Event(Base):
    """A normalized, source-agnostic activity-log event (login, file access, data
    transfer, privilege change, etc.) ingested via POST /api/events. `raw` preserves the
    untouched source payload. `incident_id` is populated post-hoc, only on whichever
    events ended up cited as evidence for a detection finding — most events are never
    linked to an incident."""

    __tablename__ = "events"

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    account_id: Mapped[uuid.UUID] = mapped_column(
        Uuid, ForeignKey("accounts.id", ondelete="CASCADE"), nullable=False
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    # The event's own time (not ingestion time) — all detection windowing is computed
    # from this, never wall-clock, so replaying historical/fixture data is deterministic.
    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    actor: Mapped[str] = mapped_column(String, nullable=False)
    source_ip: Mapped[str | None] = mapped_column(String, nullable=True)
    geo: Mapped[dict | None] = mapped_column(_JSONVariant, nullable=True)
    action: Mapped[str] = mapped_column(String, nullable=False)
    target: Mapped[str | None] = mapped_column(String, nullable=True)
    bytes: Mapped[int | None] = mapped_column(BigInteger, nullable=True)
    device: Mapped[str | None] = mapped_column(String, nullable=True)
    outcome: Mapped[str | None] = mapped_column(String, nullable=True)
    raw: Mapped[dict | None] = mapped_column(_JSONVariant, nullable=True)
    incident_id: Mapped[uuid.UUID | None] = mapped_column(
        Uuid, ForeignKey("incidents.id", ondelete="SET NULL"), nullable=True
    )

    incident: Mapped[Incident | None] = relationship(back_populates="events")


class ActorBaseline(Base):
    """A per-actor behavioral baseline (M5 Stage 2 — UEBA), upserted as new events arrive
    rather than an append-only log — one row per actor, always reflecting current
    learned-normal. `hour_counts`/`location_counts`/`ip_counts` are simple running counts;
    `daily_volume` is a bounded rolling window of per-day file-access counts (oldest days
    dropped as new ones are added). `event_count` is the cold-start gate other code checks
    before trusting this baseline over a static threshold — see app.baselines.aggregation.
    """

    __tablename__ = "actor_baselines"
    __table_args__ = (
        UniqueConstraint("account_id", "actor", name="uq_actor_baselines_account_actor"),
    )

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    account_id: Mapped[uuid.UUID] = mapped_column(
        Uuid, ForeignKey("accounts.id", ondelete="CASCADE"), nullable=False
    )
    actor: Mapped[str] = mapped_column(String, nullable=False)
    hour_counts: Mapped[list] = mapped_column(_JSONVariant, nullable=False, default=list)
    location_counts: Mapped[dict] = mapped_column(_JSONVariant, nullable=False, default=dict)
    ip_counts: Mapped[dict] = mapped_column(_JSONVariant, nullable=False, default=dict)
    daily_volume: Mapped[dict] = mapped_column(_JSONVariant, nullable=False, default=dict)
    event_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    first_seen: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False
    )
    last_updated: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        onupdate=lambda: datetime.now(timezone.utc),
        nullable=False,
    )


class AutonomyPolicy(Base):
    """An account's autonomy configuration (M6 Stage 1; account-scoped since M8 Stage 2) —
    one row per account, upserted (same pattern as TrainingRecommendation/ActorBaseline),
    not append-only. `rules`/`exclusions` are plain JSON, parsed into
    app.autonomy.policy.Policy dataclasses by the route layer — this row is the persisted
    form, not the evaluation interface."""

    __tablename__ = "autonomy_policies"

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    account_id: Mapped[uuid.UUID] = mapped_column(
        Uuid, ForeignKey("accounts.id", ondelete="CASCADE"), nullable=False, unique=True
    )
    level: Mapped[str] = mapped_column(String, nullable=False, default="L0")
    rules: Mapped[list] = mapped_column(_JSONVariant, nullable=False, default=list)
    exclusions: Mapped[list] = mapped_column(_JSONVariant, nullable=False, default=list)
    blast_radius_limit: Mapped[int] = mapped_column(Integer, nullable=False, default=10)
    blast_radius_window_minutes: Mapped[int] = mapped_column(Integer, nullable=False, default=60)
    halted_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        onupdate=lambda: datetime.now(timezone.utc),
        nullable=False,
    )


class AutonomyAction(Base):
    """Append-only audit log of every autonomy policy decision (M6 Stage 1) — the
    compliance-evidence trail. Written for every decision (auto_execute, require_approval,
    AND skip), not just executed ones, so "every action produces a complete audit log
    record" holds unconditionally. Triggered by a case OR an incident (dual-parent FK +
    CHECK, same pattern as Label/RemediationAction) since the M6 action catalog spans
    both email cases and activity incidents. `policy_rule` is a snapshot of the matched
    rule at decision time, since the live policy can change later and the audit record
    must reflect what actually applied."""

    __tablename__ = "autonomy_actions"
    __table_args__ = (
        CheckConstraint(
            "(case_id IS NOT NULL) != (incident_id IS NOT NULL)",
            name="ck_autonomy_actions_exactly_one_parent",
        ),
    )

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    account_id: Mapped[uuid.UUID] = mapped_column(
        Uuid, ForeignKey("accounts.id", ondelete="CASCADE"), nullable=False
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False
    )
    case_id: Mapped[uuid.UUID | None] = mapped_column(
        Uuid, ForeignKey("cases.id", ondelete="CASCADE"), nullable=True
    )
    incident_id: Mapped[uuid.UUID | None] = mapped_column(
        Uuid, ForeignKey("incidents.id", ondelete="CASCADE"), nullable=True
    )
    trigger_finding_id: Mapped[str] = mapped_column(String, nullable=False)
    action_type: Mapped[str] = mapped_column(String, nullable=False)
    target: Mapped[str] = mapped_column(String, nullable=False)
    confidence: Mapped[float] = mapped_column(Float, nullable=False)
    policy_rule: Mapped[dict | None] = mapped_column(_JSONVariant, nullable=True)
    decision: Mapped[str] = mapped_column(String, nullable=False)
    # "executed" | "reversed" | "pending_approval" | "skipped" | "halted"
    status: Mapped[str] = mapped_column(String, nullable=False)
    result: Mapped[dict | None] = mapped_column(_JSONVariant, nullable=True)
    reversible: Mapped[bool] = mapped_column(Boolean, nullable=False)
    mapped_controls: Mapped[dict] = mapped_column(_JSONVariant, nullable=False, default=dict)
