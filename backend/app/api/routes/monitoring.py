"""Continuous Control Monitoring (M7 Stage A) — reporting-only endpoints over the same
framework_mappings data every Case/Incident already carries. No new mutable state: both
endpoints recompute live from a bounded lookback window on every request, via the pure
functions in app.monitoring.control_monitor. Requires auth; scoped to the authenticated
user's account (M8 Stage 2) — same account_id filtering as /api/dashboard and
/api/incidents.
"""

from __future__ import annotations

from dataclasses import asdict
from datetime import datetime, timedelta
from uuid import UUID

from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session

from app.auth.dependencies import get_current_user
from app.core.config import settings
from app.core.time import to_naive_utc
from app.db.models import Case, Incident, User
from app.db.session import get_db
from app.mapping import framework_mapper
from app.models.schemas import (
    ControlHealthListResponse,
    ControlHealthResponse,
    DriftAlertListResponse,
    DriftAlertResponse,
)
from app.monitoring.control_monitor import (
    CaseIndicatorRow,
    EvidenceRow,
    compute_drift_alerts,
    control_health,
)

router = APIRouter(prefix="/api/monitoring", tags=["monitoring"])


def _lookback_start(now: datetime) -> datetime:
    return now - timedelta(days=settings.monitoring_lookback_days)


def _load_evidence(
    db: Session, account_id: UUID, start: datetime, now: datetime
) -> list[EvidenceRow]:
    cases = (
        db.query(Case.created_at, Case.framework_mappings)
        .filter(Case.account_id == account_id, Case.created_at >= start, Case.created_at <= now)
        .all()
    )
    incidents = (
        db.query(Incident.created_at, Incident.framework_mappings)
        .filter(
            Incident.account_id == account_id,
            Incident.created_at >= start,
            Incident.created_at <= now,
        )
        .all()
    )
    # Postgres (production) returns an aware datetime for a DateTime(timezone=True) column;
    # SQLite (tests) returns naive. control_monitor's freshness math subtracts this from a
    # naive datetime.utcnow(), which raises TypeError if the two sides disagree — normalize
    # here so both dialects behave the same (see app.core.time).
    return [
        EvidenceRow(
            occurred_at=to_naive_utc(row.created_at),
            framework_mappings=row.framework_mappings or {},
        )
        for row in (*cases, *incidents)
    ]


def _load_case_indicator_rows(
    db: Session, account_id: UUID, start: datetime, now: datetime
) -> list[CaseIndicatorRow]:
    rows = (
        db.query(Case.created_at, Case.indicators)
        .filter(Case.account_id == account_id, Case.created_at >= start, Case.created_at <= now)
        .all()
    )
    return [
        CaseIndicatorRow(
            created_at=to_naive_utc(row.created_at),
            indicator_ids=[i.get("id") for i in (row.indicators or [])],
        )
        for row in rows
    ]


@router.get("/controls", response_model=ControlHealthListResponse)
async def get_control_health(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
    framework: str | None = Query(
        default=None, description="Restrict to one framework_key (mitre_attack|nist_csf|iso_27001|soc2)."
    ),
) -> ControlHealthListResponse:
    now = datetime.utcnow()
    evidence = _load_evidence(db, current_user.account_id, _lookback_start(now), now)

    framework_keys = [framework] if framework else framework_mapper.loaded_framework_keys()
    items: list[ControlHealthResponse] = []
    for key in framework_keys:
        loaded = framework_mapper.get_framework(key)
        if loaded is None:
            continue
        health = control_health(
            evidence,
            loaded.controls_by_id,
            key,
            now,
            default_interval_days=settings.monitoring_default_interval_days,
            stale_multiplier=settings.monitoring_stale_multiplier,
        )
        items.extend(ControlHealthResponse(**asdict(h)) for h in health)

    return ControlHealthListResponse(items=items, total=len(items))


@router.get("/drift", response_model=DriftAlertListResponse)
async def get_drift_alerts(
    db: Session = Depends(get_db), current_user: User = Depends(get_current_user)
) -> DriftAlertListResponse:
    now = datetime.utcnow()
    start = _lookback_start(now)
    evidence = _load_evidence(db, current_user.account_id, start, now)
    case_rows = _load_case_indicator_rows(db, current_user.account_id, start, now)

    alerts = compute_drift_alerts(
        evidence,
        case_rows,
        now,
        default_interval_days=settings.monitoring_default_interval_days,
        stale_multiplier=settings.monitoring_stale_multiplier,
        auth_window_days=settings.monitoring_auth_window_days,
        auth_min_sample=settings.monitoring_auth_min_sample,
        auth_drop_threshold=settings.monitoring_auth_drop_threshold,
        coverage_comparison_days=settings.monitoring_coverage_comparison_days,
        coverage_drop_threshold=settings.monitoring_coverage_drop_threshold,
    )

    items = [DriftAlertResponse(**asdict(a)) for a in alerts]
    return DriftAlertListResponse(items=items, total=len(items))
