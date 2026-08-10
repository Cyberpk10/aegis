"""POST /api/events — source-agnostic ingestion of normalized activity events, with
synchronous per-actor detection (M5 Stage 1) against the actor's own behavioral baseline
(M5 Stage 2 — UEBA). Defensive monitoring only: this endpoint persists events and, when
warranted, an incident case — nothing here blocks, isolates, or otherwise alters any
external system. An incident is only created when the fused verdict for an actor's event
window is non-safe (see app.detections/app.scoring.intrusion_risk_engine) — events are
continuous telemetry, so persisting a "safe" incident per actor per batch would flood the
incidents table with routine activity. Requires auth; every event/baseline/incident is
scoped to the authenticated user's account (M8 Stage 2) — two accounts with an
identically-named actor never share a baseline or a detection window.
"""

from __future__ import annotations

import uuid
from datetime import timedelta
from uuid import UUID

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app.auth.dependencies import get_current_user
from app.baselines.aggregation import BaselineSnapshot, empty_baseline, update_baseline
from app.core.config import settings
from app.db.models import ActorBaseline, Event, Incident, User
from app.db.session import get_db
from app.detections.base import ActorEventWindow
from app.detections.engine import run_detections
from app.events.schema import ActivityEvent, EventBatchRequest
from app.mapping.framework_mapper import map_indicators
from app.models.schemas import EventBatchResponse, Finding, IncidentSummary
from app.scoring.intrusion_risk_engine import fuse

router = APIRouter(prefix="/api/events", tags=["events"])


def _persist_event(db: Session, account_id: UUID, event: ActivityEvent) -> Event:
    row = Event(
        id=event.id or uuid.uuid4(),
        account_id=account_id,
        timestamp=event.timestamp,
        actor=event.actor,
        source_ip=event.source_ip,
        geo=event.geo.model_dump(mode="json") if event.geo else None,
        action=event.action.value,
        target=event.target,
        bytes=event.bytes,
        device=event.device,
        outcome=event.outcome,
        raw=event.raw,
    )
    db.add(row)
    return row


def _to_activity_event(row: Event) -> ActivityEvent:
    return ActivityEvent(
        id=row.id,
        timestamp=row.timestamp,
        actor=row.actor,
        source_ip=row.source_ip,
        geo=row.geo,
        action=row.action,
        target=row.target,
        bytes=row.bytes,
        device=row.device,
        outcome=row.outcome,
        raw=row.raw,
    )


def _incident_title(actor: str, findings: list[Finding]) -> str:
    # Findings are already in deterministic order (app.detections.engine's fixed _RULES
    # order) — the first is treated as the "primary" detection for the incident title.
    return f"{findings[0].title} — {actor}"


def _load_baseline_snapshot(db: Session, account_id: UUID, actor: str) -> BaselineSnapshot:
    row = (
        db.query(ActorBaseline)
        .filter(ActorBaseline.account_id == account_id, ActorBaseline.actor == actor)
        .first()
    )
    if row is None:
        return empty_baseline(actor)
    return BaselineSnapshot(
        actor=actor,
        hour_counts=list(row.hour_counts),
        location_counts=dict(row.location_counts),
        ip_counts=dict(row.ip_counts),
        daily_volume=dict(row.daily_volume),
        event_count=row.event_count,
    )


def _persist_baseline(db: Session, account_id: UUID, snapshot: BaselineSnapshot) -> None:
    row = (
        db.query(ActorBaseline)
        .filter(ActorBaseline.account_id == account_id, ActorBaseline.actor == snapshot.actor)
        .first()
    )
    if row is None:
        db.add(
            ActorBaseline(
                id=uuid.uuid4(),
                account_id=account_id,
                actor=snapshot.actor,
                hour_counts=snapshot.hour_counts,
                location_counts=snapshot.location_counts,
                ip_counts=snapshot.ip_counts,
                daily_volume=snapshot.daily_volume,
                event_count=snapshot.event_count,
            )
        )
        return

    row.hour_counts = snapshot.hour_counts
    row.location_counts = snapshot.location_counts
    row.ip_counts = snapshot.ip_counts
    row.daily_volume = snapshot.daily_volume
    row.event_count = snapshot.event_count


@router.post("", response_model=EventBatchResponse)
async def ingest_events(
    body: EventBatchRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> EventBatchResponse:
    account_id = current_user.account_id
    persisted_rows = [_persist_event(db, account_id, event) for event in body.events]
    db.flush()

    actors = sorted({row.actor for row in persisted_rows})
    lookback = timedelta(hours=settings.intrusion_lookback_hours)
    incidents_created: list[IncidentSummary] = []

    for actor in actors:
        actor_batch_rows = [row for row in persisted_rows if row.actor == actor]
        window_end = max(row.timestamp for row in actor_batch_rows)
        window_start = window_end - lookback

        window_rows = (
            db.query(Event)
            .filter(
                Event.account_id == account_id,
                Event.actor == actor,
                Event.timestamp >= window_start,
                Event.timestamp <= window_end,
            )
            .order_by(Event.timestamp)
            .all()
        )

        window = ActorEventWindow(
            actor=actor, events=[_to_activity_event(row) for row in window_rows]
        )

        # Load the baseline BEFORE detection and update it AFTER — never the other way
        # around. Folding this batch in first would let a burst of malicious activity
        # inflate its own "normal" and mask itself from the very comparison meant to
        # catch it. The baseline still updates even when nothing fires: routine activity
        # is exactly what should be learned as normal.
        baseline = _load_baseline_snapshot(db, account_id, actor)
        findings = run_detections(window, baseline)
        score, verdict = fuse(findings)

        batch_events = [_to_activity_event(row) for row in actor_batch_rows]
        _persist_baseline(db, account_id, update_baseline(baseline, batch_events))

        if verdict.value == "safe":
            continue

        framework_mappings = map_indicators([f.id for f in findings])

        incident = Incident(
            id=uuid.uuid4(),
            account_id=account_id,
            title=_incident_title(actor, findings),
            actor=actor,
            verdict=verdict.value,
            score=score,
            detection_types=sorted({f.id for f in findings}),
            findings=[f.model_dump(mode="json") for f in findings],
            framework_mappings={
                key: [ref.model_dump(mode="json") for ref in refs]
                for key, refs in framework_mappings.items()
            },
            window_start=window_start,
            window_end=window_end,
        )
        db.add(incident)
        db.flush()
        db.refresh(incident)

        evidence_ids = {eid for f in findings for eid in f.evidence_event_ids}
        if evidence_ids:
            db.query(Event).filter(
                Event.account_id == account_id, Event.id.in_(evidence_ids)
            ).update({"incident_id": incident.id}, synchronize_session=False)

        incidents_created.append(
            IncidentSummary(
                id=incident.id,
                created_at=incident.created_at,
                title=incident.title,
                actor=incident.actor,
                verdict=verdict,
                score=score,
                detection_types=incident.detection_types,
                window_start=window_start,
                window_end=window_end,
            )
        )

    db.commit()

    return EventBatchResponse(accepted=len(persisted_rows), incidents_created=incidents_created)
