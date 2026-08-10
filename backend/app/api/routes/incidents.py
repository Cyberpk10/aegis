"""GET/DELETE endpoints for browsing persisted intrusion/data-exfiltration incidents
(M5 Stage 1), plus the analyst-feedback POST .../label endpoint — mirrors
app.api.routes.cases exactly, reusing the same Label table/append-only audit-trail
machinery (see app.db.models.Label's incident_id column). Every endpoint requires auth and
is scoped to the authenticated user's account (M8 Stage 2) — deleting is admin-only."""

from __future__ import annotations

from datetime import datetime
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session

from app.auth.audit_log import log_event
from app.auth.dependencies import get_current_user, require_admin
from app.db.models import Event, Incident, Label, User
from app.db.session import get_db
from app.events.schema import ActivityEvent
from app.models.schemas import (
    IncidentDetailResponse,
    IncidentListResponse,
    IncidentSummary,
    LabelRequest,
    LabelResponse,
    Verdict,
)

router = APIRouter(prefix="/api/incidents", tags=["incidents"])


def _latest_label(db: Session, account_id: UUID, incident_id: UUID) -> Label | None:
    return (
        db.query(Label)
        .filter(Label.account_id == account_id, Label.incident_id == incident_id)
        .order_by(Label.created_at.desc())
        .first()
    )


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


def _to_incident_detail(
    incident: Incident, evidence_events: list[Event], latest_label: Label | None
) -> IncidentDetailResponse:
    return IncidentDetailResponse(
        id=incident.id,
        created_at=incident.created_at,
        title=incident.title,
        actor=incident.actor,
        verdict=incident.verdict,
        score=incident.score,
        detection_types=incident.detection_types,
        findings=incident.findings,
        framework_mappings=incident.framework_mappings,
        window_start=incident.window_start,
        window_end=incident.window_end,
        evidence_events=[_to_activity_event(e) for e in evidence_events],
        latest_label=LabelResponse.model_validate(latest_label) if latest_label else None,
    )


@router.get("", response_model=IncidentListResponse)
async def list_incidents(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    verdict: Verdict | None = None,
    actor: str | None = None,
    date_from: datetime | None = None,
    date_to: datetime | None = None,
) -> IncidentListResponse:
    query = db.query(Incident).filter(Incident.account_id == current_user.account_id)
    if verdict is not None:
        query = query.filter(Incident.verdict == verdict.value)
    if actor is not None:
        query = query.filter(Incident.actor == actor)
    if date_from is not None:
        query = query.filter(Incident.created_at >= date_from)
    if date_to is not None:
        query = query.filter(Incident.created_at <= date_to)

    total = query.count()
    rows = (
        query.order_by(Incident.created_at.desc())
        .offset((page - 1) * page_size)
        .limit(page_size)
        .all()
    )

    return IncidentListResponse(
        items=[IncidentSummary.model_validate(row) for row in rows],
        total=total,
        page=page,
        page_size=page_size,
    )


@router.get("/{incident_id}", response_model=IncidentDetailResponse)
async def get_incident(
    incident_id: UUID,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> IncidentDetailResponse:
    incident = db.get(Incident, incident_id)
    if incident is None or incident.account_id != current_user.account_id:
        raise HTTPException(status_code=404, detail="Incident not found.")
    evidence_events = (
        db.query(Event)
        .filter(Event.account_id == current_user.account_id, Event.incident_id == incident_id)
        .order_by(Event.timestamp)
        .all()
    )
    return _to_incident_detail(
        incident, evidence_events, _latest_label(db, current_user.account_id, incident_id)
    )


@router.delete("/{incident_id}", status_code=204)
async def delete_incident(
    incident_id: UUID,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_admin),
) -> None:
    incident = db.get(Incident, incident_id)
    if incident is None or incident.account_id != current_user.account_id:
        raise HTTPException(status_code=404, detail="Incident not found.")
    log_event(
        db,
        event_type="incident_deleted",
        account_id=current_user.account_id,
        user_id=current_user.id,
        detail={"incident_id": str(incident_id)},
    )
    db.delete(incident)
    db.commit()


@router.post("/{incident_id}/label", response_model=LabelResponse)
async def label_incident(
    incident_id: UUID,
    body: LabelRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> LabelResponse:
    """Record an analyst's verdict on an incident. Append-only — relabeling inserts a new
    row rather than overwriting the previous one, same as app.api.routes.cases.label_case."""
    incident = db.get(Incident, incident_id)
    if incident is None or incident.account_id != current_user.account_id:
        raise HTTPException(status_code=404, detail="Incident not found.")

    label = Label(
        account_id=current_user.account_id,
        incident_id=incident_id,
        analyst_verdict=body.analyst_verdict.value,
        note=body.note,
        labeled_by=current_user.email,
    )
    db.add(label)
    db.commit()
    db.refresh(label)

    return LabelResponse.model_validate(label)
