"""Off-hours access: sensitive actions outside the actor's normal hours. Uses the actor's
own behavioral baseline (M5 Stage 2) once enough history exists; falls back to a static
business-hours window (M5 Stage 1 behavior) for actors with too little history to baseline."""

from __future__ import annotations

from app.baselines.aggregation import BaselineSnapshot, is_typical_hour
from app.core.config import settings
from app.detections.base import ActorEventWindow, make_finding
from app.events.schema import ActivityEvent
from app.models.schemas import Finding, Severity

_SENSITIVE_ACTIONS = frozenset(
    {
        "login",
        "file_access",
        "file_download",
        "db_query",
        "privilege_change",
        "config_change",
        "data_transfer",
    }
)


def _is_off_hours_static(event: ActivityEvent) -> bool:
    ts = event.timestamp
    if ts.weekday() >= 5:  # Saturday/Sunday
        return True
    return not (settings.business_hours_start <= ts.hour < settings.business_hours_end)


def _is_off_baseline(event: ActivityEvent, baseline: BaselineSnapshot) -> bool:
    # A baseline doesn't erase "this actor has never worked a weekend before" being worth
    # surfacing — weekends aren't part of the hour-of-day histogram's semantics, so that
    # check stays unconditional even once a baseline is established.
    if event.timestamp.weekday() >= 5:
        return True
    return not is_typical_hour(baseline, event.timestamp.hour)


def evaluate(window: ActorEventWindow, baseline: BaselineSnapshot | None = None) -> list[Finding]:
    use_baseline = (
        baseline is not None and baseline.event_count >= settings.baseline_min_events_for_hours
    )
    is_off = (
        (lambda e: _is_off_baseline(e, baseline)) if use_baseline else _is_off_hours_static
    )

    off_hours_events = [e for e in window.events if e.action in _SENSITIVE_ACTIONS and is_off(e)]
    if not off_hours_events:
        return []

    count = len(off_hours_events)
    severity = Severity.LOW if count < 3 else (Severity.MEDIUM if count < 8 else Severity.HIGH)
    points = min(40, 8 * count)

    if use_baseline:
        description = (
            f"{count} sensitive action(s) by '{window.actor}' outside their established "
            f"activity pattern (hours/days not previously seen)."
        )
    else:
        description = (
            f"{count} sensitive action(s) by '{window.actor}' outside business hours "
            f"({settings.business_hours_start:02d}:00-{settings.business_hours_end:02d}:00 "
            f"UTC, Mon-Fri)."
        )

    return [
        make_finding(
            id="OFF_HOURS_ACCESS",
            category="access",
            title="Off-hours access",
            description=description,
            severity=severity,
            points=points,
            evidence_event_ids=[e.id for e in off_hours_events if e.id is not None],
        )
    ]
