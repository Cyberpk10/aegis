"""Off-hours access: sensitive actions outside a static business-hours window (Stage 1 —
no per-org calendar/timezone learning yet, just a configured UTC window, Mon-Fri)."""

from __future__ import annotations

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


def _is_off_hours(event: ActivityEvent) -> bool:
    ts = event.timestamp
    if ts.weekday() >= 5:  # Saturday/Sunday
        return True
    return not (settings.business_hours_start <= ts.hour < settings.business_hours_end)


def evaluate(window: ActorEventWindow) -> list[Finding]:
    off_hours_events = [
        e for e in window.events if e.action in _SENSITIVE_ACTIONS and _is_off_hours(e)
    ]
    if not off_hours_events:
        return []

    count = len(off_hours_events)
    severity = Severity.LOW if count < 3 else (Severity.MEDIUM if count < 8 else Severity.HIGH)
    points = min(40, 8 * count)

    return [
        make_finding(
            id="OFF_HOURS_ACCESS",
            category="access",
            title="Off-hours access",
            description=(
                f"{count} sensitive action(s) by '{window.actor}' outside business hours "
                f"({settings.business_hours_start:02d}:00-{settings.business_hours_end:02d}:00 "
                f"UTC, Mon-Fri)."
            ),
            severity=severity,
            points=points,
            evidence_event_ids=[e.id for e in off_hours_events if e.id is not None],
        )
    ]
