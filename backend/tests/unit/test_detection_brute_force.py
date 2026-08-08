from __future__ import annotations

from datetime import datetime, timedelta, timezone

from app.detections.base import ActorEventWindow
from app.detections.brute_force import evaluate
from app.events.schema import ActivityEvent, EventAction

_BASE = datetime(2026, 1, 6, 10, 0, tzinfo=timezone.utc)


def _event(minute_offset: int, action: EventAction, outcome: str | None = "failure") -> ActivityEvent:
    return ActivityEvent(
        timestamp=_BASE + timedelta(minutes=minute_offset),
        actor="alice@corp.com",
        action=action,
        outcome=outcome,
    )


def test_fires_at_five_failures_within_fifteen_minutes():
    events = [_event(i, EventAction.AUTH_FAIL) for i in range(5)]
    window = ActorEventWindow(actor="alice@corp.com", events=events)

    findings = evaluate(window)

    assert len(findings) == 1
    assert findings[0].id == "BRUTE_FORCE_PASSWORD_SPRAY"
    assert findings[0].severity.value == "medium"


def test_does_not_fire_below_threshold():
    events = [_event(i, EventAction.AUTH_FAIL) for i in range(4)]
    window = ActorEventWindow(actor="alice@corp.com", events=events)

    assert evaluate(window) == []


def test_does_not_fire_when_failures_spread_beyond_subwindow():
    events = [_event(i * 20, EventAction.AUTH_FAIL) for i in range(5)]
    window = ActorEventWindow(actor="alice@corp.com", events=events)

    assert evaluate(window) == []


def test_severity_escalates_and_points_increase_with_more_failures():
    small = ActorEventWindow(
        actor="alice@corp.com", events=[_event(i, EventAction.AUTH_FAIL) for i in range(5)]
    )
    large = ActorEventWindow(
        actor="alice@corp.com", events=[_event(i, EventAction.AUTH_FAIL) for i in range(10)]
    )

    small_finding = evaluate(small)[0]
    large_finding = evaluate(large)[0]

    assert large_finding.points > small_finding.points
    assert large_finding.severity.value == "high"


def test_followed_by_successful_login_bumps_severity_to_high():
    events = [_event(i, EventAction.AUTH_FAIL) for i in range(5)]
    events.append(_event(6, EventAction.LOGIN, outcome="success"))
    window = ActorEventWindow(actor="alice@corp.com", events=events)

    finding = evaluate(window)[0]
    assert finding.severity.value == "high"
    assert "successful login" in finding.description.lower()
