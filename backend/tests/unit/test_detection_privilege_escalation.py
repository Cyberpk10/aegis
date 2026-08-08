from __future__ import annotations

from datetime import datetime, timedelta, timezone

from app.detections.base import ActorEventWindow
from app.detections.privilege_escalation import evaluate
from app.events.schema import ActivityEvent, EventAction

_BASE = datetime(2026, 1, 6, 14, 0, tzinfo=timezone.utc)


def _priv_change(minute_offset: int = 0) -> ActivityEvent:
    return ActivityEvent(
        timestamp=_BASE + timedelta(minutes=minute_offset),
        actor="grace@corp.com",
        action=EventAction.PRIVILEGE_CHANGE,
        target="grace@corp.com -> admin",
        outcome="success",
    )


def _auth_fail(minute_offset: int) -> ActivityEvent:
    return ActivityEvent(
        timestamp=_BASE + timedelta(minutes=minute_offset),
        actor="grace@corp.com",
        action=EventAction.AUTH_FAIL,
        outcome="failure",
    )


def test_fires_on_any_privilege_change():
    window = ActorEventWindow(actor="grace@corp.com", events=[_priv_change()])
    findings = evaluate(window)
    assert len(findings) == 1
    assert findings[0].id == "PRIVILEGE_ESCALATION"
    assert findings[0].severity.value == "medium"


def test_does_not_fire_without_a_privilege_change():
    window = ActorEventWindow(
        actor="grace@corp.com",
        events=[
            ActivityEvent(
                timestamp=_BASE, actor="grace@corp.com", action=EventAction.LOGIN, outcome="success"
            )
        ],
    )
    assert evaluate(window) == []


def test_severity_bumps_to_high_when_preceded_by_auth_failures():
    window = ActorEventWindow(
        actor="grace@corp.com", events=[_auth_fail(-10), _auth_fail(-5), _priv_change()]
    )
    finding = evaluate(window)[0]
    assert finding.severity.value == "high"
    assert finding.points == 40
    assert "possible compromised-account" in finding.description.lower()


def test_auth_failures_after_the_privilege_change_do_not_count_as_chained():
    window = ActorEventWindow(
        actor="grace@corp.com", events=[_priv_change(), _auth_fail(5)]
    )
    finding = evaluate(window)[0]
    assert finding.severity.value == "medium"
