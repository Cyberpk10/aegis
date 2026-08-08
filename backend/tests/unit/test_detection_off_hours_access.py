from __future__ import annotations

from datetime import datetime, timezone

from app.detections.base import ActorEventWindow
from app.detections.off_hours_access import evaluate
from app.events.schema import ActivityEvent, EventAction


def _event(hour: int, action: EventAction, day: int = 6) -> ActivityEvent:
    # 2026-01-06 is a Tuesday (weekday); 2026-01-10 is a Saturday.
    return ActivityEvent(
        timestamp=datetime(2026, 1, day, hour, 0, tzinfo=timezone.utc),
        actor="carol@corp.com",
        action=action,
        outcome="success",
    )


def test_fires_for_action_before_business_hours_on_a_weekday():
    window = ActorEventWindow(actor="carol@corp.com", events=[_event(2, EventAction.FILE_ACCESS)])
    findings = evaluate(window)
    assert len(findings) == 1
    assert findings[0].id == "OFF_HOURS_ACCESS"
    assert findings[0].severity.value == "low"


def test_fires_for_action_on_a_weekend_even_during_daytime_hours():
    window = ActorEventWindow(
        actor="carol@corp.com", events=[_event(14, EventAction.FILE_ACCESS, day=10)]
    )
    assert len(evaluate(window)) == 1


def test_does_not_fire_during_business_hours_on_a_weekday():
    window = ActorEventWindow(actor="carol@corp.com", events=[_event(14, EventAction.FILE_ACCESS)])
    assert evaluate(window) == []


def test_ignores_non_sensitive_actions():
    window = ActorEventWindow(actor="carol@corp.com", events=[_event(2, EventAction.LOGOUT)])
    assert evaluate(window) == []


def test_severity_scales_with_count():
    few = ActorEventWindow(
        actor="carol@corp.com", events=[_event(2, EventAction.FILE_ACCESS)]
    )
    many = ActorEventWindow(
        actor="carol@corp.com",
        events=[_event(2, EventAction.FILE_ACCESS) for _ in range(10)],
    )
    assert evaluate(few)[0].severity.value == "low"
    assert evaluate(many)[0].severity.value == "high"
