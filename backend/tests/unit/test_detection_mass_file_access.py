from __future__ import annotations

from datetime import datetime, timedelta, timezone

from app.detections.base import ActorEventWindow
from app.detections.mass_file_access import evaluate
from app.events.schema import ActivityEvent, EventAction

_BASE = datetime(2026, 1, 6, 14, 0, tzinfo=timezone.utc)


def _events(count: int, distinct_targets: bool = True) -> list[ActivityEvent]:
    return [
        ActivityEvent(
            timestamp=_BASE + timedelta(minutes=i),
            actor="dave@corp.com",
            action=EventAction.FILE_ACCESS,
            target=f"doc-{i}.pdf" if distinct_targets else "doc-shared.pdf",
            outcome="success",
        )
        for i in range(count)
    ]


def test_fires_at_count_threshold():
    window = ActorEventWindow(actor="dave@corp.com", events=_events(20))
    findings = evaluate(window)
    assert len(findings) == 1
    assert findings[0].id == "MASS_FILE_ACCESS"


def test_does_not_fire_below_threshold():
    window = ActorEventWindow(actor="dave@corp.com", events=_events(5))
    assert evaluate(window) == []


def test_fires_on_distinct_target_threshold_even_below_count_threshold():
    window = ActorEventWindow(actor="dave@corp.com", events=_events(10))
    assert len(evaluate(window)) == 1


def test_repeated_access_to_one_target_does_not_fire_via_target_count():
    window = ActorEventWindow(actor="dave@corp.com", events=_events(9, distinct_targets=False))
    assert evaluate(window) == []


def test_severity_high_above_high_threshold():
    window = ActorEventWindow(actor="dave@corp.com", events=_events(40))
    assert evaluate(window)[0].severity.value == "high"
