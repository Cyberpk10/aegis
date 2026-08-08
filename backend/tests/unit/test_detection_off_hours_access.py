from __future__ import annotations

from datetime import datetime, timezone

from app.baselines.aggregation import empty_baseline, update_baseline
from app.core.config import settings
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


def _night_shift_baseline(monkeypatch, min_occurrences: int = 2):
    """A baseline where hour 2 has been established as the actor's normal login hour
    (e.g. a night-shift analyst) — established across several distinct weekdays so the
    weekend rule doesn't interfere."""
    monkeypatch.setattr(settings, "baseline_min_hour_occurrences", min_occurrences)
    monkeypatch.setattr(settings, "baseline_min_events_for_hours", 3)
    baseline = empty_baseline("carol@corp.com")
    for day in (5, 6, 7, 8):  # Mon-Thu 2026-01-05..08
        baseline = update_baseline(
            baseline, [_event(2, EventAction.FILE_ACCESS, day=day)]
        )
    return baseline


def test_baseline_does_not_fire_for_an_hour_within_the_established_pattern(monkeypatch):
    baseline = _night_shift_baseline(monkeypatch)
    window = ActorEventWindow(actor="carol@corp.com", events=[_event(2, EventAction.FILE_ACCESS)])
    assert evaluate(window, baseline) == []


def test_baseline_fires_for_an_hour_outside_the_established_pattern(monkeypatch):
    baseline = _night_shift_baseline(monkeypatch)
    # Hour 14 was never seen in the baseline, even though it's within Stage 1's static
    # business hours — baseline overrides the static window once established.
    window = ActorEventWindow(actor="carol@corp.com", events=[_event(14, EventAction.FILE_ACCESS)])
    findings = evaluate(window, baseline)
    assert len(findings) == 1
    assert "established" in findings[0].description.lower()


def test_cold_start_baseline_falls_back_to_static_business_hours(monkeypatch):
    baseline = _night_shift_baseline(monkeypatch)  # 4 events
    monkeypatch.setattr(settings, "baseline_min_events_for_hours", 100)  # never enough history
    # 2am is within the "established" night-shift pattern, but the baseline isn't trusted
    # yet — falls back to Stage 1 static business hours, which flags 2am as off-hours.
    window = ActorEventWindow(actor="carol@corp.com", events=[_event(2, EventAction.FILE_ACCESS)])
    findings = evaluate(window, baseline)
    assert len(findings) == 1
    assert "business hours" in findings[0].description.lower()
