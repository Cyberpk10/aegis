from __future__ import annotations

from datetime import datetime, timezone

from app.baselines.aggregation import empty_baseline, update_baseline
from app.core.config import settings
from app.detections.anomalous_location import evaluate
from app.detections.base import ActorEventWindow
from app.events.schema import ActivityEvent, EventAction, GeoLocation


def _login(day: int, country: str, outcome: str = "success") -> ActivityEvent:
    return ActivityEvent(
        timestamp=datetime(2026, 1, day, 9, 0, tzinfo=timezone.utc),
        actor="bob@corp.com",
        action=EventAction.LOGIN,
        outcome=outcome,
        geo=GeoLocation(country=country),
    )


def _established_baseline(monkeypatch, min_events: int = 3):
    monkeypatch.setattr(settings, "baseline_min_events_for_location", min_events)
    baseline = empty_baseline("bob@corp.com")
    for day in (5, 6, 7):
        baseline = update_baseline(baseline, [_login(day, "US")])
    return baseline


def test_does_not_fire_for_a_known_location(monkeypatch):
    baseline = _established_baseline(monkeypatch)
    window = ActorEventWindow(actor="bob@corp.com", events=[_login(10, "US")])
    assert evaluate(window, baseline) == []


def test_fires_for_a_never_seen_location(monkeypatch):
    baseline = _established_baseline(monkeypatch)
    window = ActorEventWindow(actor="bob@corp.com", events=[_login(10, "RU")])
    findings = evaluate(window, baseline)
    assert len(findings) == 1
    assert findings[0].id == "ANOMALOUS_LOCATION"
    assert "RU" in findings[0].description


def test_cold_start_no_baseline_never_fires():
    window = ActorEventWindow(actor="bob@corp.com", events=[_login(10, "RU")])
    assert evaluate(window, None) == []


def test_cold_start_insufficient_history_never_fires(monkeypatch):
    baseline = _established_baseline(monkeypatch)  # 3 events
    monkeypatch.setattr(settings, "baseline_min_events_for_location", 100)  # never enough
    window = ActorEventWindow(actor="bob@corp.com", events=[_login(10, "RU")])
    assert evaluate(window, baseline) == []


def test_ignores_failed_logins():
    baseline = empty_baseline("bob@corp.com")
    window = ActorEventWindow(
        actor="bob@corp.com", events=[_login(10, "RU", outcome="failure")]
    )
    assert evaluate(window, baseline) == []
