from __future__ import annotations

from datetime import datetime, timedelta, timezone

from app.detections.base import ActorEventWindow
from app.detections.impossible_travel import evaluate
from app.events.schema import ActivityEvent, EventAction, GeoLocation

_BASE = datetime(2026, 1, 6, 9, 0, tzinfo=timezone.utc)
_NYC = GeoLocation(country="US", lat=40.7128, lon=-74.0060)
_MOSCOW = GeoLocation(country="RU", lat=55.7558, lon=37.6173)


def _login(minutes_offset: int, geo: GeoLocation, outcome: str = "success") -> ActivityEvent:
    return ActivityEvent(
        timestamp=_BASE + timedelta(minutes=minutes_offset),
        actor="bob@corp.com",
        action=EventAction.LOGIN,
        outcome=outcome,
        geo=geo,
    )


def test_fires_on_geographically_impossible_consecutive_logins():
    window = ActorEventWindow(
        actor="bob@corp.com", events=[_login(0, _NYC), _login(30, _MOSCOW)]
    )
    findings = evaluate(window)
    assert len(findings) == 1
    assert findings[0].id == "IMPOSSIBLE_TRAVEL"
    assert findings[0].severity.value == "high"


def test_does_not_fire_for_same_location():
    window = ActorEventWindow(
        actor="bob@corp.com", events=[_login(0, _NYC), _login(45, _NYC)]
    )
    assert evaluate(window) == []


def test_does_not_fire_outside_travel_window():
    # Same distant locations, but 5 hours apart — outside the 3h window, so no longer
    # "impossible" (an actual flight could plausibly cover this).
    window = ActorEventWindow(
        actor="bob@corp.com", events=[_login(0, _NYC), _login(300, _MOSCOW)]
    )
    assert evaluate(window) == []


def test_ignores_failed_logins():
    window = ActorEventWindow(
        actor="bob@corp.com",
        events=[_login(0, _NYC, outcome="failure"), _login(30, _MOSCOW, outcome="failure")],
    )
    assert evaluate(window) == []


def test_ignores_events_missing_geo():
    events = [
        ActivityEvent(
            timestamp=_BASE, actor="bob@corp.com", action=EventAction.LOGIN, outcome="success"
        ),
        _login(30, _MOSCOW),
    ]
    window = ActorEventWindow(actor="bob@corp.com", events=events)
    assert evaluate(window) == []
