from __future__ import annotations

from datetime import datetime, timezone

from app.baselines.aggregation import (
    empty_baseline,
    is_known_location,
    is_typical_hour,
    is_volume_anomalous,
    update_baseline,
)
from app.core.config import settings
from app.events.schema import ActivityEvent, EventAction, GeoLocation


def _event(
    day: int,
    hour: int,
    action: EventAction,
    outcome: str | None = "success",
    country: str | None = None,
    source_ip: str | None = None,
) -> ActivityEvent:
    return ActivityEvent(
        timestamp=datetime(2026, 1, day, hour, 0, tzinfo=timezone.utc),
        actor="alice@corp.com",
        action=action,
        outcome=outcome,
        geo=GeoLocation(country=country) if country else None,
        source_ip=source_ip,
    )


def test_empty_baseline_has_zero_counts():
    baseline = empty_baseline("alice@corp.com")
    assert baseline.event_count == 0
    assert baseline.hour_counts == [0] * 24
    assert baseline.location_counts == {}
    assert baseline.daily_volume == {}


def test_update_baseline_increments_hour_counts_for_sensitive_actions():
    baseline = empty_baseline("alice@corp.com")
    updated = update_baseline(baseline, [_event(6, 9, EventAction.LOGIN)])
    assert updated.hour_counts[9] == 1
    assert updated.event_count == 1


def test_update_baseline_ignores_logout_for_hour_counts():
    baseline = empty_baseline("alice@corp.com")
    updated = update_baseline(baseline, [_event(6, 9, EventAction.LOGOUT)])
    assert updated.hour_counts[9] == 0
    assert updated.event_count == 1  # still counts toward general history


def test_update_baseline_tracks_location_and_ip_for_successful_logins():
    baseline = empty_baseline("alice@corp.com")
    updated = update_baseline(
        baseline, [_event(6, 9, EventAction.LOGIN, country="US", source_ip="203.0.113.5")]
    )
    assert updated.location_counts == {"US": 1}
    assert updated.ip_counts == {"203.0.113.5": 1}


def test_update_baseline_ignores_failed_logins_for_location():
    baseline = empty_baseline("alice@corp.com")
    updated = update_baseline(
        baseline, [_event(6, 9, EventAction.LOGIN, outcome="failure", country="US")]
    )
    assert updated.location_counts == {}


def test_update_baseline_increments_daily_volume_for_file_actions():
    baseline = empty_baseline("alice@corp.com")
    events = [_event(6, 9, EventAction.FILE_ACCESS), _event(6, 10, EventAction.FILE_DOWNLOAD)]
    updated = update_baseline(baseline, events)
    assert updated.daily_volume == {"2026-01-06": 2}


def test_update_baseline_trims_daily_volume_to_rolling_window(monkeypatch):
    monkeypatch.setattr(settings, "baseline_daily_volume_window_days", 3)
    baseline = empty_baseline("alice@corp.com")
    for day in range(1, 6):  # 5 distinct days, window is 3
        baseline = update_baseline(baseline, [_event(day, 9, EventAction.FILE_ACCESS)])
    assert len(baseline.daily_volume) == 3
    assert set(baseline.daily_volume.keys()) == {"2026-01-03", "2026-01-04", "2026-01-05"}


def test_is_typical_hour_respects_min_occurrences_threshold(monkeypatch):
    monkeypatch.setattr(settings, "baseline_min_hour_occurrences", 2)
    baseline = empty_baseline("alice@corp.com")
    baseline = update_baseline(baseline, [_event(6, 9, EventAction.LOGIN)])
    assert is_typical_hour(baseline, 9) is False  # seen once, threshold is 2
    baseline = update_baseline(baseline, [_event(7, 9, EventAction.LOGIN)])
    assert is_typical_hour(baseline, 9) is True


def test_is_known_location_true_only_when_seen():
    baseline = empty_baseline("alice@corp.com")
    baseline = update_baseline(baseline, [_event(6, 9, EventAction.LOGIN, country="US")])
    assert is_known_location(baseline, "US") is True
    assert is_known_location(baseline, "RU") is False


def test_is_volume_anomalous_returns_none_under_cold_start(monkeypatch):
    monkeypatch.setattr(settings, "baseline_min_days_for_volume", 5)
    baseline = empty_baseline("alice@corp.com")
    baseline = update_baseline(baseline, [_event(6, 9, EventAction.FILE_ACCESS)])
    assert is_volume_anomalous(baseline, 100) is None


def test_is_volume_anomalous_fires_above_mean_plus_stddev(monkeypatch):
    monkeypatch.setattr(settings, "baseline_min_days_for_volume", 3)
    monkeypatch.setattr(settings, "baseline_volume_stddev_multiplier", 2.0)
    baseline = empty_baseline("alice@corp.com")
    # Establish a consistent baseline of 3 file-access events/day for 5 days.
    for day in range(1, 6):
        events = [_event(day, 9, EventAction.FILE_ACCESS) for _ in range(3)]
        baseline = update_baseline(baseline, events)
    assert is_volume_anomalous(baseline, 3) is False  # matches established pattern
    assert is_volume_anomalous(baseline, 50) is True  # wildly outside established pattern
