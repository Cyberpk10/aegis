from __future__ import annotations

from datetime import datetime, timedelta, timezone

from app.baselines.aggregation import empty_baseline, update_baseline
from app.core.config import settings
from app.detections.base import ActorEventWindow
from app.detections.mass_file_access import evaluate
from app.events.schema import ActivityEvent, EventAction

_BASE = datetime(2026, 1, 6, 14, 0, tzinfo=timezone.utc)


def _events(
    count: int, distinct_targets: bool = True, day: int = 6
) -> list[ActivityEvent]:
    base = _BASE.replace(day=day)
    return [
        ActivityEvent(
            timestamp=base + timedelta(minutes=i),
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


def _low_volume_baseline(monkeypatch, daily_count: int = 3, days: int = 5):
    monkeypatch.setattr(settings, "baseline_min_days_for_volume", days)
    monkeypatch.setattr(settings, "baseline_min_events_for_hours", 1)
    monkeypatch.setattr(settings, "baseline_volume_stddev_multiplier", 2.0)
    baseline = empty_baseline("dave@corp.com")
    for day in range(1, days + 1):
        baseline = update_baseline(
            baseline, _events(daily_count, distinct_targets=False, day=day)
        )
    return baseline


def test_baseline_fires_below_static_threshold_when_above_established_pattern(monkeypatch):
    baseline = _low_volume_baseline(monkeypatch, daily_count=3)
    # 12 same-target events: below the Stage 1 static count threshold (20) and below the
    # distinct-target threshold (10), but well above this actor's established ~3/day.
    window = ActorEventWindow(
        actor="dave@corp.com", events=_events(12, distinct_targets=False, day=10)
    )
    findings = evaluate(window, baseline)
    assert len(findings) == 1
    assert "established" in findings[0].description.lower()


def test_baseline_does_not_fire_within_established_pattern(monkeypatch):
    baseline = _low_volume_baseline(monkeypatch, daily_count=15)
    window = ActorEventWindow(
        actor="dave@corp.com", events=_events(15, distinct_targets=False, day=10)
    )
    assert evaluate(window, baseline) == []


def test_cold_start_baseline_falls_back_to_static_thresholds(monkeypatch):
    baseline = _low_volume_baseline(monkeypatch, daily_count=3, days=2)  # under the gate
    monkeypatch.setattr(settings, "baseline_min_days_for_volume", 5)  # 2 < 5, cold start
    window = ActorEventWindow(
        actor="dave@corp.com", events=_events(12, distinct_targets=False, day=10)
    )
    # 12 is below the Stage 1 static count threshold (20) — falls back to static behavior
    # and does not fire, even though it's well above the (untrusted) baseline pattern.
    assert evaluate(window, baseline) == []
