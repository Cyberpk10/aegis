"""Pure aggregation math for per-actor behavioral baselines (M5 Stage 2 — UEBA) — no
DB/SQLAlchemy here, same separation as app.dashboard.aggregation / app.risk_model.aggregation.
BaselineSnapshot is a DB-free read view of app.db.models.ActorBaseline; update_baseline is
the pure function that folds newly-ingested events into a snapshot, which the route layer
then persists.
"""

from __future__ import annotations

import statistics
from dataclasses import dataclass, field

from app.core.config import settings
from app.events.schema import ActivityEvent

# Mirrors app.detections.off_hours_access._SENSITIVE_ACTIONS — kept as an independent
# constant (not imported) so app.baselines never depends on app.detections, only the
# other way around. Update both together if the sensitive-action set ever changes.
_HOUR_TRACKED_ACTIONS = frozenset(
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
# Mirrors app.detections.mass_file_access._FILE_ACTIONS.
_VOLUME_TRACKED_ACTIONS = frozenset({"file_access", "file_download"})


@dataclass(frozen=True)
class BaselineSnapshot:
    actor: str
    hour_counts: list[int] = field(default_factory=lambda: [0] * 24)
    location_counts: dict[str, int] = field(default_factory=dict)
    ip_counts: dict[str, int] = field(default_factory=dict)
    daily_volume: dict[str, int] = field(default_factory=dict)
    event_count: int = 0


def empty_baseline(actor: str) -> BaselineSnapshot:
    """A fresh baseline for an actor with no prior history — the cold-start starting point."""
    return BaselineSnapshot(actor=actor)


def _trim_daily_volume(daily_volume: dict[str, int], window_days: int) -> dict[str, int]:
    if len(daily_volume) <= window_days:
        return dict(daily_volume)
    kept_dates = sorted(daily_volume.keys())[-window_days:]
    return {d: daily_volume[d] for d in kept_dates}


def update_baseline(existing: BaselineSnapshot, new_events: list[ActivityEvent]) -> BaselineSnapshot:
    """Pure function: folds new_events into existing, returning a new snapshot. Never
    called with events already reflected in `existing` — the caller (app.api.routes.events)
    is responsible for only passing the just-ingested batch, not the full detection window,
    to avoid double-counting."""
    hour_counts = list(existing.hour_counts)
    location_counts = dict(existing.location_counts)
    ip_counts = dict(existing.ip_counts)
    daily_volume = dict(existing.daily_volume)
    event_count = existing.event_count

    for event in new_events:
        event_count += 1

        if event.action in _HOUR_TRACKED_ACTIONS:
            hour_counts[event.timestamp.hour] += 1

        if event.action == "login" and event.outcome == "success":
            if event.geo and event.geo.country:
                location_counts[event.geo.country] = location_counts.get(event.geo.country, 0) + 1
            if event.source_ip:
                ip_counts[event.source_ip] = ip_counts.get(event.source_ip, 0) + 1

        if event.action in _VOLUME_TRACKED_ACTIONS:
            day_key = event.timestamp.date().isoformat()
            daily_volume[day_key] = daily_volume.get(day_key, 0) + 1

    daily_volume = _trim_daily_volume(daily_volume, settings.baseline_daily_volume_window_days)

    return BaselineSnapshot(
        actor=existing.actor,
        hour_counts=hour_counts,
        location_counts=location_counts,
        ip_counts=ip_counts,
        daily_volume=daily_volume,
        event_count=event_count,
    )


def is_typical_hour(snapshot: BaselineSnapshot, hour: int) -> bool:
    return snapshot.hour_counts[hour] >= settings.baseline_min_hour_occurrences


def is_known_location(snapshot: BaselineSnapshot, country: str) -> bool:
    return snapshot.location_counts.get(country, 0) > 0


def is_volume_anomalous(snapshot: BaselineSnapshot, current_count: int) -> bool | None:
    """None means "not enough history to judge" (cold start) — callers must fall back to
    a static threshold in that case, never treat None as either true or false."""
    if len(snapshot.daily_volume) < settings.baseline_min_days_for_volume:
        return None

    values = list(snapshot.daily_volume.values())
    mean = statistics.fmean(values)
    stdev = statistics.pstdev(values) if len(values) > 1 else 0.0
    threshold = mean + settings.baseline_volume_stddev_multiplier * stdev
    return current_count > threshold
