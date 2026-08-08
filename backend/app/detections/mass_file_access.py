"""Mass file access/download: an unusually large volume of file operations relative to the
actor's own baseline (M5 Stage 2) once enough history exists, or a static count/distinct-
target threshold (M5 Stage 1 behavior) as a fallback for actors with too little history.
The distinct-target check is always a static backstop regardless of baseline — touching
many never-seen files is worth flagging independent of daily-volume history."""

from __future__ import annotations

from app.baselines.aggregation import BaselineSnapshot, is_volume_anomalous
from app.core.config import settings
from app.detections.base import ActorEventWindow, make_finding
from app.models.schemas import Finding, Severity

_FILE_ACTIONS = frozenset({"file_access", "file_download"})
_COUNT_THRESHOLD = 20
_DISTINCT_TARGET_THRESHOLD = 10
_HIGH_COUNT_THRESHOLD = 40


def _has_enough_history(baseline: BaselineSnapshot | None) -> bool:
    return (
        baseline is not None
        and baseline.event_count >= settings.baseline_min_events_for_hours
        and len(baseline.daily_volume) >= settings.baseline_min_days_for_volume
    )


def evaluate(window: ActorEventWindow, baseline: BaselineSnapshot | None = None) -> list[Finding]:
    file_events = [e for e in window.events if e.action in _FILE_ACTIONS]
    distinct_targets = {e.target for e in file_events if e.target}
    count = len(file_events)

    use_baseline = _has_enough_history(baseline)
    volume_fired = (
        bool(is_volume_anomalous(baseline, count)) if use_baseline else count >= _COUNT_THRESHOLD
    )
    distinct_fired = len(distinct_targets) >= _DISTINCT_TARGET_THRESHOLD
    if not volume_fired and not distinct_fired:
        return []

    severity = Severity.HIGH if count >= _HIGH_COUNT_THRESHOLD else Severity.MEDIUM
    points = min(50, 10 + count // 2)

    reasons = []
    if volume_fired:
        reasons.append(
            "outside their established daily access volume"
            if use_baseline
            else f"above the static count threshold ({_COUNT_THRESHOLD})"
        )
    if distinct_fired:
        reasons.append(f"at or above {_DISTINCT_TARGET_THRESHOLD} distinct targets")

    return [
        make_finding(
            id="MASS_FILE_ACCESS",
            category="exfiltration",
            title="Mass file access/download",
            description=(
                f"'{window.actor}' accessed {count} files ({len(distinct_targets)} distinct "
                f"targets) within the detection window — {', '.join(reasons)}."
            ),
            severity=severity,
            points=points,
            evidence_event_ids=[e.id for e in file_events if e.id is not None],
        )
    ]
