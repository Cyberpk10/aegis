"""Mass file access/download: an unusually large number of file operations, or an
unusually large number of distinct files/targets touched, within the window."""

from __future__ import annotations

from app.detections.base import ActorEventWindow, make_finding
from app.models.schemas import Finding, Severity

_FILE_ACTIONS = frozenset({"file_access", "file_download"})
_COUNT_THRESHOLD = 20
_DISTINCT_TARGET_THRESHOLD = 10
_HIGH_COUNT_THRESHOLD = 40


def evaluate(window: ActorEventWindow) -> list[Finding]:
    file_events = [e for e in window.events if e.action in _FILE_ACTIONS]
    distinct_targets = {e.target for e in file_events if e.target}

    count = len(file_events)
    if count < _COUNT_THRESHOLD and len(distinct_targets) < _DISTINCT_TARGET_THRESHOLD:
        return []

    severity = Severity.HIGH if count >= _HIGH_COUNT_THRESHOLD else Severity.MEDIUM
    points = min(50, 10 + count // 2)

    return [
        make_finding(
            id="MASS_FILE_ACCESS",
            category="exfiltration",
            title="Mass file access/download",
            description=(
                f"'{window.actor}' accessed {count} files ({len(distinct_targets)} distinct "
                f"targets) within the detection window."
            ),
            severity=severity,
            points=points,
            evidence_event_ids=[e.id for e in file_events if e.id is not None],
        )
    ]
