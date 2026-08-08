"""Brute force / password spray detection: a burst of auth_fail events for one actor in
a short sliding window."""

from __future__ import annotations

from datetime import timedelta

from app.baselines.aggregation import BaselineSnapshot
from app.detections.base import ActorEventWindow, make_finding
from app.events.schema import ActivityEvent
from app.models.schemas import Finding, Severity

_SUB_WINDOW = timedelta(minutes=15)
_FIRE_THRESHOLD = 5
_HIGH_THRESHOLD = 10


def _max_auth_fail_burst(events: list[ActivityEvent]) -> list[ActivityEvent]:
    """Returns the largest set of auth_fail events that all fall within any 15-minute
    sliding window, using a simple two-pointer scan over timestamp-sorted events."""
    fails = sorted(
        (e for e in events if e.action == "auth_fail"), key=lambda e: e.timestamp
    )
    best: list[ActivityEvent] = []
    left = 0
    for right in range(len(fails)):
        while fails[right].timestamp - fails[left].timestamp > _SUB_WINDOW:
            left += 1
        window = fails[left : right + 1]
        if len(window) > len(best):
            best = window
    return best


def evaluate(window: ActorEventWindow, baseline: BaselineSnapshot | None = None) -> list[Finding]:
    # Doesn't use behavioral baselines — a burst of auth failures is suspicious regardless
    # of the actor's history. Accepts the parameter only for a uniform engine signature.
    burst = _max_auth_fail_burst(window.events)
    if len(burst) < _FIRE_THRESHOLD:
        return []

    burst_end = burst[-1].timestamp
    followed_by_success = any(
        e.action == "login" and e.outcome == "success" and e.timestamp >= burst_end
        for e in window.events
    )

    severity = Severity.HIGH if len(burst) >= _HIGH_THRESHOLD or followed_by_success else Severity.MEDIUM
    points = min(60, 15 + 3 * (len(burst) - _FIRE_THRESHOLD) + (20 if followed_by_success else 0))

    description = (
        f"{len(burst)} failed authentication attempts for '{window.actor}' within a "
        f"15-minute window."
    )
    if followed_by_success:
        description += " A successful login followed the failure burst."

    return [
        make_finding(
            id="BRUTE_FORCE_PASSWORD_SPRAY",
            category="access",
            title="Brute force / password spray",
            description=description,
            severity=severity,
            points=points,
            evidence_event_ids=[e.id for e in burst if e.id is not None],
        )
    ]
