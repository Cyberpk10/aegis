"""Anomalous location: a successful login from a country the actor's baseline has never
seen before (M5 Stage 2 — UEBA). Distinct signal from impossible_travel: this doesn't need
a second login in the same window to compare against — a first-ever login from a brand-new
country is worth surfacing on its own, once there's enough history to know it's new.
Cold start (no baseline, or too little location history) never fires — a brand-new actor's
first-ever login isn't evidence of anything, and there's no static-threshold equivalent to
fall back to here."""

from __future__ import annotations

from app.baselines.aggregation import BaselineSnapshot, is_known_location
from app.core.config import settings
from app.detections.base import ActorEventWindow, make_finding
from app.models.schemas import Finding, Severity


def evaluate(window: ActorEventWindow, baseline: BaselineSnapshot | None = None) -> list[Finding]:
    if baseline is None or baseline.event_count < settings.baseline_min_events_for_location:
        return []

    novel_logins = [
        e
        for e in window.events
        if e.action == "login"
        and e.outcome == "success"
        and e.geo
        and e.geo.country
        and not is_known_location(baseline, e.geo.country)
    ]
    if not novel_logins:
        return []

    countries = sorted({e.geo.country for e in novel_logins if e.geo and e.geo.country})

    return [
        make_finding(
            id="ANOMALOUS_LOCATION",
            category="access",
            title="Anomalous login location",
            description=(
                f"'{window.actor}' logged in from {', '.join(countries)} — not seen in "
                f"this actor's established location history."
            ),
            severity=Severity.HIGH,
            points=40,
            evidence_event_ids=[e.id for e in novel_logins if e.id is not None],
        )
    ]
