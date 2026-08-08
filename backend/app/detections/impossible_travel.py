"""Impossible travel: two successful logins for the same actor, from different
locations, closer together in time than physical travel between them would allow."""

from __future__ import annotations

import math
from datetime import timedelta

from app.baselines.aggregation import BaselineSnapshot
from app.detections.base import ActorEventWindow, make_finding
from app.models.schemas import Finding, Severity

_TRAVEL_WINDOW = timedelta(hours=3)
# Comfortably above commercial-flight cruise speed (~900 km/h) so genuine business travel
# (which also includes ground transit/boarding time, not just cruise time) never misfires.
_MAX_PLAUSIBLE_SPEED_KMH = 1000.0
_EARTH_RADIUS_KM = 6371.0


def _haversine_km(lat1: float, lon1: float, lat2: float, lon2: float) -> float:
    phi1, phi2 = math.radians(lat1), math.radians(lat2)
    d_phi = math.radians(lat2 - lat1)
    d_lambda = math.radians(lon2 - lon1)
    a = math.sin(d_phi / 2) ** 2 + math.cos(phi1) * math.cos(phi2) * math.sin(d_lambda / 2) ** 2
    return 2 * _EARTH_RADIUS_KM * math.asin(min(1.0, math.sqrt(a)))


def evaluate(window: ActorEventWindow, baseline: BaselineSnapshot | None = None) -> list[Finding]:
    # Doesn't use behavioral baselines — its threshold (physically implausible travel
    # speed) is a physics constant, not an arbitrary business rule, so there's nothing to
    # baseline here. Accepts the parameter only for a uniform engine signature.
    logins = sorted(
        (
            e
            for e in window.events
            if e.action == "login" and e.outcome == "success" and e.geo is not None
            and e.geo.lat is not None and e.geo.lon is not None
        ),
        key=lambda e: e.timestamp,
    )

    findings: list[Finding] = []
    for prev, curr in zip(logins, logins[1:]):
        delta = curr.timestamp - prev.timestamp
        if delta <= timedelta(0) or delta > _TRAVEL_WINDOW:
            continue
        distance_km = _haversine_km(prev.geo.lat, prev.geo.lon, curr.geo.lat, curr.geo.lon)
        hours = delta.total_seconds() / 3600
        implied_speed = distance_km / hours if hours > 0 else float("inf")
        if implied_speed <= _MAX_PLAUSIBLE_SPEED_KMH:
            continue

        findings.append(
            make_finding(
                id="IMPOSSIBLE_TRAVEL",
                category="access",
                title="Impossible travel",
                description=(
                    f"'{window.actor}' logged in from two locations {distance_km:.0f} km "
                    f"apart within {hours:.2f}h — an implied speed of "
                    f"{implied_speed:.0f} km/h, exceeding plausible travel."
                ),
                severity=Severity.HIGH,
                points=45,
                evidence_event_ids=[e.id for e in (prev, curr) if e.id is not None],
            )
        )

    return findings
