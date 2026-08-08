from __future__ import annotations

from app.db.models import ActorBaseline


def _iso(day: int, hour: int, minute: int = 0) -> str:
    return f"2026-01-{day:02d}T{hour:02d}:{minute:02d}:00Z"


def _establishing_batch(actor: str, country: str = "US") -> list[dict]:
    """5 weekdays (2026-01-05..09, Mon-Fri) of a consistent pattern: one login and one
    file_access at hour 10 each day, same country/IP — enough to clear every M5 Stage 2
    default cold-start gate (min_events_for_hours=5, min_events_for_location=5,
    min_days_for_volume=5)."""
    events = []
    for day in (5, 6, 7, 8, 9):
        events.append(
            {
                "timestamp": _iso(day, 10, 0),
                "actor": actor,
                "action": "login",
                "outcome": "success",
                "source_ip": "198.51.100.10",
                "geo": {"country": country},
            }
        )
        events.append(
            {
                "timestamp": _iso(day, 10, 5),
                "actor": actor,
                "action": "file_access",
                "outcome": "success",
                "target": f"shared/report-{day}.pdf",
            }
        )
    return events


def test_establishing_batch_creates_no_incident_and_builds_baseline(client, db_session):
    response = client.post(
        "/api/events", json={"events": _establishing_batch("erin@corp.com")}
    )

    assert response.status_code == 200
    body = response.json()
    assert body["accepted"] == 10
    assert body["incidents_created"] == []

    baseline = (
        db_session.query(ActorBaseline).filter(ActorBaseline.actor == "erin@corp.com").first()
    )
    assert baseline is not None
    assert baseline.event_count == 10
    assert baseline.hour_counts[10] == 10
    assert baseline.location_counts == {"US": 5}
    assert len(baseline.daily_volume) == 5


def test_pattern_breaking_login_fires_anomalous_location_after_baseline_established(
    client, db_session
):
    establish = client.post(
        "/api/events", json={"events": _establishing_batch("frank@corp.com")}
    )
    assert establish.json()["incidents_created"] == []

    baseline_before = (
        db_session.query(ActorBaseline).filter(ActorBaseline.actor == "frank@corp.com").first()
    )
    assert baseline_before.event_count == 10

    # 2026-01-12 is the following Monday — same hour as the established pattern, but a
    # country never seen in frank's baseline.
    breaking = client.post(
        "/api/events",
        json={
            "events": [
                {
                    "timestamp": _iso(12, 10, 0),
                    "actor": "frank@corp.com",
                    "action": "login",
                    "outcome": "success",
                    "source_ip": "203.0.113.99",
                    "geo": {"country": "RU"},
                }
            ]
        },
    )

    assert breaking.status_code == 200
    incidents = breaking.json()["incidents_created"]
    assert len(incidents) == 1
    assert "ANOMALOUS_LOCATION" in incidents[0]["detection_types"]

    detail = client.get(f"/api/incidents/{incidents[0]['id']}")
    finding_ids = {f["id"] for f in detail.json()["findings"]}
    assert "ANOMALOUS_LOCATION" in finding_ids
    # Established hour (10) on a weekday is within frank's baseline pattern — off-hours
    # should NOT also fire alongside the location anomaly.
    assert "OFF_HOURS_ACCESS" not in finding_ids

    # The baseline itself advanced from the pattern-breaking request too — RU is now known.
    # expire_all() forces a fresh SELECT rather than returning the identity-map-cached
    # (now-stale) object from the query above.
    db_session.expire_all()
    baseline_after = (
        db_session.query(ActorBaseline).filter(ActorBaseline.actor == "frank@corp.com").first()
    )
    assert baseline_after.event_count == 11
    assert baseline_after.location_counts["RU"] == 1


def test_pattern_consistent_login_does_not_fire_after_baseline_established(client, db_session):
    establish = client.post(
        "/api/events", json={"events": _establishing_batch("grace@corp.com")}
    )
    assert establish.json()["incidents_created"] == []

    # Same hour, same country, same following Monday — matches the established pattern.
    consistent = client.post(
        "/api/events",
        json={
            "events": [
                {
                    "timestamp": _iso(12, 10, 0),
                    "actor": "grace@corp.com",
                    "action": "login",
                    "outcome": "success",
                    "source_ip": "198.51.100.10",
                    "geo": {"country": "US"},
                }
            ]
        },
    )

    assert consistent.status_code == 200
    assert consistent.json()["incidents_created"] == []
