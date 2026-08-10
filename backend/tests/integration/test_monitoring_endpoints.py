"""Integration tests for M7 Stage A (Continuous Control Monitoring).

Case.created_at / Incident.created_at are server-generated (server_default=func.now())
and not client-settable through any existing endpoint, so — unlike most integration
tests in this suite, which seed through the API — these tests insert Case/Incident rows
directly via the `db_session` fixture with explicit timestamps, then drive the actual
GET endpoints through the `client` fixture. Timestamps are relative offsets from
`datetime.now(timezone.utc)` computed at test-run time (the route itself has no
injectable `now`, same as app.api.routes.dashboard), so relative ages stay correct
regardless of when the suite runs — nothing here depends on a fixed wall-clock instant.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from app.db.models import Case, Incident
from app.mapping import framework_mapper


def _days_ago(days: int) -> datetime:
    return datetime.now(timezone.utc) - timedelta(days=days)


def _pick_real_control(framework_key: str) -> tuple[str, str]:
    framework = framework_mapper.get_framework(framework_key)
    assert framework is not None
    control_id, control = next(iter(framework.controls_by_id.items()))
    return control_id, control["name"]


def _mapping_for(control_id: str, control_name: str, indicator_id: str) -> dict:
    return {
        "nist_csf": [
            {
                "indicator_id": indicator_id,
                "control_id": control_id,
                "control_name": control_name,
                "url": None,
            }
        ]
    }


def test_controls_endpoint_reports_operating_for_recent_evidence(client, db_session):
    control_id, control_name = _pick_real_control("nist_csf")
    case = Case(
        created_at=_days_ago(2),
        filename="phish.eml",
        verdict="malicious",
        score=90,
        indicators=[],
        framework_mappings=_mapping_for(control_id, control_name, "LOOKALIKE_DOMAIN"),
    )
    db_session.add(case)
    db_session.commit()

    response = client.get("/api/monitoring/controls", params={"framework": "nist_csf"})
    assert response.status_code == 200
    items = response.json()["items"]

    seeded = next(c for c in items if c["control_id"] == control_id)
    assert seeded["status"] == "operating"
    assert seeded["evidence_count"] == 1

    # A control never referenced by any evidence still appears (full control universe),
    # just as no_evidence rather than being omitted.
    untouched = next(c for c in items if c["control_id"] != control_id)
    assert untouched["status"] == "no_evidence"
    assert untouched["evidence_count"] == 0


def test_stale_control_reads_stale_and_raises_a_went_quiet_drift_alert(client, db_session):
    control_id, control_name = _pick_real_control("nist_csf")
    # 60 days old: within the 180-day lookback window, but well past the
    # default 14-day interval * 3.0 stale multiplier (42 days) boundary.
    incident = Incident(
        created_at=_days_ago(60),
        title="Mass file access",
        actor="alice@corp.com",
        verdict="malicious",
        score=70,
        detection_types=["MASS_FILE_ACCESS"],
        findings=[],
        framework_mappings=_mapping_for(control_id, control_name, "MASS_FILE_ACCESS"),
        window_start=_days_ago(60),
        window_end=_days_ago(60),
    )
    db_session.add(incident)
    db_session.commit()

    controls_response = client.get("/api/monitoring/controls", params={"framework": "nist_csf"})
    assert controls_response.status_code == 200
    seeded = next(
        c for c in controls_response.json()["items"] if c["control_id"] == control_id
    )
    assert seeded["status"] == "stale"

    drift_response = client.get("/api/monitoring/drift")
    assert drift_response.status_code == 200
    alerts = drift_response.json()["items"]
    matching = [a for a in alerts if a["control_id"] == control_id and a["type"] == "went_quiet"]
    assert len(matching) == 1
    assert matching[0]["severity"] == "high"


def test_drift_endpoint_flags_a_falling_auth_pass_rate(client, db_session):
    # Prior window (14-28 days ago): mostly passing DMARC.
    for i in range(10):
        db_session.add(
            Case(
                created_at=_days_ago(15 + i),
                filename=f"prior-{i}.eml",
                verdict="safe",
                score=5,
                indicators=(
                    [{"id": "AUTH_DMARC_FAIL", "category": "auth", "title": "x",
                      "description": "x", "evidence": [], "severity": "high", "score": 15}]
                    if i == 0
                    else []
                ),
                framework_mappings={},
            )
        )
    # Recent window (last 14 days): mostly failing DMARC.
    for i in range(10):
        db_session.add(
            Case(
                created_at=_days_ago(i),
                filename=f"recent-{i}.eml",
                verdict="malicious",
                score=80,
                indicators=(
                    [{"id": "AUTH_DMARC_FAIL", "category": "auth", "title": "x",
                      "description": "x", "evidence": [], "severity": "high", "score": 15}]
                    if i < 7
                    else []
                ),
                framework_mappings={},
            )
        )
    db_session.commit()

    response = client.get("/api/monitoring/drift")
    assert response.status_code == 200
    alerts = response.json()["items"]
    auth_alerts = [a for a in alerts if a["type"] == "auth_pass_rate_drop"]
    assert auth_alerts
    assert all("DMARC" in a["detail"] for a in auth_alerts)
