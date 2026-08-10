from __future__ import annotations

from app.db.models import Incident


def test_ingest_attack_batch_creates_incident_with_findings_and_mappings(
    authed_client, db_session, load_events_fixture
):
    events = load_events_fixture("brute_force_attack.json")

    response = authed_client.post("/api/events", json={"events": events})

    assert response.status_code == 200
    body = response.json()
    assert body["accepted"] == len(events)
    assert len(body["incidents_created"]) == 1

    created = body["incidents_created"][0]
    assert created["actor"] == "alice@corp.com"
    assert created["verdict"] in ("suspicious", "malicious")
    assert "BRUTE_FORCE_PASSWORD_SPRAY" in created["detection_types"]

    # Exactly one Incident row persisted — deterministic given the same inputs.
    incidents = db_session.query(Incident).all()
    assert len(incidents) == 1

    detail = authed_client.get(f"/api/incidents/{created['id']}")
    assert detail.status_code == 200
    detail_body = detail.json()
    assert detail_body["findings"][0]["id"] == "BRUTE_FORCE_PASSWORD_SPRAY"
    assert "mitre_attack" in detail_body["framework_mappings"]
    assert len(detail_body["evidence_events"]) >= 5
    assert all(e["action"] == "auth_fail" for e in detail_body["evidence_events"][:5])


def test_ingest_benign_batch_creates_no_incident(authed_client, db_session, load_events_fixture):
    events = load_events_fixture("brute_force_benign.json")

    response = authed_client.post("/api/events", json={"events": events})

    assert response.status_code == 200
    body = response.json()
    assert body["accepted"] == len(events)
    assert body["incidents_created"] == []
    assert db_session.query(Incident).count() == 0


def test_ingesting_events_for_multiple_actors_only_flags_the_non_safe_one(
    authed_client, load_events_fixture
):
    attack_events = load_events_fixture("brute_force_attack.json")
    benign_events = load_events_fixture("off_hours_benign.json")  # different actor, benign

    response = authed_client.post("/api/events", json={"events": attack_events + benign_events})

    assert response.status_code == 200
    body = response.json()
    assert body["accepted"] == len(attack_events) + len(benign_events)
    assert len(body["incidents_created"]) == 1
    assert body["incidents_created"][0]["actor"] == "alice@corp.com"


def test_label_incident_records_analyst_feedback(authed_client, load_events_fixture, test_account):
    events = load_events_fixture("brute_force_attack.json")
    ingest = authed_client.post("/api/events", json={"events": events})
    incident_id = ingest.json()["incidents_created"][0]["id"]

    label_response = authed_client.post(
        f"/api/incidents/{incident_id}/label",
        json={"analyst_verdict": "malicious", "note": "confirmed compromised account"},
    )
    assert label_response.status_code == 200
    label_body = label_response.json()
    assert label_body["incident_id"] == incident_id
    assert label_body["labeled_by"] == test_account.user.email

    detail = authed_client.get(f"/api/incidents/{incident_id}")
    assert detail.json()["latest_label"]["analyst_verdict"] == "malicious"


def test_get_and_delete_incident_lifecycle(authed_client, load_events_fixture):
    events = load_events_fixture("brute_force_attack.json")
    ingest = authed_client.post("/api/events", json={"events": events})
    incident_id = ingest.json()["incidents_created"][0]["id"]

    listing = authed_client.get("/api/incidents")
    assert listing.status_code == 200
    assert any(item["id"] == incident_id for item in listing.json()["items"])

    delete_response = authed_client.delete(f"/api/incidents/{incident_id}")
    assert delete_response.status_code == 204

    missing = authed_client.get(f"/api/incidents/{incident_id}")
    assert missing.status_code == 404


def test_incidents_are_isolated_per_account(
    authed_client, other_account_authed_client, load_events_fixture
):
    events = load_events_fixture("brute_force_attack.json")
    ingest = authed_client.post("/api/events", json={"events": events})
    incident_id = ingest.json()["incidents_created"][0]["id"]

    listing = other_account_authed_client.get("/api/incidents")
    assert listing.status_code == 200
    assert all(item["id"] != incident_id for item in listing.json()["items"])

    detail = other_account_authed_client.get(f"/api/incidents/{incident_id}")
    assert detail.status_code == 404
