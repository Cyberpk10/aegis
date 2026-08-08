from __future__ import annotations

import uuid
from datetime import datetime, timezone

from app.autonomy.actions import ACTIONS, DISABLE_SESSION
from app.autonomy.executor import MockConnector, execute_if_authorized
from app.autonomy.policy import Policy, PolicyRule
from app.db.models import AutonomyAction


def test_get_policy_defaults_to_l0_with_no_rules(client):
    response = client.get("/api/autonomy/policy")
    assert response.status_code == 200
    body = response.json()
    assert body["tenant_id"] == "default"
    assert body["level"] == "L0"
    assert body["rules"] == []
    assert body["exclusions"] == []


def test_put_policy_round_trips(client):
    payload = {
        "level": "L2",
        "rules": [
            {"action_type": "DISABLE_SESSION", "min_confidence": 0.7, "scopes": ["activity"], "full_auto": False}
        ],
        "exclusions": ["ceo@corp.com"],
        "blast_radius_limit": 5,
        "blast_radius_window_minutes": 30,
    }
    put_response = client.put("/api/autonomy/policy", json=payload)
    assert put_response.status_code == 200

    get_response = client.get("/api/autonomy/policy")
    body = get_response.json()
    assert body["level"] == "L2"
    assert body["rules"] == payload["rules"]
    assert body["exclusions"] == ["ceo@corp.com"]
    assert body["blast_radius_limit"] == 5
    assert body["blast_radius_window_minutes"] == 30


def test_put_policy_is_scoped_per_tenant_header(client):
    client.put(
        "/api/autonomy/policy",
        json={"level": "L1", "rules": [], "exclusions": []},
        headers={"X-Tenant-Id": "tenant-a"},
    )
    default_policy = client.get("/api/autonomy/policy").json()
    tenant_a_policy = client.get("/api/autonomy/policy", headers={"X-Tenant-Id": "tenant-a"}).json()

    assert default_policy["level"] == "L0"
    assert tenant_a_policy["level"] == "L1"


def test_halt_drops_level_to_l0_and_flips_pending_rows(client, db_session):
    client.put("/api/autonomy/policy", json={"level": "L3", "rules": [], "exclusions": []})

    incident_id = uuid.uuid4()
    execute_if_authorized(
        db_session,
        policy=Policy(tenant_id="default", level="L0"),  # forces require_approval
        blast_radius_limit=10,
        blast_radius_window_minutes=60,
        connector=MockConnector(),
        action=ACTIONS[DISABLE_SESSION],
        confidence=0.9,
        target="alice@corp.com",
        scope="activity",
        trigger_finding_id="BRUTE_FORCE_PASSWORD_SPRAY",
        case_id=None,
        incident_id=incident_id,
    )
    db_session.commit()

    halt_response = client.post("/api/autonomy/halt")
    assert halt_response.status_code == 200
    body = halt_response.json()
    assert body["level"] == "L0"
    assert body["halted_pending_count"] == 1

    policy_after = client.get("/api/autonomy/policy").json()
    assert policy_after["level"] == "L0"

    db_session.expire_all()
    row = db_session.query(AutonomyAction).first()
    assert row.status == "halted"


def test_list_actions_filters_by_action_type_and_status(client, db_session):
    incident_id = uuid.uuid4()
    for action_type, status_policy in [(DISABLE_SESSION, "L0")]:
        execute_if_authorized(
            db_session,
            policy=Policy(tenant_id="default", level=status_policy),
            blast_radius_limit=10,
            blast_radius_window_minutes=60,
            connector=MockConnector(),
            action=ACTIONS[action_type],
            confidence=0.9,
            target="alice@corp.com",
            scope="activity",
            trigger_finding_id="BRUTE_FORCE_PASSWORD_SPRAY",
            case_id=None,
            incident_id=incident_id,
        )
    db_session.commit()

    response = client.get("/api/autonomy/actions", params={"action_type": "DISABLE_SESSION"})
    assert response.status_code == 200
    body = response.json()
    assert body["total"] == 1
    assert body["items"][0]["action_type"] == "DISABLE_SESSION"
    assert body["items"][0]["mapped_controls"]  # non-empty

    empty_response = client.get("/api/autonomy/actions", params={"action_type": "QUARANTINE_EMAIL"})
    assert empty_response.json()["total"] == 0


def test_reverse_endpoint_rejects_a_pending_approval_row(client, db_session):
    incident_id = uuid.uuid4()
    row = execute_if_authorized(
        db_session,
        policy=Policy(tenant_id="default", level="L0"),
        blast_radius_limit=10,
        blast_radius_window_minutes=60,
        connector=MockConnector(),
        action=ACTIONS[DISABLE_SESSION],
        confidence=0.9,
        target="alice@corp.com",
        scope="activity",
        trigger_finding_id="BRUTE_FORCE_PASSWORD_SPRAY",
        case_id=None,
        incident_id=incident_id,
    )
    db_session.commit()

    response = client.post(f"/api/autonomy/actions/{row.id}/reverse")
    assert response.status_code == 400


def test_reverse_endpoint_succeeds_on_an_executed_reversible_row(client, db_session):
    incident_id = uuid.uuid4()
    row = execute_if_authorized(
        db_session,
        policy=Policy(
            tenant_id="default",
            level="L2",
            rules=[PolicyRule(action_type=DISABLE_SESSION, min_confidence=0.1)],
        ),
        blast_radius_limit=10,
        blast_radius_window_minutes=60,
        connector=MockConnector(),
        action=ACTIONS[DISABLE_SESSION],
        confidence=0.9,
        target="alice@corp.com",
        scope="activity",
        trigger_finding_id="BRUTE_FORCE_PASSWORD_SPRAY",
        case_id=None,
        incident_id=incident_id,
    )
    db_session.commit()
    assert row.status == "executed"

    response = client.post(f"/api/autonomy/actions/{row.id}/reverse")
    assert response.status_code == 200
    assert response.json()["status"] == "reversed"


def test_reverse_endpoint_404s_for_unknown_id(client):
    response = client.post(f"/api/autonomy/actions/{uuid.uuid4()}/reverse")
    assert response.status_code == 404
