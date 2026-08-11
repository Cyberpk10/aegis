from __future__ import annotations

import uuid
from datetime import datetime, timezone

from app.autonomy.actions import ACTIONS, BLOCK_SENDER_DOMAIN, DISABLE_SESSION
from app.autonomy.executor import MockConnector, execute_if_authorized
from app.autonomy.policy import Policy, PolicyRule
from app.db.models import AutonomyAction


def test_get_policy_defaults_to_l0_with_no_rules(authed_client, test_account):
    response = authed_client.get("/api/autonomy/policy")
    assert response.status_code == 200
    body = response.json()
    assert body["account_id"] == str(test_account.account.id)
    assert body["level"] == "L0"
    assert body["rules"] == []
    assert body["exclusions"] == []


def test_put_policy_round_trips(authed_client):
    payload = {
        "level": "L2",
        "rules": [
            {"action_type": "DISABLE_SESSION", "min_confidence": 0.7, "scopes": ["activity"], "full_auto": False}
        ],
        "exclusions": ["ceo@corp.com"],
        "blast_radius_limit": 5,
        "blast_radius_window_minutes": 30,
    }
    put_response = authed_client.put("/api/autonomy/policy", json=payload)
    assert put_response.status_code == 200

    get_response = authed_client.get("/api/autonomy/policy")
    body = get_response.json()
    assert body["level"] == "L2"
    assert body["rules"] == payload["rules"]
    assert body["exclusions"] == ["ceo@corp.com"]
    assert body["blast_radius_limit"] == 5
    assert body["blast_radius_window_minutes"] == 30


def test_put_policy_requires_admin(analyst_authed_client):
    response = analyst_authed_client.put(
        "/api/autonomy/policy", json={"level": "L1", "rules": [], "exclusions": []}
    )
    assert response.status_code == 403


def test_policy_is_isolated_per_account(authed_client, other_account_authed_client):
    authed_client.put(
        "/api/autonomy/policy", json={"level": "L1", "rules": [], "exclusions": []}
    )
    own_policy = authed_client.get("/api/autonomy/policy").json()
    other_policy = other_account_authed_client.get("/api/autonomy/policy").json()

    assert own_policy["level"] == "L1"
    assert other_policy["level"] == "L0"
    assert own_policy["account_id"] != other_policy["account_id"]


def test_halt_drops_level_to_l0_and_flips_pending_rows(authed_client, db_session, test_account):
    authed_client.put("/api/autonomy/policy", json={"level": "L3", "rules": [], "exclusions": []})

    incident_id = uuid.uuid4()
    execute_if_authorized(
        db_session,
        policy=Policy(account_id=test_account.account.id, level="L0"),  # forces require_approval
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

    halt_response = authed_client.post("/api/autonomy/halt")
    assert halt_response.status_code == 200
    body = halt_response.json()
    assert body["level"] == "L0"
    assert body["halted_pending_count"] == 1

    policy_after = authed_client.get("/api/autonomy/policy").json()
    assert policy_after["level"] == "L0"

    db_session.expire_all()
    row = db_session.query(AutonomyAction).first()
    assert row.status == "halted"


def test_halt_requires_admin(analyst_authed_client):
    response = analyst_authed_client.post("/api/autonomy/halt")
    assert response.status_code == 403


def test_list_actions_filters_by_action_type_and_status(authed_client, db_session, test_account):
    incident_id = uuid.uuid4()
    for action_type, status_policy in [(DISABLE_SESSION, "L0")]:
        execute_if_authorized(
            db_session,
            policy=Policy(account_id=test_account.account.id, level=status_policy),
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

    response = authed_client.get("/api/autonomy/actions", params={"action_type": "DISABLE_SESSION"})
    assert response.status_code == 200
    body = response.json()
    assert body["total"] == 1
    assert body["items"][0]["action_type"] == "DISABLE_SESSION"
    assert body["items"][0]["mapped_controls"]  # non-empty

    empty_response = authed_client.get("/api/autonomy/actions", params={"action_type": "QUARANTINE_EMAIL"})
    assert empty_response.json()["total"] == 0


def test_reverse_endpoint_rejects_a_pending_approval_row(authed_client, db_session, test_account):
    incident_id = uuid.uuid4()
    row = execute_if_authorized(
        db_session,
        policy=Policy(account_id=test_account.account.id, level="L0"),
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

    response = authed_client.post(f"/api/autonomy/actions/{row.id}/reverse")
    assert response.status_code == 400


def test_reverse_endpoint_succeeds_on_an_executed_reversible_row(authed_client, db_session, test_account):
    # BLOCK_SENDER_DOMAIN, not DISABLE_SESSION — DISABLE_SESSION is reversible=False (M6
    # Stage 2, no Graph API to un-revoke a session), so it can never reach "executed" +
    # reversible=True the way this test needs.
    incident_id = uuid.uuid4()
    row = execute_if_authorized(
        db_session,
        policy=Policy(
            account_id=test_account.account.id,
            level="L2",
            rules=[PolicyRule(action_type=BLOCK_SENDER_DOMAIN, min_confidence=0.1)],
        ),
        blast_radius_limit=10,
        blast_radius_window_minutes=60,
        connector=MockConnector(),
        action=ACTIONS[BLOCK_SENDER_DOMAIN],
        confidence=0.9,
        target="evil.com",
        scope="activity",
        trigger_finding_id="BRUTE_FORCE_PASSWORD_SPRAY",
        case_id=None,
        incident_id=incident_id,
    )
    db_session.commit()
    assert row.status == "executed"

    response = authed_client.post(f"/api/autonomy/actions/{row.id}/reverse")
    assert response.status_code == 200
    assert response.json()["status"] == "reversed"


def test_reverse_endpoint_404s_for_unknown_id(authed_client):
    response = authed_client.post(f"/api/autonomy/actions/{uuid.uuid4()}/reverse")
    assert response.status_code == 404


def test_reverse_endpoint_404s_for_another_accounts_action(
    authed_client, other_account_authed_client, db_session, test_account
):
    incident_id = uuid.uuid4()
    row = execute_if_authorized(
        db_session,
        policy=Policy(
            account_id=test_account.account.id,
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

    response = other_account_authed_client.post(f"/api/autonomy/actions/{row.id}/reverse")
    assert response.status_code == 404


# --- Microsoft Graph integration (M6 Stage 2) ---------------------------------------------


def test_get_graph_integration_defaults_to_not_connected(authed_client):
    response = authed_client.get("/api/autonomy/graph-integration")
    assert response.status_code == 200
    assert response.json() == {
        "connected": False,
        "tenant_id": None,
        "connected_at": None,
        "is_enabled": False,
    }


def test_put_graph_integration_round_trips(authed_client):
    put_response = authed_client.put(
        "/api/autonomy/graph-integration", json={"tenant_id": "11111111-2222-3333-4444-555555555555"}
    )
    assert put_response.status_code == 200
    body = put_response.json()
    assert body["connected"] is True
    assert body["tenant_id"] == "11111111-2222-3333-4444-555555555555"
    assert body["is_enabled"] is True
    assert body["connected_at"] is not None

    get_response = authed_client.get("/api/autonomy/graph-integration")
    assert get_response.json()["tenant_id"] == "11111111-2222-3333-4444-555555555555"


def test_put_graph_integration_updates_an_existing_row(authed_client):
    authed_client.put("/api/autonomy/graph-integration", json={"tenant_id": "old-tenant"})
    second = authed_client.put("/api/autonomy/graph-integration", json={"tenant_id": "new-tenant"})

    assert second.status_code == 200
    assert second.json()["tenant_id"] == "new-tenant"

    get_response = authed_client.get("/api/autonomy/graph-integration")
    assert get_response.json()["tenant_id"] == "new-tenant"


def test_put_graph_integration_requires_admin(analyst_authed_client):
    response = analyst_authed_client.put(
        "/api/autonomy/graph-integration", json={"tenant_id": "some-tenant"}
    )
    assert response.status_code == 403


def test_graph_integration_is_isolated_per_account(authed_client, other_account_authed_client):
    authed_client.put("/api/autonomy/graph-integration", json={"tenant_id": "account-a-tenant"})

    other_response = other_account_authed_client.get("/api/autonomy/graph-integration")
    assert other_response.json()["connected"] is False
