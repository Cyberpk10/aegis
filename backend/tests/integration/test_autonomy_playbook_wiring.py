from __future__ import annotations

import uuid
from datetime import datetime, timedelta
from unittest.mock import patch

import httpx
import respx

from app.autonomy.graph_connector import GraphConnector
from app.core.config import settings
from app.db.models import AutonomyAction, Case, GraphIntegration, Incident
from app.storage.raw_email_store import save_raw_email

CREDENTIAL_REQUEST = {
    "id": "CREDENTIAL_REQUEST",
    "category": "content",
    "title": "Credential-harvesting language detected",
    "description": "d",
    "evidence": [],
    "severity": "high",
    "score": 90.0,
}
BRUTE_FORCE_FINDING = {
    "id": "BRUTE_FORCE_PASSWORD_SPRAY",
    "category": "access",
    "title": "Brute force / password spray",
    "description": "d",
    "severity": "high",
    "points": 90.0,
    "evidence_event_ids": [],
}


def _make_case(db_session, account_id, *, from_addr="phisher@evil.com") -> Case:
    case = Case(
        id=uuid.uuid4(),
        account_id=account_id,
        filename="test.eml",
        verdict="malicious",
        score=90,
        from_addr=from_addr,
        subject="Test",
        indicators=[CREDENTIAL_REQUEST],
        framework_mappings={},
    )
    db_session.add(case)
    db_session.commit()
    db_session.refresh(case)
    return case


def _make_incident(db_session, account_id, *, actor="alice@corp.com") -> Incident:
    window_end = datetime(2026, 1, 6, 10, 6)
    incident = Incident(
        id=uuid.uuid4(),
        account_id=account_id,
        title="Brute force — " + actor,
        actor=actor,
        verdict="suspicious",
        score=45,
        detection_types=["BRUTE_FORCE_PASSWORD_SPRAY"],
        findings=[BRUTE_FORCE_FINDING],
        framework_mappings={},
        window_start=window_end - timedelta(hours=24),
        window_end=window_end,
    )
    db_session.add(incident)
    db_session.commit()
    db_session.refresh(incident)
    return incident


def _set_policy(authed_client, level, rules, exclusions=None):
    authed_client.put(
        "/api/autonomy/policy",
        json={"level": level, "rules": rules, "exclusions": exclusions or []},
    )


def test_case_playbook_fetch_auto_executes_and_records_one_row(authed_client, db_session, test_account):
    _set_policy(
        authed_client,
        "L1",
        [{"action_type": "QUARANTINE_EMAIL", "min_confidence": 0.5, "scopes": None, "full_auto": False}],
    )
    case = _make_case(db_session, test_account.account.id)

    response = authed_client.post(f"/api/cases/{case.id}/remediate")
    assert response.status_code == 200

    rows = db_session.query(AutonomyAction).filter(AutonomyAction.case_id == case.id).all()
    assert len(rows) == 1
    assert rows[0].action_type == "QUARANTINE_EMAIL"
    assert rows[0].status == "executed"
    assert rows[0].mapped_controls  # non-empty


def test_fetching_the_same_case_playbook_again_does_not_re_execute(authed_client, db_session, test_account):
    _set_policy(
        authed_client,
        "L1",
        [{"action_type": "QUARANTINE_EMAIL", "min_confidence": 0.5, "scopes": None, "full_auto": False}],
    )
    case = _make_case(db_session, test_account.account.id)

    authed_client.post(f"/api/cases/{case.id}/remediate")
    authed_client.post(f"/api/cases/{case.id}/remediate")
    authed_client.post(f"/api/cases/{case.id}/remediate")

    rows = db_session.query(AutonomyAction).filter(AutonomyAction.case_id == case.id).all()
    assert len(rows) == 1  # not re-evaluated or re-executed on repeated fetches


def test_incident_playbook_fetch_never_auto_executes_disable_session(authed_client, db_session, test_account):
    # DISABLE_SESSION is reversible=False (M6 Stage 2 — Microsoft Graph has no API to
    # un-revoke a session), so even a matching rule at a policy level that would auto-execute
    # any other containment action must still land on pending_approval — a human has to
    # approve it. This is the full incident-remediation-pathway confirmation of the same
    # invariant tests/unit/test_autonomy_policy.py checks at the pure evaluate() layer.
    _set_policy(
        authed_client,
        "L2",
        [{"action_type": "DISABLE_SESSION", "min_confidence": 0.5, "scopes": None, "full_auto": False}],
    )
    incident = _make_incident(db_session, test_account.account.id, actor="bob@corp.com")

    response = authed_client.post(f"/api/incidents/{incident.id}/remediate")
    assert response.status_code == 200

    rows = db_session.query(AutonomyAction).filter(AutonomyAction.incident_id == incident.id).all()
    assert len(rows) == 1
    assert rows[0].action_type == "DISABLE_SESSION"
    assert rows[0].status == "pending_approval"
    assert rows[0].target == "bob@corp.com"


def test_excluded_actor_never_auto_executes_even_at_l3_full_auto(authed_client, db_session, test_account):
    # This incident's finding maps to DISABLE_SESSION (reversible=False since M6 Stage 2), so
    # the outcome asserted below is now guaranteed twice over (exclusion AND irreversibility)
    # rather than solely by exclusion — the exclusion-specific behavior on its own is covered
    # precisely, in isolation, by tests/unit/test_autonomy_policy.py using a still-reversible
    # containment action.
    _set_policy(
        authed_client,
        "L3",
        [
            {
                "action_type": "DISABLE_SESSION",
                "min_confidence": 0.01,
                "scopes": None,
                "full_auto": True,
            }
        ],
        exclusions=["ceo@corp.com"],
    )
    incident = _make_incident(db_session, test_account.account.id, actor="ceo@corp.com")

    response = authed_client.post(f"/api/incidents/{incident.id}/remediate")
    assert response.status_code == 200

    rows = db_session.query(AutonomyAction).filter(AutonomyAction.incident_id == incident.id).all()
    assert len(rows) == 1
    assert rows[0].status == "pending_approval"
    assert rows[0].decision == "require_approval"


def test_no_matching_policy_rule_skips_but_still_logs(authed_client, db_session, test_account):
    _set_policy(authed_client, "L2", [])  # no rules at all
    case = _make_case(db_session, test_account.account.id)

    authed_client.post(f"/api/cases/{case.id}/remediate")

    rows = db_session.query(AutonomyAction).filter(AutonomyAction.case_id == case.id).all()
    assert len(rows) == 1
    assert rows[0].decision == "skip"
    assert rows[0].status == "skipped"


def test_playbook_evaluation_is_isolated_per_account(
    authed_client, other_account_authed_client, db_session, test_account
):
    """A case created under one account's admin is invisible to another account's playbook
    fetch, and each account's autonomy policy is evaluated independently."""
    _set_policy(
        authed_client,
        "L1",
        [{"action_type": "QUARANTINE_EMAIL", "min_confidence": 0.5, "scopes": None, "full_auto": False}],
    )
    case = _make_case(db_session, test_account.account.id)

    response = other_account_authed_client.post(f"/api/cases/{case.id}/remediate")
    assert response.status_code == 404

    rows = db_session.query(AutonomyAction).filter(AutonomyAction.case_id == case.id).all()
    assert len(rows) == 0


# --- Real GraphConnector wiring end-to-end (M6 Stage 2) ------------------------------------


def test_connected_account_auto_executes_through_a_real_graph_connector_mocked_http(
    authed_client, db_session, test_account, monkeypatch
):
    """Full-stack proof: an account that has configured Microsoft Graph credentials AND
    connected a tenant gets a real GraphConnector — not MockConnector — selected by
    connector_factory and actually invoked by the case-remediation HTTP endpoint. Only the
    outbound Graph HTTP calls are faked (respx); everything else (policy engine, executor,
    route handler) runs for real."""
    monkeypatch.setattr(settings, "microsoft_graph_client_id", "test-client-id")
    monkeypatch.setattr(settings, "microsoft_graph_client_secret", "test-client-secret")
    db_session.add(
        GraphIntegration(account_id=test_account.account.id, tenant_id="test-tenant-id")
    )
    db_session.commit()

    _set_policy(
        authed_client,
        "L1",
        [{"action_type": "QUARANTINE_EMAIL", "min_confidence": 0.5, "scopes": None, "full_auto": False}],
    )

    case = _make_case(db_session, test_account.account.id)
    case.to_addresses = ["soc@corp.com"]
    raw_eml = (
        b"From: phisher@evil.com\r\n"
        b"To: soc@corp.com\r\n"
        b"Subject: Test\r\n"
        b"Message-ID: <real-message-id@evil.com>\r\n"
        b"\r\n"
        b"body\r\n"
    )
    case.raw_email_path = save_raw_email(case.id, raw_eml)
    db_session.commit()

    with patch.object(GraphConnector, "_acquire_token", return_value="fake-token"):
        with respx.mock(base_url="https://graph.microsoft.com/v1.0") as mock:
            mock.get("/users/soc@corp.com/messages").mock(
                return_value=httpx.Response(
                    200, json={"value": [{"id": "msg-1", "parentFolderId": "inbox-id"}]}
                )
            )
            mock.get("/users/soc@corp.com/mailFolders").mock(
                return_value=httpx.Response(200, json={"value": []})
            )
            mock.post("/users/soc@corp.com/mailFolders").mock(
                return_value=httpx.Response(201, json={"id": "quarantine-id"})
            )
            mock.post("/users/soc@corp.com/messages/msg-1/move").mock(
                return_value=httpx.Response(201, json={"id": "msg-1-moved"})
            )

            response = authed_client.post(f"/api/cases/{case.id}/remediate")

    assert response.status_code == 200

    rows = db_session.query(AutonomyAction).filter(AutonomyAction.case_id == case.id).all()
    assert len(rows) == 1
    assert rows[0].status == "executed"
    assert rows[0].result["outcome"] == "success"
    assert rows[0].result["quarantine_folder_id"] == "quarantine-id"


def test_connected_account_with_no_locatable_message_id_fails_cleanly_not_a_500(
    authed_client, db_session, test_account, monkeypatch
):
    """A case with no findable Message-ID (e.g. never actually delivered through this
    tenant) must not crash the playbook-fetch request — GraphConnector.execute() raises,
    execute_if_authorized() catches it and records execution_failed, exactly the same
    contract as any other connector failure."""
    monkeypatch.setattr(settings, "microsoft_graph_client_id", "test-client-id")
    monkeypatch.setattr(settings, "microsoft_graph_client_secret", "test-client-secret")
    db_session.add(
        GraphIntegration(account_id=test_account.account.id, tenant_id="test-tenant-id")
    )
    db_session.commit()

    _set_policy(
        authed_client,
        "L1",
        [{"action_type": "QUARANTINE_EMAIL", "min_confidence": 0.5, "scopes": None, "full_auto": False}],
    )
    case = _make_case(db_session, test_account.account.id)
    case.to_addresses = ["soc@corp.com"]
    db_session.commit()  # no raw_email_path at all -> no Message-ID ever found

    with patch.object(GraphConnector, "_acquire_token", return_value="fake-token"):
        response = authed_client.post(f"/api/cases/{case.id}/remediate")

    assert response.status_code == 200

    rows = db_session.query(AutonomyAction).filter(AutonomyAction.case_id == case.id).all()
    assert len(rows) == 1
    assert rows[0].status == "execution_failed"
    assert rows[0].result["outcome"] == "failed"
