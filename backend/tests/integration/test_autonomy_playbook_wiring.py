from __future__ import annotations

import uuid
from datetime import datetime, timedelta

from app.db.models import AutonomyAction, Case, Incident

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


def _make_case(db_session, *, from_addr="phisher@evil.com") -> Case:
    case = Case(
        id=uuid.uuid4(),
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


def _make_incident(db_session, *, actor="alice@corp.com") -> Incident:
    window_end = datetime(2026, 1, 6, 10, 6)
    incident = Incident(
        id=uuid.uuid4(),
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


def _set_policy(client, level, rules, exclusions=None):
    client.put(
        "/api/autonomy/policy",
        json={"level": level, "rules": rules, "exclusions": exclusions or []},
    )


def test_case_playbook_fetch_auto_executes_and_records_one_row(client, db_session):
    _set_policy(
        client,
        "L1",
        [{"action_type": "QUARANTINE_EMAIL", "min_confidence": 0.5, "scopes": None, "full_auto": False}],
    )
    case = _make_case(db_session)

    response = client.post(f"/api/cases/{case.id}/remediate")
    assert response.status_code == 200

    rows = db_session.query(AutonomyAction).filter(AutonomyAction.case_id == case.id).all()
    assert len(rows) == 1
    assert rows[0].action_type == "QUARANTINE_EMAIL"
    assert rows[0].status == "executed"
    assert rows[0].mapped_controls  # non-empty


def test_fetching_the_same_case_playbook_again_does_not_re_execute(client, db_session):
    _set_policy(
        client,
        "L1",
        [{"action_type": "QUARANTINE_EMAIL", "min_confidence": 0.5, "scopes": None, "full_auto": False}],
    )
    case = _make_case(db_session)

    client.post(f"/api/cases/{case.id}/remediate")
    client.post(f"/api/cases/{case.id}/remediate")
    client.post(f"/api/cases/{case.id}/remediate")

    rows = db_session.query(AutonomyAction).filter(AutonomyAction.case_id == case.id).all()
    assert len(rows) == 1  # not re-evaluated or re-executed on repeated fetches


def test_incident_playbook_fetch_auto_executes_disable_session(client, db_session):
    _set_policy(
        client,
        "L2",
        [{"action_type": "DISABLE_SESSION", "min_confidence": 0.5, "scopes": None, "full_auto": False}],
    )
    incident = _make_incident(db_session, actor="bob@corp.com")

    response = client.post(f"/api/incidents/{incident.id}/remediate")
    assert response.status_code == 200

    rows = db_session.query(AutonomyAction).filter(AutonomyAction.incident_id == incident.id).all()
    assert len(rows) == 1
    assert rows[0].action_type == "DISABLE_SESSION"
    assert rows[0].status == "executed"
    assert rows[0].target == "bob@corp.com"


def test_excluded_actor_never_auto_executes_even_at_l3_full_auto(client, db_session):
    _set_policy(
        client,
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
    incident = _make_incident(db_session, actor="ceo@corp.com")

    response = client.post(f"/api/incidents/{incident.id}/remediate")
    assert response.status_code == 200

    rows = db_session.query(AutonomyAction).filter(AutonomyAction.incident_id == incident.id).all()
    assert len(rows) == 1
    assert rows[0].status == "pending_approval"
    assert rows[0].decision == "require_approval"


def test_no_matching_policy_rule_skips_but_still_logs(client, db_session):
    _set_policy(client, "L2", [])  # no rules at all
    case = _make_case(db_session)

    client.post(f"/api/cases/{case.id}/remediate")

    rows = db_session.query(AutonomyAction).filter(AutonomyAction.case_id == case.id).all()
    assert len(rows) == 1
    assert rows[0].decision == "skip"
    assert rows[0].status == "skipped"
