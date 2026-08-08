from __future__ import annotations

import re
import uuid
from datetime import datetime
from pathlib import Path

from app.db.models import Case, RemediationAction, TrainingRecommendation

CREDENTIAL_INDICATOR = {
    "id": "CREDENTIAL_REQUEST",
    "category": "content",
    "title": "Credential-harvesting language detected",
    "description": "d",
    "evidence": [],
    "severity": "high",
    "score": 30.0,
}
SPF_INDICATOR = {
    "id": "AUTH_SPF_FAIL",
    "category": "authentication",
    "title": "SPF authentication failed",
    "description": "d",
    "evidence": [],
    "severity": "high",
    "score": 15.0,
}
MITRE_MAPPING = {
    "mitre_attack": [
        {
            "indicator_id": "CREDENTIAL_REQUEST",
            "control_id": "T1598",
            "control_name": "Phishing for Information",
            "url": None,
        },
        {
            "indicator_id": "AUTH_SPF_FAIL",
            "control_id": "T1656",
            "control_name": "Impersonation",
            "url": None,
        },
    ]
}


def _make_case(
    db_session,
    *,
    verdict,
    created_at,
    indicators=None,
    framework_mappings=None,
    to_addresses=None,
):
    case = Case(
        id=uuid.uuid4(),
        created_at=created_at,
        filename="test.eml",
        verdict=verdict,
        score=50,
        from_addr="sender@example.com",
        subject="Test",
        to_addresses=to_addresses or [],
        indicators=indicators or [],
        framework_mappings=framework_mappings or {},
    )
    db_session.add(case)
    db_session.commit()
    db_session.refresh(case)
    return case


def test_get_remediation_playbook_returns_expected_steps_and_controls(client, db_session):
    case = _make_case(
        db_session,
        verdict="malicious",
        created_at=datetime(2026, 1, 5),
        indicators=[CREDENTIAL_INDICATOR, SPF_INDICATOR],
        framework_mappings=MITRE_MAPPING,
    )

    response = client.post(f"/api/cases/{case.id}/remediate")

    assert response.status_code == 200
    body = response.json()
    step_ids = {s["step_id"] for s in body["steps"]}
    assert step_ids == {"BLOCK_SENDER_DOMAIN", "RESET_CREDENTIALS", "NOTIFY_TARGETED_USER"}

    reset_step = next(s for s in body["steps"] if s["step_id"] == "RESET_CREDENTIALS")
    assert reset_step["status"] == "recommended"
    assert reset_step["control_refs"] == [
        {"framework_key": "mitre_attack", "control_id": "T1598", "control_name": "Phishing for Information"}
    ]


def test_playbook_for_case_with_no_indicators_is_empty(client, db_session):
    case = _make_case(db_session, verdict="safe", created_at=datetime(2026, 1, 5))

    response = client.post(f"/api/cases/{case.id}/remediate")

    assert response.status_code == 200
    assert response.json()["steps"] == []


def test_remediate_unknown_case_returns_404(client):
    response = client.post(f"/api/cases/{uuid.uuid4()}/remediate")
    assert response.status_code == 404


def test_action_persists_and_is_reflected_on_next_playbook_fetch(client, db_session):
    case = _make_case(
        db_session,
        verdict="malicious",
        created_at=datetime(2026, 1, 5),
        indicators=[CREDENTIAL_INDICATOR],
        framework_mappings=MITRE_MAPPING,
    )

    action_response = client.post(
        f"/api/cases/{case.id}/remediate/RESET_CREDENTIALS/action",
        json={"status": "approved", "note": "confirmed with IT"},
        headers={"X-Analyst-Id": "alice@example.com"},
    )

    assert action_response.status_code == 200
    body = action_response.json()
    assert body["status"] == "approved"
    assert body["actor"] == "alice@example.com"
    assert body["note"] == "confirmed with IT"

    playbook_response = client.post(f"/api/cases/{case.id}/remediate")
    reset_step = next(
        s for s in playbook_response.json()["steps"] if s["step_id"] == "RESET_CREDENTIALS"
    )
    assert reset_step["status"] == "approved"
    assert reset_step["actor"] == "alice@example.com"


def test_action_uses_default_analyst_id_when_no_header_sent(client, db_session):
    case = _make_case(
        db_session, verdict="malicious", created_at=datetime(2026, 1, 5), indicators=[CREDENTIAL_INDICATOR]
    )

    response = client.post(
        f"/api/cases/{case.id}/remediate/RESET_CREDENTIALS/action", json={"status": "approved"}
    )

    assert response.json()["actor"] == "anonymous-analyst"


def test_reacting_on_a_step_keeps_history_and_shows_latest_status(client, db_session):
    case = _make_case(
        db_session, verdict="malicious", created_at=datetime(2026, 1, 5), indicators=[CREDENTIAL_INDICATOR]
    )

    client.post(f"/api/cases/{case.id}/remediate/RESET_CREDENTIALS/action", json={"status": "approved"})
    client.post(f"/api/cases/{case.id}/remediate/RESET_CREDENTIALS/action", json={"status": "done"})

    rows = db_session.query(RemediationAction).filter(RemediationAction.case_id == case.id).all()
    assert len(rows) == 2  # append-only history preserved

    playbook_response = client.post(f"/api/cases/{case.id}/remediate")
    reset_step = next(
        s for s in playbook_response.json()["steps"] if s["step_id"] == "RESET_CREDENTIALS"
    )
    assert reset_step["status"] == "done"


def test_action_on_step_not_applicable_to_case_returns_400(client, db_session):
    # SPF_INDICATOR alone does not trigger RESET_CREDENTIALS.
    case = _make_case(
        db_session, verdict="malicious", created_at=datetime(2026, 1, 5), indicators=[SPF_INDICATOR]
    )

    response = client.post(
        f"/api/cases/{case.id}/remediate/RESET_CREDENTIALS/action", json={"status": "approved"}
    )

    assert response.status_code == 400


def test_action_on_unknown_case_returns_404(client):
    response = client.post(
        f"/api/cases/{uuid.uuid4()}/remediate/RESET_CREDENTIALS/action", json={"status": "approved"}
    )
    assert response.status_code == 404


def test_get_targets_aggregates_and_stores_recommendation_once_threshold_crossed(client, db_session):
    for i in range(3):
        _make_case(
            db_session,
            verdict="malicious",
            created_at=datetime(2026, 1, i + 1),
            indicators=[CREDENTIAL_INDICATOR],
            to_addresses=["alice@example.com"],
        )

    response = client.get("/api/targets")

    assert response.status_code == 200
    body = response.json()
    assert body["threshold"] == 3

    alice = next(t for t in body["targets"] if t["recipient"] == "alice@example.com")
    assert alice["hit_count"] == 3
    assert alice["flagged_for_training"] is True
    assert alice["top_indicator_id"] == "CREDENTIAL_REQUEST"
    assert alice["first_flagged_at"] is not None

    stored = (
        db_session.query(TrainingRecommendation)
        .filter(TrainingRecommendation.recipient == "alice@example.com")
        .first()
    )
    assert stored is not None
    assert stored.hit_count == 3


def test_get_targets_excludes_recipients_below_threshold(client, db_session):
    _make_case(
        db_session,
        verdict="malicious",
        created_at=datetime(2026, 1, 1),
        indicators=[CREDENTIAL_INDICATOR],
        to_addresses=["bob@example.com"],
    )

    response = client.get("/api/targets")
    bob = next(t for t in response.json()["targets"] if t["recipient"] == "bob@example.com")

    assert bob["flagged_for_training"] is False
    assert bob["recommendation"] is None

    stored = (
        db_session.query(TrainingRecommendation)
        .filter(TrainingRecommendation.recipient == "bob@example.com")
        .first()
    )
    assert stored is None


# --- Guardrail: nothing here is destructive or reaches outside the process ---------------


def test_remediate_action_only_persists_state_no_side_effects_on_case(client, db_session):
    case = _make_case(
        db_session,
        verdict="malicious",
        created_at=datetime(2026, 1, 5),
        indicators=[CREDENTIAL_INDICATOR],
        framework_mappings=MITRE_MAPPING,
    )
    before = {
        "verdict": case.verdict,
        "score": case.score,
        "indicators": case.indicators,
        "framework_mappings": case.framework_mappings,
        "raw_email_path": case.raw_email_path,
        "from_addr": case.from_addr,
        "subject": case.subject,
    }

    client.post(f"/api/cases/{case.id}/remediate/RESET_CREDENTIALS/action", json={"status": "approved"})

    db_session.expire_all()
    refreshed = db_session.get(Case, case.id)
    after = {
        "verdict": refreshed.verdict,
        "score": refreshed.score,
        "indicators": refreshed.indicators,
        "framework_mappings": refreshed.framework_mappings,
        "raw_email_path": refreshed.raw_email_path,
        "from_addr": refreshed.from_addr,
        "subject": refreshed.subject,
    }
    assert before == after  # the case itself is untouched

    actions = db_session.query(RemediationAction).filter(RemediationAction.case_id == case.id).all()
    assert len(actions) == 1  # the only effect is one recorded state row


# Matches actual import statements / call sites only — not prose mentions (this test
# file's sibling module docstrings *talk about* not having these capabilities, which
# would false-positive on a bare word-boundary search).
_FORBIDDEN_CAPABILITIES = re.compile(
    r"^\s*(import\s+(requests|httpx|smtplib|subprocess)\b"
    r"|from\s+(requests|httpx|smtplib|subprocess)\s+import\b)"
    r"|os\.system\(|subprocess\.(run|call|Popen)\(|urllib\.request\.",
    re.MULTILINE,
)


def test_remediation_source_contains_no_network_or_process_execution_capability():
    """Static guardrail, not just a behavioral one: proves the *capability* to reach
    outside the process doesn't exist in this feature's code, not just that this one
    test run happened not to trigger it."""
    backend_root = Path(__file__).resolve().parents[2]
    remediation_dir = backend_root / "app" / "remediation"
    route_file = backend_root / "app" / "api" / "routes" / "remediation.py"

    files = sorted(remediation_dir.glob("*.py")) + [route_file]
    assert len(files) >= 3  # sanity: we actually found the files we intend to check

    for path in files:
        source = path.read_text()
        match = _FORBIDDEN_CAPABILITIES.search(source)
        assert match is None, f"{path} contains {match and match.group(0)!r} — remediation must stay recommend-only"
