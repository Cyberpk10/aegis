from __future__ import annotations

import re
import uuid
from datetime import datetime, timedelta
from pathlib import Path

from app.db.models import Incident, RemediationAction

BRUTE_FORCE_FINDING = {
    "id": "BRUTE_FORCE_PASSWORD_SPRAY",
    "category": "access",
    "title": "Brute force / password spray",
    "description": "5 failed authentication attempts",
    "severity": "medium",
    "points": 15.0,
    "evidence_event_ids": [],
}
MITRE_MAPPING = {
    "mitre_attack": [
        {
            "indicator_id": "BRUTE_FORCE_PASSWORD_SPRAY",
            "control_id": "T1110",
            "control_name": "Brute Force",
            "url": "https://attack.mitre.org/techniques/T1110/",
        }
    ]
}


def _make_incident(db_session, account_id, *, findings=None, framework_mappings=None) -> Incident:
    window_end = datetime(2026, 1, 6, 10, 6)
    incident = Incident(
        id=uuid.uuid4(),
        account_id=account_id,
        title="Brute force / password spray — alice@corp.com",
        actor="alice@corp.com",
        verdict="suspicious",
        score=30,
        detection_types=["BRUTE_FORCE_PASSWORD_SPRAY"],
        findings=findings if findings is not None else [BRUTE_FORCE_FINDING],
        framework_mappings=framework_mappings or MITRE_MAPPING,
        window_start=window_end - timedelta(hours=24),
        window_end=window_end,
    )
    db_session.add(incident)
    db_session.commit()
    db_session.refresh(incident)
    return incident


def test_get_incident_remediation_playbook_returns_expected_steps_and_controls(
    authed_client, db_session, test_account
):
    incident = _make_incident(db_session, test_account.account.id)

    response = authed_client.post(f"/api/incidents/{incident.id}/remediate")

    assert response.status_code == 200
    body = response.json()
    assert body["case_id"] == str(incident.id)
    step_ids = {step["step_id"] for step in body["steps"]}
    assert "FORCE_PASSWORD_RESET" in step_ids
    assert "BLOCK_SOURCE_IP" in step_ids

    reset_step = next(s for s in body["steps"] if s["step_id"] == "FORCE_PASSWORD_RESET")
    assert reset_step["status"] == "recommended"
    assert reset_step["control_refs"][0]["control_id"] == "T1110"


def test_playbook_for_incident_with_no_findings_is_empty(authed_client, db_session, test_account):
    incident = _make_incident(db_session, test_account.account.id, findings=[], framework_mappings={})
    response = authed_client.post(f"/api/incidents/{incident.id}/remediate")
    assert response.status_code == 200
    assert response.json()["steps"] == []


def test_incident_remediation_action_persists_and_is_reflected_on_next_fetch(
    authed_client, db_session, test_account
):
    incident = _make_incident(db_session, test_account.account.id)

    action_response = authed_client.post(
        f"/api/incidents/{incident.id}/remediate/FORCE_PASSWORD_RESET/action",
        json={"status": "approved", "note": "reset requested"},
    )
    assert action_response.status_code == 200
    action_body = action_response.json()
    assert action_body["incident_id"] == str(incident.id)
    assert action_body["status"] == "approved"

    playbook = authed_client.post(f"/api/incidents/{incident.id}/remediate").json()
    reset_step = next(s for s in playbook["steps"] if s["step_id"] == "FORCE_PASSWORD_RESET")
    assert reset_step["status"] == "approved"
    assert reset_step["actor"] == test_account.user.email

    actions = db_session.query(RemediationAction).filter(
        RemediationAction.incident_id == incident.id
    ).all()
    assert len(actions) == 1  # the only effect is one recorded state row


def test_rejects_action_for_a_step_not_in_the_incidents_playbook(authed_client, db_session, test_account):
    incident = _make_incident(db_session, test_account.account.id)
    response = authed_client.post(
        f"/api/incidents/{incident.id}/remediate/ISOLATE_HOST/action",
        json={"status": "approved"},
    )
    assert response.status_code == 400


def test_incident_remediation_is_isolated_per_account(
    authed_client, other_account_authed_client, db_session, test_account
):
    incident = _make_incident(db_session, test_account.account.id)
    response = other_account_authed_client.post(f"/api/incidents/{incident.id}/remediate")
    assert response.status_code == 404


# Matches actual import statements / call sites only — not prose mentions (module
# docstrings *talk about* not having these capabilities, which would false-positive on a
# bare word-boundary search). Same pattern as
# test_remediation_endpoints.py::test_remediation_source_contains_no_network_or_process_execution_capability.
_FORBIDDEN_CAPABILITIES = re.compile(
    r"^\s*(import\s+(requests|httpx|smtplib|subprocess)\b"
    r"|from\s+(requests|httpx|smtplib|subprocess)\s+import\b)"
    r"|os\.system\(|subprocess\.(run|call|Popen)\(|urllib\.request\.",
    re.MULTILINE,
)


def test_intrusion_detection_source_contains_no_network_or_process_execution_capability():
    """Static guardrail, not just a behavioral one: proves the *capability* to reach
    outside the process — block an IP, isolate a host, reset a credential, page someone —
    doesn't exist anywhere in the M5 Stage 1 detection/remediation code, not just that
    this one test run happened not to trigger it."""
    backend_root = Path(__file__).resolve().parents[2]
    dirs_to_check = [
        backend_root / "app" / "detections",
        backend_root / "app" / "events",
        backend_root / "app" / "baselines",
    ]
    files = [
        backend_root / "app" / "remediation" / "intrusion_playbook.py",
        backend_root / "app" / "api" / "routes" / "events.py",
        backend_root / "app" / "api" / "routes" / "incidents.py",
    ]
    for directory in dirs_to_check:
        files.extend(sorted(directory.glob("*.py")))

    assert len(files) >= 10  # sanity: we actually found the files we intend to check

    for path in files:
        source = path.read_text()
        match = _FORBIDDEN_CAPABILITIES.search(source)
        assert match is None, (
            f"{path} contains {match and match.group(0)!r} — intrusion detection must "
            "stay observe/recommend-only"
        )
