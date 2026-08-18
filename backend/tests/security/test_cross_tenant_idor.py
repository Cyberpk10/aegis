"""Cross-account (IDOR) adversarial tests. app.db.models.Account is the tenancy boundary —
every table hangs off it via account_id — and the route-level pattern is consistently
`row.account_id != current_user.account_id -> 404`. Direct-object-reference tests for
cases/incidents/autonomy already exist (tests/integration/test_cases_endpoints.py,
test_autonomy_endpoints.py, ...); this file targets the resources that had NO existing
cross-account regression test despite looking correctly scoped in the code — audit report
downloads, the aggregate risk/dashboard/monitoring endpoints, label export, and the copilot's
account_id-is-never-client-or-LLM-supplied guarantee — so a future regression here is
actually caught rather than relying on code review alone.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone

import pytest

from app.core.config import settings
from app.db.models import Case

CRED = {
    "id": "CREDENTIAL_REQUEST",
    "category": "content",
    "title": "Credential-harvesting language detected",
    "description": "d",
    "evidence": [],
    "severity": "high",
    "score": 30.0,
}
MITRE_MAPPING = {
    "mitre_attack": [
        {"indicator_id": "CREDENTIAL_REQUEST", "control_id": "T1598", "control_name": "Phishing for Information", "url": None}
    ]
}


def _make_case(db_session, account_id, *, verdict="malicious", score=80, to_addresses=None):
    case = Case(
        id=uuid.uuid4(),
        account_id=account_id,
        created_at=datetime.now(timezone.utc),
        filename="t.eml",
        verdict=verdict,
        score=score,
        from_addr="attacker@evil.example",
        subject="Victim-account-only secret subject XYZ123",
        to_addresses=to_addresses or ["target@victimcorp.example"],
        indicators=[CRED],
        framework_mappings=MITRE_MAPPING,
    )
    db_session.add(case)
    db_session.commit()
    db_session.refresh(case)
    return case


# --- Audit reports --------------------------------------------------------------------


def test_audit_report_not_downloadable_by_another_account(
    authed_client, other_account_authed_client, db_session, test_account
):
    _make_case(db_session, test_account.account.id)
    gen = authed_client.post("/api/audit/report", json={"framework": "mitre"})
    assert gen.status_code == 200
    report_id = gen.json()["id"]

    # The victim's own account can list/download it.
    assert authed_client.get(f"/api/audit/reports/{report_id}/download?format=json").status_code == 200

    # A different account guessing/enumerating the report id cannot.
    cross = other_account_authed_client.get(f"/api/audit/reports/{report_id}/download?format=json")
    assert cross.status_code == 404

    listing = other_account_authed_client.get("/api/audit/reports").json()
    assert all(item["id"] != report_id for item in listing["items"])


# --- Aggregate endpoints: no cross-tenant bleed into the numbers ----------------------


def test_dashboard_summary_excludes_other_accounts_cases(
    authed_client, other_account_authed_client, db_session, test_account
):
    for _ in range(5):
        _make_case(db_session, test_account.account.id)

    victim_summary = other_account_authed_client.get("/api/dashboard/summary").json()
    assert victim_summary["total_analyzed"]["current"] == 0


def test_risk_financial_excludes_other_accounts_cases(
    authed_client, other_account_authed_client, db_session, test_account
):
    _make_case(db_session, test_account.account.id, verdict="malicious", score=90)

    victim_risk = other_account_authed_client.get("/api/risk/financial").json()
    assert victim_risk["detection_counts"] == {"malicious": 0, "suspicious": 0, "safe": 0}
    assert victim_risk["exposure_avoided"]["total_usd"] == 0
    assert victim_risk["residual_risk"]["false_negative_count"] == 0


def test_monitoring_controls_not_influenced_by_other_accounts_evidence(
    authed_client, other_account_authed_client, db_session, test_account
):
    for _ in range(3):
        _make_case(db_session, test_account.account.id)

    victim_controls = other_account_authed_client.get("/api/monitoring/controls").json()
    # Every control's evidence must be computed purely from the caller's own account.
    assert all(c["evidence_count"] == 0 for c in victim_controls["items"])


def test_labels_export_excludes_other_accounts_labels(
    authed_client, other_account_authed_client, db_session, test_account
):
    case = _make_case(db_session, test_account.account.id)
    label_resp = authed_client.post(
        f"/api/cases/{case.id}/label", json={"analyst_verdict": "malicious", "note": "confirmed phish"}
    )
    assert label_resp.status_code == 200

    victim_export = other_account_authed_client.get("/api/labels/export")
    assert victim_export.status_code == 200
    assert victim_export.text == ""  # nothing at all, not even a filtered/partial line

    owner_export = authed_client.get("/api/labels/export")
    assert "confirmed phish" in owner_export.text


# --- Autonomy: filter-param IDOR (passing another account's id as a query filter) -----


def test_autonomy_actions_filter_by_foreign_case_id_returns_nothing(
    other_account_authed_client, db_session, test_account
):
    """Even though `case_id` is accepted as a free-form filter on GET /api/autonomy/actions,
    the base query is always pre-scoped to the caller's own account_id — passing another
    account's real case id as a filter must never leak that it exists or return its rows."""
    victim_case = _make_case(db_session, test_account.account.id)

    response = other_account_authed_client.get(f"/api/autonomy/actions?case_id={victim_case.id}")
    assert response.status_code == 200
    assert response.json()["items"] == []
    assert response.json()["total"] == 0


# --- Copilot: account_id is never client- or LLM-supplied ------------------------------


def _enable_copilot(monkeypatch):
    monkeypatch.setattr(settings, "enable_copilot", True)
    monkeypatch.setenv("ANTHROPIC_API_KEY", "test-key")


def test_copilot_verdict_counts_never_crosses_accounts(
    authed_client, other_account_authed_client, db_session, test_account, monkeypatch
):
    from app.api.routes import copilot as copilot_route

    _enable_copilot(monkeypatch)
    for _ in range(4):
        _make_case(db_session, test_account.account.id, verdict="malicious")

    monkeypatch.setattr(copilot_route, "select_template", lambda q, **kw: ("verdict_counts", {}))
    monkeypatch.setattr(copilot_route, "narrate", lambda *a, **kw: "narrative")

    victim_response = other_account_authed_client.post(
        "/api/copilot/query", json={"question": "how many malicious emails?"}
    )
    assert victim_response.status_code == 200
    assert victim_response.json()["result"]["total"] == 0

    owner_response = authed_client.post(
        "/api/copilot/query", json={"question": "how many malicious emails?"}
    )
    assert owner_response.json()["result"]["total"] == 4


def test_copilot_target_lookup_cannot_be_used_to_probe_another_accounts_recipients(
    authed_client, other_account_authed_client, db_session, test_account, monkeypatch
):
    """An attacker in account B who has somehow learned a real recipient address that was
    targeted in account A tries to use target_lookup to confirm/enumerate it. Since
    execute_template always scopes the underlying case query to the caller's OWN
    account_id (app.copilot.templates._cases_in_range), this must come back empty for B
    regardless of what happened in A."""
    from app.api.routes import copilot as copilot_route

    _enable_copilot(monkeypatch)
    victim_recipient = "cfo@victimcorp.example"
    for _ in range(5):
        _make_case(db_session, test_account.account.id, to_addresses=[victim_recipient])

    monkeypatch.setattr(
        copilot_route,
        "select_template",
        lambda q, **kw: ("target_lookup", {"recipient": victim_recipient}),
    )
    monkeypatch.setattr(copilot_route, "narrate", lambda *a, **kw: "narrative")

    attacker_response = other_account_authed_client.post(
        "/api/copilot/query", json={"question": f"has {victim_recipient} been targeted?"}
    )
    assert attacker_response.status_code == 200
    assert attacker_response.json()["result"]["hit_count"] == 0
    assert attacker_response.json()["result"]["flagged_for_training"] is False
