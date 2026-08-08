from __future__ import annotations

import uuid
from datetime import datetime

from app.db.models import Case, Label
from app.risk_model.assumptions import risk_assumptions

PAYMENT_REQUEST = {"id": "PAYMENT_REQUEST", "category": "content", "title": "Payment", "description": "d", "evidence": [], "severity": "high", "score": 20.0}
CREDENTIAL_REQUEST = {"id": "CREDENTIAL_REQUEST", "category": "content", "title": "Credential", "description": "d", "evidence": [], "severity": "high", "score": 20.0}
URGENCY_LANGUAGE = {"id": "URGENCY_LANGUAGE", "category": "content", "title": "Urgency", "description": "d", "evidence": [], "severity": "medium", "score": 16.0}


def _make_case(db_session, *, verdict, created_at, indicators=None):
    case = Case(
        id=uuid.uuid4(),
        created_at=created_at,
        filename="test.eml",
        verdict=verdict,
        score=50,
        from_addr="sender@example.com",
        subject="Test",
        indicators=indicators or [],
        framework_mappings={},
    )
    db_session.add(case)
    db_session.commit()
    db_session.refresh(case)
    return case


def _make_label(db_session, case_id, analyst_verdict, created_at):
    label = Label(id=uuid.uuid4(), case_id=case_id, analyst_verdict=analyst_verdict, labeled_by="tester", created_at=created_at)
    db_session.add(label)
    db_session.commit()


def test_financial_risk_matches_hand_computed_totals(client, db_session):
    case_bec = _make_case(db_session, verdict="malicious", created_at=datetime(2026, 1, 5), indicators=[PAYMENT_REQUEST])
    _make_case(db_session, verdict="malicious", created_at=datetime(2026, 1, 10), indicators=[CREDENTIAL_REQUEST])
    _make_case(db_session, verdict="suspicious", created_at=datetime(2026, 1, 12), indicators=[URGENCY_LANGUAGE])
    missed_case = _make_case(db_session, verdict="safe", created_at=datetime(2026, 1, 15), indicators=[])
    _make_label(db_session, missed_case.id, "malicious", datetime(2026, 1, 16))

    response = client.get(
        "/api/risk/financial",
        params={"date_from": "2026-01-01T00:00:00", "date_to": "2026-01-31T23:59:59"},
    )

    assert response.status_code == 200
    body = response.json()

    by_type = {b["attack_type"]: b for b in body["exposure_avoided"]["by_attack_type"]}
    assert by_type["bec"]["count"] == 1
    assert by_type["bec"]["avg_loss_usd"] == risk_assumptions.bec_avg_loss_usd
    assert by_type["bec"]["subtotal_usd"] == risk_assumptions.bec_avg_loss_usd
    assert by_type["credential_phishing"]["count"] == 1
    # "suspicious" verdict has a default prevention weight of 0 -> not counted.
    assert by_type["generic_phishing"]["count"] == 0
    assert body["exposure_avoided"]["total_usd"] == (
        risk_assumptions.bec_avg_loss_usd + risk_assumptions.credential_phishing_avg_loss_usd
    )

    assert body["residual_risk"]["false_negative_count"] == 1
    assert body["residual_risk"]["total_usd"] == risk_assumptions.generic_phishing_avg_loss_usd

    assert body["detection_counts"] == {"malicious": 2, "suspicious": 1, "safe": 1}


def test_financial_risk_always_includes_assumptions_even_when_empty(client):
    response = client.get(
        "/api/risk/financial",
        params={"date_from": "2026-01-01T00:00:00", "date_to": "2026-01-31T23:59:59"},
    )

    assert response.status_code == 200
    body = response.json()
    assert body["exposure_avoided"]["total_usd"] == 0.0
    assert body["residual_risk"]["total_usd"] == 0.0
    assert body["assumptions"]  # non-empty on every call
    assert "bec_avg_loss_usd" in body["assumptions"]
    assert body["assumptions"]["bec_avg_loss_usd"]["value"] == risk_assumptions.bec_avg_loss_usd
    assert body["assumptions"]["bec_avg_loss_usd"]["source"]


def test_financial_risk_defaults_to_current_quarter_when_no_range_given(client, db_session):
    _make_case(db_session, verdict="malicious", created_at=datetime.utcnow(), indicators=[PAYMENT_REQUEST])

    response = client.get("/api/risk/financial")

    assert response.status_code == 200
    body = response.json()
    assert body["exposure_avoided"]["total_usd"] == risk_assumptions.bec_avg_loss_usd
