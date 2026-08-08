from __future__ import annotations

import uuid
from datetime import datetime

from app.db.models import Case, Label


def _make_case(db_session, *, verdict, created_at, indicators=None, framework_mappings=None):
    case = Case(
        id=uuid.uuid4(),
        created_at=created_at,
        filename="test.eml",
        verdict=verdict,
        score=50,
        from_addr="sender@example.com",
        subject="Test",
        indicators=indicators or [],
        framework_mappings=framework_mappings or {},
    )
    db_session.add(case)
    db_session.commit()
    db_session.refresh(case)
    return case


def _make_label(db_session, case_id, analyst_verdict, created_at):
    label = Label(
        id=uuid.uuid4(),
        case_id=case_id,
        analyst_verdict=analyst_verdict,
        labeled_by="tester",
        created_at=created_at,
    )
    db_session.add(label)
    db_session.commit()


def test_dashboard_summary_aggregates_seeded_cases_and_labels(client, db_session):
    urgency = {
        "id": "URGENCY_LANGUAGE",
        "category": "content",
        "title": "Urgency",
        "description": "d",
        "evidence": [],
        "severity": "high",
        "score": 16.0,
    }
    spf_fail = {
        "id": "AUTH_SPF_FAIL",
        "category": "authentication",
        "title": "SPF fail",
        "description": "d",
        "evidence": [],
        "severity": "high",
        "score": 15.0,
    }
    mitre_urgency = {
        "mitre_attack": [
            {
                "indicator_id": "URGENCY_LANGUAGE",
                "control_id": "T1598",
                "control_name": "Phishing for Information",
                "url": None,
            }
        ]
    }
    mitre_spf = {
        "mitre_attack": [
            {
                "indicator_id": "AUTH_SPF_FAIL",
                "control_id": "T1656",
                "control_name": "Impersonation",
                "url": None,
            }
        ]
    }

    # Current period (January 2026).
    case_a = _make_case(
        db_session,
        verdict="malicious",
        created_at=datetime(2026, 1, 5),
        indicators=[urgency],
        framework_mappings=mitre_urgency,
    )
    case_b = _make_case(
        db_session,
        verdict="malicious",
        created_at=datetime(2026, 1, 10),
        indicators=[spf_fail],
        framework_mappings=mitre_spf,
    )
    _make_case(db_session, verdict="safe", created_at=datetime(2026, 1, 15))
    _make_case(db_session, verdict="suspicious", created_at=datetime(2026, 1, 20), indicators=[urgency])

    # Previous period (December 2025) — only used for the count deltas.
    _make_case(db_session, verdict="malicious", created_at=datetime(2025, 12, 20))
    _make_case(db_session, verdict="safe", created_at=datetime(2025, 12, 22))

    _make_label(db_session, case_a.id, "malicious", datetime(2026, 1, 6))  # agrees -> TP
    _make_label(db_session, case_b.id, "suspicious", datetime(2026, 1, 11))  # disagrees -> FP

    response = client.get(
        "/api/dashboard/summary",
        params={"date_from": "2026-01-01T00:00:00", "date_to": "2026-01-31T23:59:59"},
    )

    assert response.status_code == 200
    body = response.json()

    assert body["total_analyzed"] == {"current": 4, "previous": 2, "delta": 2, "delta_pct": 100.0}

    vc = body["verdict_counts"]
    assert vc["malicious"] == {"current": 2, "previous": 1, "delta": 1, "delta_pct": 100.0}
    assert vc["suspicious"] == {"current": 1, "previous": 0, "delta": 1, "delta_pct": None}
    assert vc["safe"] == {"current": 1, "previous": 1, "delta": 0, "delta_pct": 0.0}

    assert body["analyst_agreement"] == {"rate_pct": 50.0, "labeled_count": 2, "agreeing_count": 1}

    kris = body["kris"]
    assert kris["malicious_catch_rate_pct"] == 100.0
    assert kris["false_positive_rate_pct"] == 100.0
    assert kris["unlabeled_count"] == 2
    assert kris["labeled_count"] == 2

    top = body["top_indicators"]
    assert top[0]["indicator_id"] == "URGENCY_LANGUAGE"
    assert top[0]["count"] == 2
    assert top[1]["indicator_id"] == "AUTH_SPF_FAIL"
    assert top[1]["count"] == 1

    assert body["monthly_threat_trend"] == [{"month": "2026-01", "count": 3}]

    coverage = {c["framework_key"]: c for c in body["framework_coverage"]}
    mitre = coverage["mitre_attack"]
    assert mitre["covered_controls"] == 2
    assert mitre["total_controls"] == 7
    assert mitre["coverage_pct"] == round(100 * 2 / 7, 2)


def test_dashboard_summary_defaults_to_last_30_days_when_no_range_given(client, db_session):
    _make_case(db_session, verdict="safe", created_at=datetime.utcnow())

    response = client.get("/api/dashboard/summary")

    assert response.status_code == 200
    body = response.json()
    assert body["total_analyzed"]["current"] == 1


def test_dashboard_summary_handles_empty_database(client):
    response = client.get(
        "/api/dashboard/summary",
        params={"date_from": "2026-01-01T00:00:00", "date_to": "2026-01-31T23:59:59"},
    )

    assert response.status_code == 200
    body = response.json()
    assert body["total_analyzed"] == {"current": 0, "previous": 0, "delta": 0, "delta_pct": None}
    assert body["analyst_agreement"]["rate_pct"] is None
    assert body["kris"]["malicious_catch_rate_pct"] is None
    assert body["top_indicators"] == []
    assert body["monthly_threat_trend"] == []
