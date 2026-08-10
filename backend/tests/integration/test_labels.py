from __future__ import annotations

import json
import uuid

from app.db.models import Label


def _post_eml(authed_client, load_eml, filename: str) -> dict:
    raw = load_eml(filename)
    response = authed_client.post("/api/analyze", files={"file": (filename, raw, "message/rfc822")})
    assert response.status_code == 200
    return response.json()


def _export_records(authed_client) -> list[dict]:
    response = authed_client.get("/api/labels/export")
    assert response.status_code == 200
    lines = [line for line in response.text.splitlines() if line.strip()]
    return [json.loads(line) for line in lines]


def test_label_case_is_stored_and_shown_on_case_detail(authed_client, load_eml, test_account):
    case = _post_eml(authed_client, load_eml, "phishing_lookalike_paypal.eml")

    response = authed_client.post(
        f"/api/cases/{case['id']}/label",
        json={"analyst_verdict": "malicious", "note": "Confirmed via header analysis."},
    )
    assert response.status_code == 200
    label = response.json()
    assert label["case_id"] == case["id"]
    assert label["analyst_verdict"] == "malicious"
    assert label["note"] == "Confirmed via header analysis."
    assert label["labeled_by"] == test_account.user.email

    case_detail = authed_client.get(f"/api/cases/{case['id']}").json()
    assert case_detail["latest_label"]["analyst_verdict"] == "malicious"
    assert case_detail["latest_label"]["note"] == "Confirmed via header analysis."


def test_label_case_appears_in_export(authed_client, load_eml):
    case = _post_eml(authed_client, load_eml, "phishing_lookalike_paypal.eml")
    authed_client.post(f"/api/cases/{case['id']}/label", json={"analyst_verdict": "malicious"})

    records = _export_records(authed_client)
    matching = [r for r in records if r["case_id"] == case["id"]]
    assert len(matching) == 1
    assert matching[0]["analyst_verdict"] == "malicious"
    assert matching[0]["machine_verdict"] == case["verdict"]
    assert matching[0]["filename"] == "phishing_lookalike_paypal.eml"


def test_export_excludes_unlabeled_cases(authed_client, load_eml):
    _post_eml(authed_client, load_eml, "benign_newsletter.eml")
    assert _export_records(authed_client) == []


def test_relabel_preserves_history_and_export_reflects_latest(authed_client, load_eml, db_session):
    case = _post_eml(authed_client, load_eml, "phishing_lookalike_paypal.eml")
    case_id = case["id"]

    first = authed_client.post(f"/api/cases/{case_id}/label", json={"analyst_verdict": "suspicious"})
    assert first.status_code == 200
    second = authed_client.post(
        f"/api/cases/{case_id}/label",
        json={"analyst_verdict": "malicious", "note": "Escalated after review."},
    )
    assert second.status_code == 200

    # History: both label rows still exist, oldest first.
    rows = (
        db_session.query(Label)
        .filter(Label.case_id == uuid.UUID(case_id))
        .order_by(Label.created_at)
        .all()
    )
    assert [row.analyst_verdict for row in rows] == ["suspicious", "malicious"]

    # The case detail and the export both reflect only the latest label.
    case_detail = authed_client.get(f"/api/cases/{case_id}").json()
    assert case_detail["latest_label"]["analyst_verdict"] == "malicious"
    assert case_detail["latest_label"]["note"] == "Escalated after review."

    records = _export_records(authed_client)
    matching = [r for r in records if r["case_id"] == case_id]
    assert len(matching) == 1
    assert matching[0]["analyst_verdict"] == "malicious"


def test_label_nonexistent_case_returns_404(authed_client):
    response = authed_client.post(
        "/api/cases/00000000-0000-0000-0000-000000000000/label",
        json={"analyst_verdict": "safe"},
    )
    assert response.status_code == 404


def test_labeled_by_uses_authenticated_users_email(authed_client, load_eml, test_account):
    case = _post_eml(authed_client, load_eml, "benign_newsletter.eml")

    response = authed_client.post(
        f"/api/cases/{case['id']}/label",
        json={"analyst_verdict": "safe"},
    )

    assert response.json()["labeled_by"] == test_account.user.email
