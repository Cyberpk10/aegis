from __future__ import annotations

import pytest


def test_rejects_empty_text(authed_client):
    response = authed_client.post("/api/analyze/text", json={"raw_text": ""})
    assert response.status_code == 400


def test_rejects_whitespace_only_text(authed_client):
    response = authed_client.post("/api/analyze/text", json={"raw_text": "   \n\t  "})
    assert response.status_code == 400


@pytest.mark.parametrize(
    "filename",
    [
        "phishing_lookalike_paypal.eml",
        "phishing_bec_wire_transfer.eml",
        "phishing_shortener_credential_harvest.eml",
        "benign_newsletter.eml",
        "benign_internal_it_notice.eml",
        "benign_legit_password_reset.eml",
    ],
)
def test_pasted_full_raw_email_matches_file_upload_verdict(authed_client, load_eml, filename):
    raw = load_eml(filename)

    file_response = authed_client.post(
        "/api/analyze", files={"file": (filename, raw, "message/rfc822")}
    )
    text_response = authed_client.post(
        "/api/analyze/text", json={"raw_text": raw.decode("utf-8", errors="replace")}
    )

    assert file_response.status_code == 200
    assert text_response.status_code == 200
    file_body = file_response.json()
    text_body = text_response.json()

    assert text_body["verdict"] == file_body["verdict"]
    assert text_body["score"] == file_body["score"]
    assert text_body["indicators"] == file_body["indicators"]
    assert text_body["framework_mappings"] == file_body["framework_mappings"]
    assert text_body["summary"]["subject"] == file_body["summary"]["subject"]
    assert text_body["summary"]["from_address"] == file_body["summary"]["from_address"]


def test_paste_subject_and_body_only_returns_sensible_result(authed_client):
    raw_text = (
        "Subject: Urgent: verify your account now\n\n"
        "Please click here immediately to confirm your password before your account is suspended."
    )
    response = authed_client.post("/api/analyze/text", json={"raw_text": raw_text})

    assert response.status_code == 200
    body = response.json()
    assert body["summary"]["subject"] == "Urgent: verify your account now"
    assert body["verdict"] in {"safe", "suspicious", "malicious"}
    assert isinstance(body["indicators"], list)
    assert isinstance(body["score"], int)


def test_paste_plain_text_with_no_headers_at_all_does_not_error(authed_client):
    response = authed_client.post(
        "/api/analyze/text", json={"raw_text": "just some plain text with no headers at all"}
    )
    assert response.status_code == 200
    body = response.json()
    assert body["summary"]["subject"] is None
    assert body["verdict"] in {"safe", "suspicious", "malicious"}


def test_paste_persists_a_retrievable_case_scoped_to_account(authed_client):
    raw_text = "Subject: Team lunch\n\nLet's meet at noon."
    analyze_response = authed_client.post("/api/analyze/text", json={"raw_text": raw_text})
    assert analyze_response.status_code == 200
    analyze_body = analyze_response.json()
    assert analyze_body["id"]

    case_response = authed_client.get(f"/api/cases/{analyze_body['id']}")
    assert case_response.status_code == 200
    case_body = case_response.json()

    assert case_body["id"] == analyze_body["id"]
    assert case_body["verdict"] == analyze_body["verdict"]
    assert case_body["score"] == analyze_body["score"]
    assert case_body["filename"] == "Team lunch.eml"
    assert case_body["subject"] == "Team lunch"


def test_paste_requires_auth(client):
    response = client.post("/api/analyze/text", json={"raw_text": "Subject: X\n\nBody"})
    assert response.status_code == 401


def test_other_account_cannot_see_a_pasted_case(authed_client, other_account_authed_client):
    raw_text = "Subject: Confidential\n\nSensitive content."
    analyze_response = authed_client.post("/api/analyze/text", json={"raw_text": raw_text})
    case_id = analyze_response.json()["id"]

    response = other_account_authed_client.get(f"/api/cases/{case_id}")
    assert response.status_code == 404
