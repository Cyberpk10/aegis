from __future__ import annotations

_EMAIL_ONLY_INDICATOR_IDS = {
    "AUTH_SPF_FAIL",
    "AUTH_DKIM_FAIL",
    "AUTH_DMARC_FAIL",
    "SENDER_REPLYTO_MISMATCH",
}


def test_malicious_slack_message_returns_malicious_verdict_with_shared_and_chat_indicators(authed_client):
    response = authed_client.post(
        "/api/messages/analyze",
        json={
            "channel": "slack",
            "channel_name": "DM",
            "from_display": "IT Support",
            "from_address": "it-support@external-vendor.example",
            "is_direct_message": True,
            "is_external_sender": True,
            "text": (
                "URGENT: your account will be suspended. Verify your account immediately: "
                "http://bit.ly/verify-now-123"
            ),
            "links": [
                {
                    "display_text": "http://bit.ly/verify-now-123",
                    "href": "http://bit.ly/verify-now-123",
                }
            ],
        },
    )
    assert response.status_code == 200
    body = response.json()

    assert body["verdict"] in ("suspicious", "malicious")
    ids = {i["id"] for i in body["indicators"]}
    assert "URGENCY_LANGUAGE" in ids
    assert "CREDENTIAL_REQUEST" in ids
    assert "LINK_SHORTENER" in ids
    assert "EXTERNAL_DM_WITH_LINK" in ids
    assert ids.isdisjoint(_EMAIL_ONLY_INDICATOR_IDS)
    assert body["summary"]["channel"] == "slack"
    assert body["summary"]["is_direct_message"] is True


def test_benign_chat_message_returns_safe_verdict_with_no_indicators(authed_client):
    response = authed_client.post(
        "/api/messages/analyze",
        json={
            "channel": "teams",
            "channel_name": "19:general@thread.tacv2",
            "from_display": "Alice Smith",
            "from_address": "alice@corp.com",
            "is_direct_message": False,
            "is_external_sender": False,
            "text": "Good morning team! Standup in 10 minutes.",
        },
    )
    assert response.status_code == 200
    body = response.json()

    assert body["verdict"] == "safe"
    assert body["indicators"] == []


def test_analyzed_message_persists_as_a_case_with_channel_and_is_filterable(authed_client):
    response = authed_client.post(
        "/api/messages/analyze",
        json={
            "channel": "slack",
            "from_display": "bob",
            "from_address": "bob@corp.com",
            "text": "hello world",
        },
    )
    assert response.status_code == 200
    case_id = response.json()["id"]

    cases_response = authed_client.get("/api/cases", params={"channel": "slack"})
    assert cases_response.status_code == 200
    items = cases_response.json()["items"]
    assert any(item["id"] == case_id and item["channel"] == "slack" for item in items)

    detail_response = authed_client.get(f"/api/cases/{case_id}")
    assert detail_response.status_code == 200
    assert detail_response.json()["channel"] == "slack"

    email_only_response = authed_client.get("/api/cases", params={"channel": "email"})
    assert email_only_response.status_code == 200
    assert all(item["id"] != case_id for item in email_only_response.json()["items"])
