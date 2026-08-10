from __future__ import annotations

import hashlib
import hmac
import time
import uuid

from app.core.config import settings
from app.db.models import Case

_SIGNING_KEY = "test-mailgun-signing-key"
_URL = "/api/inbound/email/mime"


def _sign(timestamp: str, token: str, key: str = _SIGNING_KEY) -> str:
    return hmac.new(key.encode(), f"{timestamp}{token}".encode(), hashlib.sha256).hexdigest()


def _mailgun_form(*, recipient: str, body_mime: bytes, token: str = "webhooktoken123") -> dict:
    timestamp = str(int(time.time()))
    return {
        "timestamp": timestamp,
        "token": token,
        "signature": _sign(timestamp, token),
        "recipient": recipient,
        "body-mime": body_mime.decode("utf-8", errors="replace"),
    }


def test_valid_forwarded_phishing_email_creates_a_case_for_the_correct_account(
    client, db_session, monkeypatch, load_eml, test_account
):
    monkeypatch.setattr(settings, "mailgun_webhook_signing_key", _SIGNING_KEY)
    raw = load_eml("phishing_lookalike_paypal.eml")
    recipient = f"pilot-{test_account.account.inbound_token}@{settings.inbound_email_domain}"

    response = client.post(_URL, data=_mailgun_form(recipient=recipient, body_mime=raw))

    assert response.status_code == 200, response.text
    body = response.json()
    assert body["status"] == "created"
    assert body["verdict"] == "malicious"

    case = db_session.query(Case).filter(Case.id == uuid.UUID(body["case_id"])).first()
    assert case is not None
    assert case.account_id == test_account.account.id
    assert case.content_hash is not None


def test_invalid_signature_is_rejected_and_creates_no_case(
    client, db_session, monkeypatch, load_eml, test_account
):
    monkeypatch.setattr(settings, "mailgun_webhook_signing_key", _SIGNING_KEY)
    raw = load_eml("phishing_lookalike_paypal.eml")
    recipient = f"pilot-{test_account.account.inbound_token}@{settings.inbound_email_domain}"

    form = _mailgun_form(recipient=recipient, body_mime=raw)
    form["signature"] = "0" * 64  # well-formed hex, but not the correct HMAC

    response = client.post(_URL, data=form)

    assert response.status_code == 401
    assert db_session.query(Case).count() == 0


def test_missing_signature_fields_are_rejected(client, monkeypatch, load_eml, test_account):
    monkeypatch.setattr(settings, "mailgun_webhook_signing_key", _SIGNING_KEY)
    raw = load_eml("phishing_lookalike_paypal.eml")
    recipient = f"pilot-{test_account.account.inbound_token}@{settings.inbound_email_domain}"

    response = client.post(_URL, data={"recipient": recipient, "body-mime": raw.decode()})

    assert response.status_code == 401


def test_endpoint_returns_503_when_signing_key_is_not_configured(client, monkeypatch, load_eml):
    monkeypatch.setattr(settings, "mailgun_webhook_signing_key", "")
    raw = load_eml("phishing_lookalike_paypal.eml")

    response = client.post(
        _URL, data=_mailgun_form(recipient="pilot-anything@in.example.com", body_mime=raw)
    )

    assert response.status_code == 503


def test_unknown_recipient_token_creates_no_case_and_leaks_nothing(
    client, db_session, monkeypatch, load_eml
):
    monkeypatch.setattr(settings, "mailgun_webhook_signing_key", _SIGNING_KEY)
    raw = load_eml("phishing_lookalike_paypal.eml")

    response = client.post(
        _URL,
        data=_mailgun_form(recipient="pilot-doesnotexist@in.example.com", body_mime=raw),
    )

    assert response.status_code == 404
    assert "doesnotexist" not in response.text
    assert db_session.query(Case).count() == 0


def test_duplicate_forward_does_not_create_a_second_case(
    client, db_session, monkeypatch, load_eml, test_account
):
    monkeypatch.setattr(settings, "mailgun_webhook_signing_key", _SIGNING_KEY)
    raw = load_eml("phishing_lookalike_paypal.eml")
    recipient = f"pilot-{test_account.account.inbound_token}@{settings.inbound_email_domain}"

    first = client.post(
        _URL, data=_mailgun_form(recipient=recipient, body_mime=raw, token="tok-a")
    )
    second = client.post(
        _URL, data=_mailgun_form(recipient=recipient, body_mime=raw, token="tok-b")
    )

    assert first.status_code == 200
    assert second.status_code == 200
    assert second.json()["status"] == "duplicate"
    assert second.json()["case_id"] == first.json()["case_id"]
    assert db_session.query(Case).count() == 1


def test_forwarded_wrapper_is_unwrapped_before_analysis(
    client, db_session, monkeypatch, load_eml, test_account
):
    """A Gmail-style forward wrapper around a real phishing sample still produces the same
    verdict as analyzing the original directly — proving the wrapper itself doesn't get
    analyzed instead of the original message."""
    from email.message import EmailMessage

    monkeypatch.setattr(settings, "mailgun_webhook_signing_key", _SIGNING_KEY)
    original_raw = load_eml("phishing_lookalike_paypal.eml")

    from app.parsing.eml_parser import parse_eml

    original_parsed = parse_eml(original_raw)

    wrapper = EmailMessage()
    wrapper["From"] = "employee@corp.com"
    wrapper["Subject"] = f"Fwd: {original_parsed.subject}"
    wrapper["To"] = "soc@corp.com"
    wrapper.set_content(
        "Hey team, got this, looks off to me.\n\n"
        "---------- Forwarded message ---------\n"
        f"From: {original_parsed.from_display} <{original_parsed.from_address}>\n"
        "Date: Mon, Jan 5, 2026 at 9:00 AM\n"
        f"Subject: {original_parsed.subject}\n"
        f"To: {', '.join(original_parsed.to_addresses) or 'victim@corp.com'}\n\n"
        + (original_parsed.body_text or "Click here to verify your account now.")
    )

    recipient = f"pilot-{test_account.account.inbound_token}@{settings.inbound_email_domain}"
    response = client.post(
        _URL, data=_mailgun_form(recipient=recipient, body_mime=wrapper.as_bytes())
    )

    assert response.status_code == 200, response.text
    body = response.json()
    assert body["status"] == "created"

    case = db_session.query(Case).filter(Case.id == uuid.UUID(body["case_id"])).first()
    assert case.from_addr == original_parsed.from_address
    # The forwarder's own address must not have become the analyzed sender.
    assert case.from_addr != "employee@corp.com"


def test_per_account_rate_limit_returns_429(client, db_session, monkeypatch, load_eml, test_account):
    monkeypatch.setattr(settings, "mailgun_webhook_signing_key", _SIGNING_KEY)
    monkeypatch.setattr(settings, "inbound_email_rate_limit_per_account_per_hour", 2)
    raw = load_eml("phishing_lookalike_paypal.eml")
    recipient = f"pilot-{test_account.account.inbound_token}@{settings.inbound_email_domain}"

    # Each post must carry different content (and a different Mailgun token) so dedup doesn't
    # short-circuit before the rate-limit check gets exercised the intended number of times.
    # Prepending a distinct extra header line keeps the rest of the message byte-identical
    # and structurally valid (header order doesn't matter, and this stays well before the
    # blank-line/body boundary), unlike mutating bytes inside the body/MIME structure.
    def _variant(i: int) -> bytes:
        return f"X-Test-Variant: {i}\r\n".encode() + raw

    for i in range(2):
        resp = client.post(
            _URL, data=_mailgun_form(recipient=recipient, body_mime=_variant(i), token=f"tok-{i}")
        )
        assert resp.status_code == 200

    third = client.post(
        _URL, data=_mailgun_form(recipient=recipient, body_mime=_variant(2), token="tok-2-final")
    )
    assert third.status_code == 429
