from __future__ import annotations

import hashlib
import hmac
import time

from app.inbound.mailgun import extract_raw_email, verify_signature

_SIGNING_KEY = "test-signing-key"


def _sign(timestamp: str, token: str, key: str = _SIGNING_KEY) -> str:
    return hmac.new(key.encode(), f"{timestamp}{token}".encode(), hashlib.sha256).hexdigest()


def test_valid_signature_is_accepted():
    timestamp = str(int(time.time()))
    token = "abc123token"
    signature = _sign(timestamp, token)

    assert verify_signature(
        timestamp=timestamp, token=token, signature=signature,
        signing_key=_SIGNING_KEY, max_age_seconds=900,
    ) is True


def test_tampered_signature_is_rejected():
    timestamp = str(int(time.time()))
    token = "abc123token"
    signature = _sign(timestamp, token)
    tampered = signature[:-1] + ("0" if signature[-1] != "0" else "1")

    assert verify_signature(
        timestamp=timestamp, token=token, signature=tampered,
        signing_key=_SIGNING_KEY, max_age_seconds=900,
    ) is False


def test_signature_signed_with_a_different_key_is_rejected():
    timestamp = str(int(time.time()))
    token = "abc123token"
    signature = _sign(timestamp, token, key="a-different-key")

    assert verify_signature(
        timestamp=timestamp, token=token, signature=signature,
        signing_key=_SIGNING_KEY, max_age_seconds=900,
    ) is False


def test_stale_timestamp_beyond_max_age_is_rejected():
    old_timestamp = str(int(time.time()) - 3600)
    token = "abc123token"
    signature = _sign(old_timestamp, token)

    assert verify_signature(
        timestamp=old_timestamp, token=token, signature=signature,
        signing_key=_SIGNING_KEY, max_age_seconds=900,
    ) is False


def test_missing_fields_are_rejected_without_raising():
    assert verify_signature(
        timestamp="", token="", signature="", signing_key=_SIGNING_KEY, max_age_seconds=900
    ) is False
    assert verify_signature(
        timestamp="not-a-number", token="t", signature="s",
        signing_key=_SIGNING_KEY, max_age_seconds=900,
    ) is False


def test_unset_signing_key_always_rejects():
    timestamp = str(int(time.time()))
    token = "abc123token"
    signature = _sign(timestamp, token, key="")

    assert verify_signature(
        timestamp=timestamp, token=token, signature=signature,
        signing_key="", max_age_seconds=900,
    ) is False


def test_extract_raw_email_prefers_body_mime():
    raw = extract_raw_email({"body-mime": "From: a@b.com\r\nSubject: x\r\n\r\nbody\r\n"})
    assert b"From: a@b.com" in raw


def test_extract_raw_email_synthesizes_from_parsed_fields_when_body_mime_is_absent():
    raw = extract_raw_email(
        {
            "from": "attacker@evil.com",
            "recipient": "pilot-abc123@in.example.com",
            "subject": "Urgent",
            "body-plain": "click here",
        }
    )
    assert b"attacker@evil.com" in raw
    assert b"Urgent" in raw
