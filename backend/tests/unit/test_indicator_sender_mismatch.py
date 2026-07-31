from __future__ import annotations

from app.indicators import sender_mismatch
from app.parsing.eml_parser import ParsedEmail


def test_flags_reply_to_domain_mismatch():
    email = ParsedEmail(from_address="ceo@acme.com", reply_to_address="ceo@totally-different.net")
    ids = {i.id for i in sender_mismatch.evaluate(email)}
    assert "SENDER_REPLYTO_MISMATCH" in ids


def test_no_flag_when_reply_to_matches():
    email = ParsedEmail(from_address="ceo@acme.com", reply_to_address="finance@acme.com")
    ids = {i.id for i in sender_mismatch.evaluate(email)}
    assert "SENDER_REPLYTO_MISMATCH" not in ids


def test_no_flag_when_reply_to_absent():
    email = ParsedEmail(from_address="ceo@acme.com", reply_to_address=None)
    assert sender_mismatch.evaluate(email) == []


def test_flags_embedded_email_in_display_name():
    email = ParsedEmail(
        from_display="billing@realcompany.com",
        from_address="attacker@evil-domain.com",
    )
    ids = {i.id for i in sender_mismatch.evaluate(email)}
    assert "DISPLAY_NAME_EMAIL_MISMATCH" in ids


def test_no_flag_when_display_name_email_matches_from():
    email = ParsedEmail(
        from_display="billing@realcompany.com",
        from_address="billing@realcompany.com",
    )
    ids = {i.id for i in sender_mismatch.evaluate(email)}
    assert "DISPLAY_NAME_EMAIL_MISMATCH" not in ids
