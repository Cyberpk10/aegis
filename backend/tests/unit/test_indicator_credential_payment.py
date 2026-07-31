from __future__ import annotations

from app.indicators import credential_payment
from app.parsing.eml_parser import ParsedEmail


def test_flags_credential_request_language():
    email = ParsedEmail(body_text="Please verify your password to continue using our service.")
    ids = {i.id for i in credential_payment.evaluate(email)}
    assert ids == {"CREDENTIAL_REQUEST"}


def test_flags_payment_request_language():
    email = ParsedEmail(body_text="Please process a wire transfer to the account below today.")
    ids = {i.id for i in credential_payment.evaluate(email)}
    assert ids == {"PAYMENT_REQUEST"}


def test_flags_both_when_both_present():
    email = ParsedEmail(
        body_text="Verify your account and then process the wire transfer immediately."
    )
    ids = {i.id for i in credential_payment.evaluate(email)}
    assert ids == {"CREDENTIAL_REQUEST", "PAYMENT_REQUEST"}


def test_no_flag_for_legitimate_password_reset_language():
    email = ParsedEmail(
        body_text="We received a request to reset your password. If you didn't request this, ignore it."
    )
    assert credential_payment.evaluate(email) == []


def test_no_flag_for_neutral_text():
    email = ParsedEmail(body_text="Here is your weekly newsletter digest.")
    assert credential_payment.evaluate(email) == []
