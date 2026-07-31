from __future__ import annotations

from app.indicators import lookalike_domain
from app.parsing.eml_parser import Link, ParsedEmail


def test_flags_homoglyph_digit_substitution_domain():
    email = ParsedEmail(from_address="service@paypa1.com")
    ids = {i.id for i in lookalike_domain.evaluate(email)}
    assert "LOOKALIKE_DOMAIN" in ids


def test_flags_punycode_domain():
    email = ParsedEmail(from_address="service@xn--pypal-4ve.com")
    ids = {i.id for i in lookalike_domain.evaluate(email)}
    assert "PUNYCODE_IDN_DOMAIN" in ids


def test_flags_typosquat_within_edit_distance():
    email = ParsedEmail(from_address="service@paypaI.com")  # capital i, still 1-char-off length match
    ids = {i.id for i in lookalike_domain.evaluate(email)}
    assert "LOOKALIKE_DOMAIN" in ids


def test_flags_brand_name_in_unrelated_domain_after_normalization():
    email = ParsedEmail(
        links=[Link(display_text="click here", href="https://paypa1-alerts.com/x", href_domain="paypa1-alerts.com")]
    )
    ids = {i.id for i in lookalike_domain.evaluate(email)}
    assert "LOOKALIKE_DOMAIN" in ids


def test_no_flag_for_legitimate_brand_domain():
    email = ParsedEmail(from_address="service@paypal.com")
    assert lookalike_domain.evaluate(email) == []


def test_no_flag_for_unrelated_ordinary_domain():
    email = ParsedEmail(from_address="hello@acmeweekly.com")
    assert lookalike_domain.evaluate(email) == []
