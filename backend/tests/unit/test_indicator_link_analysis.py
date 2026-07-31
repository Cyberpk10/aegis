from __future__ import annotations

from app.indicators import link_analysis
from app.parsing.eml_parser import Link, ParsedEmail


def test_flags_display_href_domain_mismatch():
    email = ParsedEmail(
        links=[Link(display_text="https://www.bank.com/login", href="https://evil.example/login", href_domain="evil.example")]
    )
    ids = {i.id for i in link_analysis.evaluate(email)}
    assert "LINK_DISPLAY_HREF_MISMATCH" in ids


def test_no_flag_when_display_matches_href_domain():
    email = ParsedEmail(
        links=[Link(display_text="https://bank.com/login", href="https://bank.com/login", href_domain="bank.com")]
    )
    ids = {i.id for i in link_analysis.evaluate(email)}
    assert "LINK_DISPLAY_HREF_MISMATCH" not in ids


def test_flags_known_shortener():
    email = ParsedEmail(
        links=[Link(display_text="click here", href="http://bit.ly/abc123", href_domain="bit.ly")]
    )
    ids = {i.id for i in link_analysis.evaluate(email)}
    assert "LINK_SHORTENER" in ids


def test_flags_suspicious_tld():
    email = ParsedEmail(
        links=[Link(display_text="click here", href="http://secure-login.top/x", href_domain="secure-login.top")]
    )
    ids = {i.id for i in link_analysis.evaluate(email)}
    assert "LINK_SUSPICIOUS_TLD" in ids


def test_flags_ip_literal_host():
    email = ParsedEmail(
        links=[Link(display_text="click here", href="http://192.168.1.1/login", href_domain="192.168.1.1")]
    )
    ids = {i.id for i in link_analysis.evaluate(email)}
    assert "LINK_IP_LITERAL" in ids


def test_no_flags_for_ordinary_link():
    email = ParsedEmail(
        links=[Link(display_text="Read more", href="https://acmeweekly.com/digest", href_domain="acmeweekly.com")]
    )
    assert link_analysis.evaluate(email) == []
