from __future__ import annotations

from app.models.schemas import AuthResultValue


def test_parses_basic_headers(parse_fixture):
    email = parse_fixture("benign_newsletter.eml")
    assert email.from_address == "newsletter@acmeweekly.com"
    assert email.from_display == "Acme Weekly"
    assert email.subject == "Your Weekly Digest - Top Stories This Week"
    assert "subscriber@example.com" in email.to_addresses


def test_parses_authentication_results(parse_fixture):
    email = parse_fixture("benign_newsletter.eml")
    assert email.auth_results.spf == AuthResultValue.PASS
    assert email.auth_results.dkim == AuthResultValue.PASS
    assert email.auth_results.dmarc == AuthResultValue.PASS


def test_parses_reply_to(parse_fixture):
    email = parse_fixture("phishing_lookalike_paypal.eml")
    assert email.reply_to_address == "security-team@secure-mailer.net"


def test_extracts_links_with_display_href_mismatch(parse_fixture):
    email = parse_fixture("phishing_lookalike_paypal.eml")
    assert len(email.links) >= 1
    link = next(l for l in email.links if l.href_domain == "paypa1.com")
    assert "paypal.com" in link.display_text


def test_extracts_attachments(parse_fixture):
    email = parse_fixture("phishing_shortener_credential_harvest.eml")
    assert len(email.attachments) == 1
    assert email.attachments[0].filename == "Password_Reset_Instructions.pdf.exe"


def test_no_attachments_on_plain_email(parse_fixture):
    email = parse_fixture("benign_internal_it_notice.eml")
    assert email.attachments == []
