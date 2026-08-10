from __future__ import annotations

import email
from email.message import EmailMessage
from email.mime.message import MIMEMessage
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

from app.inbound.unwrap import unwrap_forwarded_email
from app.parsing.eml_parser import parse_eml


def _phishing_original_raw() -> bytes:
    return (
        b"From: Attacker <attacker@evil.com>\r\n"
        b"Subject: Urgent: verify your account\r\n"
        b"To: victim@corp.com\r\n"
        b"\r\n"
        b"Click here to verify: http://evil.com/verify\r\n"
    )


def test_message_rfc822_attachment_is_extracted_at_full_fidelity():
    original_msg = email.message_from_bytes(_phishing_original_raw())

    wrapper = MIMEMultipart()
    wrapper["From"] = "Alice <alice@corp.com>"
    wrapper["Subject"] = "Fwd: Urgent: verify your account"
    wrapper["To"] = "soc@corp.com"
    wrapper.attach(MIMEText("FYI, see attached — this looks sketchy."))
    wrapper.attach(MIMEMessage(original_msg))

    unwrapped = unwrap_forwarded_email(wrapper.as_bytes())
    parsed = parse_eml(unwrapped)

    assert parsed.from_address == "attacker@evil.com"
    assert parsed.subject == "Urgent: verify your account"


def test_gmail_style_text_marker_forward_is_unwrapped():
    wrapper = EmailMessage()
    wrapper["From"] = "Alice <alice@corp.com>"
    wrapper["Subject"] = "Fwd: Urgent: verify your account"
    wrapper["To"] = "soc@corp.com"
    wrapper.set_content(
        "FYI, forwarding this, looks sketchy.\n\n"
        "---------- Forwarded message ---------\n"
        "From: Attacker <attacker@evil.com>\n"
        "Date: Mon, Jan 5, 2026 at 9:00 AM\n"
        "Subject: Urgent: verify your account\n"
        "To: <victim@corp.com>\n\n"
        "Click here to verify: http://evil.com/verify\n"
    )

    unwrapped = unwrap_forwarded_email(wrapper.as_bytes())
    parsed = parse_eml(unwrapped)

    assert parsed.from_address == "attacker@evil.com"
    assert parsed.subject == "Urgent: verify your account"
    assert "verify" in parsed.body_text.lower()
    # The forwarder's own note is not treated as part of the original message.
    assert "sketchy" not in parsed.body_text.lower()


def test_apple_mail_style_text_marker_forward_is_unwrapped():
    wrapper = EmailMessage()
    wrapper["From"] = "Bob <bob@corp.com>"
    wrapper["Subject"] = "Fwd: check this"
    wrapper.set_content(
        "See below.\n\n"
        "Begin forwarded message:\n\n"
        "From: Attacker <attacker@evil.com>\n"
        "Subject: Account Suspended\n"
        "Date: January 5, 2026 at 9:00:00 AM EST\n"
        "To: victim@corp.com\n\n"
        "Your account has been suspended, click here.\n"
    )

    unwrapped = unwrap_forwarded_email(wrapper.as_bytes())
    parsed = parse_eml(unwrapped)

    assert parsed.from_address == "attacker@evil.com"
    assert parsed.subject == "Account Suspended"


def test_outlook_style_text_marker_forward_is_unwrapped():
    wrapper = EmailMessage()
    wrapper["From"] = "Carol <carol@corp.com>"
    wrapper["Subject"] = "FW: important"
    wrapper.set_content(
        "please review\n\n"
        "-----Original Message-----\n"
        "From: Attacker <attacker@evil.com>\n"
        "Sent: Monday, January 5, 2026 9:00 AM\n"
        "To: victim@corp.com\n"
        "Subject: Wire transfer needed\n\n"
        "Please wire funds immediately.\n"
    )

    unwrapped = unwrap_forwarded_email(wrapper.as_bytes())
    parsed = parse_eml(unwrapped)

    assert parsed.from_address == "attacker@evil.com"
    assert parsed.subject == "Wire transfer needed"


def test_no_marker_returns_the_input_unchanged():
    plain = EmailMessage()
    plain["From"] = "attacker@evil.com"
    plain["Subject"] = "Urgent"
    plain.set_content("just the raw phishing email, no forwarding wrapper at all")

    raw = plain.as_bytes()
    assert unwrap_forwarded_email(raw) == raw


def test_marker_with_no_recognizable_header_block_falls_back_unchanged():
    wrapper = EmailMessage()
    wrapper["From"] = "alice@corp.com"
    wrapper["Subject"] = "Fwd: something"
    wrapper.set_content(
        "---------- Forwarded message ---------\n"
        "this text has the marker but no From:/Subject: header lines after it at all\n"
    )

    raw = wrapper.as_bytes()
    # Can't confidently reconstruct an original message from this — stay with the wrapper
    # rather than guessing.
    assert unwrap_forwarded_email(raw) == raw


def test_unparseable_bytes_do_not_raise():
    garbage = b"\x00\x01not an email at all\xff\xfe"
    assert unwrap_forwarded_email(garbage) == garbage
