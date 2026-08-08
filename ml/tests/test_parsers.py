from __future__ import annotations

from aegis_ml.parsers.mbox_parser import iter_mbox_records, iter_single_message_dir_records
from aegis_ml.parsers.maildir_parser import iter_maildir_records
from aegis_ml.schema import Label, Source

MBOX_CONTENT = """From attacker@example.com Mon Jan 01 00:00:00 2001
From: "Attacker" <attacker@example.com>
To: victim@example.com
Subject: Urgent: verify your account
Date: Mon, 01 Jan 2001 00:00:00 -0000
Message-ID: <phish1@example.com>
Content-Type: text/plain; charset="utf-8"

Please verify your account by clicking the link below.
"""

RAW_MESSAGE = (
    b"From: colleague@enron.com\r\n"
    b"To: teammate@enron.com\r\n"
    b"Subject: Q3 numbers\r\n"
    b"Content-Type: text/plain; charset=\"utf-8\"\r\n"
    b"\r\n"
    b"Attached are the Q3 numbers, let me know if anything looks off.\r\n"
)


def test_iter_mbox_records_parses_headers_subject_body_from_addr(tmp_path):
    mbox_path = tmp_path / "phishing0.mbox"
    mbox_path.write_text(MBOX_CONTENT)

    records = list(iter_mbox_records(mbox_path, source=Source.NAZARIO, label=Label.PHISHING))

    assert len(records) == 1
    record = records[0]
    assert record.subject == "Urgent: verify your account"
    assert record.from_addr == "attacker@example.com"
    assert "verify your account" in record.body_text
    assert "Message-ID: <phish1@example.com>" in record.raw_headers
    assert record.label == Label.PHISHING
    assert record.source == Source.NAZARIO


def test_iter_single_message_dir_records_skips_cmds_file(tmp_path):
    directory = tmp_path / "easy_ham"
    directory.mkdir()
    (directory / "0001.txt").write_bytes(RAW_MESSAGE)
    (directory / "cmds").write_text("not an email")

    records = list(
        iter_single_message_dir_records(directory, source=Source.SPAMASSASSIN, label=Label.BENIGN)
    )

    assert len(records) == 1
    assert records[0].subject == "Q3 numbers"
    assert records[0].from_addr == "colleague@enron.com"
    assert records[0].label == Label.BENIGN


def test_iter_maildir_records_parses_enron_style_messages(tmp_path):
    directory = tmp_path / "enron_sample"
    directory.mkdir()
    (directory / "skilling-j___sent_mail__114.eml").write_bytes(RAW_MESSAGE)

    records = list(iter_maildir_records(directory, source=Source.ENRON, label=Label.BENIGN))

    assert len(records) == 1
    assert records[0].source == Source.ENRON
    assert records[0].body_text.startswith("Attached are the Q3 numbers")


def test_invalid_charset_label_in_subject_does_not_crash(tmp_path):
    # Some real-world messages carry nonstandard charset labels (e.g. "unknown-8bit")
    # that Python doesn't recognize as a codec — must degrade gracefully, not crash.
    message = (
        b"From: sender@example.com\r\n"
        b"Subject: =?unknown-8bit?Q?Hello?=\r\n"
        b"Content-Type: text/plain; charset=\"utf-8\"\r\n"
        b"\r\n"
        b"Body text.\r\n"
    )
    directory = tmp_path / "bad_charset"
    directory.mkdir()
    (directory / "0001.txt").write_bytes(message)

    records = list(
        iter_single_message_dir_records(directory, source=Source.SPAMASSASSIN, label=Label.BENIGN)
    )

    assert len(records) == 1
    assert "Hello" in records[0].subject


def test_html_only_body_is_stripped_to_text(tmp_path):
    html_message = (
        b"From: newsletter@example.com\r\n"
        b"Subject: Weekly update\r\n"
        b"Content-Type: text/html; charset=\"utf-8\"\r\n"
        b"\r\n"
        b"<html><body><p>Hello <b>World</b></p></body></html>\r\n"
    )
    directory = tmp_path / "html_only"
    directory.mkdir()
    (directory / "0001.txt").write_bytes(html_message)

    records = list(
        iter_single_message_dir_records(directory, source=Source.SPAMASSASSIN, label=Label.BENIGN)
    )

    assert "<html>" not in records[0].body_text
    assert "Hello" in records[0].body_text
    assert "World" in records[0].body_text
