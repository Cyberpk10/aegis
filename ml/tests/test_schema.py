from __future__ import annotations

from aegis_ml.schema import EmailRecord, Label, Source


def test_email_record_to_dict_serializes_enums_as_strings():
    record = EmailRecord(
        id="abc",
        raw_headers="From: attacker@example.com\n",
        subject="Hi",
        body_text="Body",
        from_addr="attacker@example.com",
        label=Label.PHISHING,
        source=Source.NAZARIO,
    )

    d = record.to_dict()

    assert d["id"] == "abc"
    assert d["label"] == "phishing"
    assert d["source"] == "nazario"
    assert d["from_addr"] == "attacker@example.com"


def test_email_record_allows_missing_from_addr():
    record = EmailRecord(
        id="abc",
        raw_headers="",
        subject="",
        body_text="",
        from_addr=None,
        label=Label.BENIGN,
        source=Source.ENRON,
    )

    assert record.to_dict()["from_addr"] is None
