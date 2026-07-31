from __future__ import annotations

from app.indicators import attachment_risk
from app.parsing.eml_parser import Attachment, ParsedEmail


def test_flags_risky_extension():
    email = ParsedEmail(attachments=[Attachment(filename="invoice.exe", content_type=None, size_bytes=100)])
    ids = {i.id for i in attachment_risk.evaluate(email)}
    assert "ATTACHMENT_RISKY_EXTENSION" in ids


def test_flags_double_extension():
    email = ParsedEmail(attachments=[Attachment(filename="invoice.pdf.exe", content_type=None, size_bytes=100)])
    ids = {i.id for i in attachment_risk.evaluate(email)}
    assert "ATTACHMENT_DOUBLE_EXTENSION" in ids
    assert "ATTACHMENT_RISKY_EXTENSION" in ids


def test_flags_macro_enabled_document():
    email = ParsedEmail(attachments=[Attachment(filename="report.docm", content_type=None, size_bytes=100)])
    ids = {i.id for i in attachment_risk.evaluate(email)}
    assert "ATTACHMENT_MACRO_ENABLED" in ids


def test_no_flags_for_ordinary_pdf():
    email = ParsedEmail(attachments=[Attachment(filename="invoice.pdf", content_type="application/pdf", size_bytes=100)])
    assert attachment_risk.evaluate(email) == []


def test_no_flags_when_no_attachments():
    email = ParsedEmail(attachments=[])
    assert attachment_risk.evaluate(email) == []
