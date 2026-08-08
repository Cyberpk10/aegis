"""Shared email.message.Message -> EmailRecord field extraction, used by both the mbox
parser (Nazario, SpamAssassin) and the maildir-style parser (Enron)."""

from __future__ import annotations

import uuid
from email.header import decode_header
from email.message import Message
from email.utils import parseaddr
from html.parser import HTMLParser

from aegis_ml.schema import EmailRecord, Label, Source

_ID_NAMESPACE = uuid.UUID("a3f1b5c2-7e4d-4b8a-9c1e-6d2f8a0b3c4d")


def make_id(source: Source, original_id: str) -> str:
    """Deterministic id so re-running the pipeline against the same raw data produces
    stable ids (uuid5, not random)."""
    return str(uuid.uuid5(_ID_NAMESPACE, f"{source.value}:{original_id}"))


def _decode_header_value(raw_value: str | None) -> str:
    if not raw_value:
        return ""
    parts = []
    for chunk, encoding in decode_header(raw_value):
        if isinstance(chunk, bytes):
            try:
                parts.append(chunk.decode(encoding or "utf-8", errors="replace"))
            except LookupError:
                # Some real-world messages carry invalid/nonstandard charset labels
                # (e.g. "unknown-8bit") that Python doesn't recognize as a codec.
                parts.append(chunk.decode("utf-8", errors="replace"))
        else:
            parts.append(chunk)
    return "".join(parts)


class _HTMLTextExtractor(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self._chunks: list[str] = []

    def handle_data(self, data: str) -> None:
        self._chunks.append(data)

    def text(self) -> str:
        return " ".join(chunk.strip() for chunk in self._chunks if chunk.strip())


def html_to_text(html: str) -> str:
    extractor = _HTMLTextExtractor()
    extractor.feed(html)
    return extractor.text()


def _decode_part(part: Message) -> str:
    payload = part.get_payload(decode=True) or b""
    charset = part.get_content_charset() or "utf-8"
    try:
        return payload.decode(charset, errors="replace")
    except LookupError:
        return payload.decode("utf-8", errors="replace")


def _extract_body(msg: Message) -> str:
    if not msg.is_multipart():
        text = _decode_part(msg)
        if msg.get_content_type() == "text/html":
            return html_to_text(text)
        return text

    plain_parts, html_parts = [], []
    for part in msg.walk():
        if part.is_multipart() or part.get_content_disposition() == "attachment":
            continue
        content_type = part.get_content_type()
        if content_type == "text/plain":
            plain_parts.append(_decode_part(part))
        elif content_type == "text/html":
            html_parts.append(_decode_part(part))

    if plain_parts:
        return "\n".join(plain_parts)
    if html_parts:
        return "\n".join(html_to_text(html) for html in html_parts)
    return ""


def record_from_message(
    msg: Message, *, source: Source, label: Label, original_id: str
) -> EmailRecord:
    raw_headers = "\n".join(f"{key}: {value}" for key, value in msg.items())
    subject = _decode_header_value(msg.get("Subject"))
    from_addr = parseaddr(msg.get("From", ""))[1] or None
    body_text = _extract_body(msg)

    return EmailRecord(
        id=make_id(source, original_id),
        raw_headers=raw_headers,
        subject=subject,
        body_text=body_text,
        from_addr=from_addr,
        label=label,
        source=source,
    )
