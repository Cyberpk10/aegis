"""Parses raw .eml bytes into a structured, indicator-engine-friendly representation.

Uses only the Python standard library `email` package — no network access, no live SPF/DKIM/DMARC
verification. Authentication results are read from whatever `Authentication-Results` header(s)
already exist on the message.
"""

from __future__ import annotations

import re
from email import policy
from email.message import Message as EmailMessage
from email.parser import BytesParser
from email.utils import getaddresses, parseaddr
from html.parser import HTMLParser
from urllib.parse import urlsplit

from app.channels.message import Attachment, Channel, Link, Message
from app.parsing.auth_results import parse_authentication_results

_URL_RE = re.compile(r"https?://[^\s<>\"'()]+", re.IGNORECASE)

_MACRO_ENABLED_EXTENSIONS = {".docm", ".xlsm", ".pptm", ".dotm", ".xltm", ".potm"}

# Backward-compat alias — every existing indicator/test constructs `ParsedEmail(...)` and
# imports it from this module; Message *is* ParsedEmail generalized to other channels, not a
# separate type, so this alias means none of those call sites need to change.
ParsedEmail = Message


class _LinkExtractor(HTMLParser):
    """Collects (display text, href) pairs from `<a>` tags in an HTML body."""

    def __init__(self) -> None:
        super().__init__()
        self._current_href: str | None = None
        self._current_text: list[str] = []
        self.links: list[tuple[str, str]] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag.lower() != "a":
            return
        href = next((v for k, v in attrs if k.lower() == "href" and v), None)
        if href:
            self._current_href = href
            self._current_text = []

    def handle_data(self, data: str) -> None:
        if self._current_href is not None:
            self._current_text.append(data)

    def handle_endtag(self, tag: str) -> None:
        if tag.lower() != "a" or self._current_href is None:
            return
        text = "".join(self._current_text).strip()
        self.links.append((text, self._current_href))
        self._current_href = None
        self._current_text = []


def _domain_of(url: str) -> str | None:
    try:
        netloc = urlsplit(url).netloc
    except ValueError:
        return None
    if not netloc:
        return None
    # Strip userinfo and port.
    netloc = netloc.rsplit("@", 1)[-1]
    netloc = netloc.split(":", 1)[0]
    return netloc.lower() or None


def _extract_links(body_html: str, body_text: str) -> list[Link]:
    links: list[Link] = []
    seen: set[tuple[str, str]] = set()

    if body_html:
        extractor = _LinkExtractor()
        try:
            extractor.feed(body_html)
        except Exception:
            pass
        for display_text, href in extractor.links:
            key = (display_text, href)
            if key in seen:
                continue
            seen.add(key)
            links.append(Link(display_text=display_text, href=href, href_domain=_domain_of(href)))

    for match in _URL_RE.finditer(body_text):
        url = match.group(0)
        key = (url, url)
        if key in seen:
            continue
        seen.add(key)
        links.append(Link(display_text=url, href=url, href_domain=_domain_of(url)))

    return links


def _walk_body_and_attachments(msg: EmailMessage) -> tuple[str, str, list[Attachment]]:
    body_text_parts: list[str] = []
    body_html_parts: list[str] = []
    attachments: list[Attachment] = []

    for part in msg.walk():
        if part.is_multipart():
            continue

        content_disposition = (part.get_content_disposition() or "").lower()
        content_type = part.get_content_type()
        filename = part.get_filename()

        if content_disposition == "attachment" or (filename and content_disposition != "inline"):
            try:
                payload = part.get_payload(decode=True) or b""
            except Exception:
                payload = b""
            attachments.append(
                Attachment(
                    filename=filename or "(unnamed)",
                    content_type=content_type,
                    size_bytes=len(payload),
                )
            )
            continue

        if content_type == "text/plain":
            body_text_parts.append(part.get_content())
        elif content_type == "text/html":
            body_html_parts.append(part.get_content())

    return "\n".join(body_text_parts), "\n".join(body_html_parts), attachments


def parse_eml(raw_bytes: bytes) -> ParsedEmail:
    """Parse raw .eml bytes into a ParsedEmail."""
    msg = BytesParser(policy=policy.default).parsebytes(raw_bytes)

    headers = {key: str(value) for key, value in msg.items()}

    from_display, from_address = parseaddr(msg.get("From", "") or "")
    reply_to_raw = msg.get("Reply-To", "") or ""
    _, reply_to_address = parseaddr(reply_to_raw)

    to_addresses = [addr for _, addr in getaddresses(msg.get_all("To", []) or []) if addr]

    auth_result_headers = [str(h) for h in (msg.get_all("Authentication-Results", []) or [])]
    auth_results = parse_authentication_results(auth_result_headers)

    body_text, body_html, attachments = _walk_body_and_attachments(msg)
    links = _extract_links(body_html, body_text)

    return ParsedEmail(
        channel=Channel.EMAIL,
        headers=headers,
        from_display=from_display or None,
        from_address=from_address or None,
        reply_to_address=reply_to_address or None,
        to_addresses=to_addresses,
        subject=msg.get("Subject"),
        date=msg.get("Date"),
        auth_results=auth_results,
        body_text=body_text,
        body_html=body_html,
        links=links,
        attachments=attachments,
    )


def is_macro_enabled_filename(filename: str) -> bool:
    lowered = filename.lower()
    return any(lowered.endswith(ext) for ext in _MACRO_ENABLED_EXTENSIONS)
