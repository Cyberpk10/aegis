"""The channel-agnostic message shape every indicator runs against (M7 Stage B).

`Message` generalizes what used to be email-only `ParsedEmail` — every existing indicator
already only reads specific fields (subject/body_text for text indicators, links for link
indicators, auth_results for auth indicators, etc.), so a Slack/Teams message that leaves
email-only fields at their defaults makes those indicators self-skip for free: no
`if channel == EMAIL` branching needed anywhere in the indicator engine. `app.parsing.eml_parser`
re-exports `Message` as `ParsedEmail` for backward compatibility — every existing indicator/test
construction call site (`ParsedEmail(subject=..., body_text=...)`) keeps working unchanged.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import Enum
from urllib.parse import urlsplit

from app.models.schemas import AuthResults

_URL_RE = re.compile(r"https?://[^\s<>\"'()]+", re.IGNORECASE)


class Channel(str, Enum):
    EMAIL = "email"
    SLACK = "slack"
    TEAMS = "teams"


@dataclass
class Link:
    display_text: str
    href: str
    href_domain: str | None


@dataclass
class Attachment:
    filename: str
    content_type: str | None
    size_bytes: int


@dataclass
class Message:
    channel: Channel = Channel.EMAIL
    headers: dict[str, str] = field(default_factory=dict)
    from_display: str | None = None
    from_address: str | None = None
    reply_to_address: str | None = None
    to_addresses: list[str] = field(default_factory=list)
    subject: str | None = None
    date: str | None = None
    auth_results: AuthResults = field(default_factory=AuthResults)
    body_text: str = ""
    body_html: str = ""
    links: list[Link] = field(default_factory=list)
    attachments: list[Attachment] = field(default_factory=list)
    # Chat-oriented (M7 Stage B) — all default to email-safe values so every existing
    # construction call site and indicator is unaffected.
    mentions: list[str] = field(default_factory=list)
    is_direct_message: bool = False
    is_external_sender: bool = False
    channel_name: str | None = None


def domain_of(url: str) -> str | None:
    """Registrable host of a URL, lowercased, userinfo/port stripped. Shared by the chat
    adapters — email's link extraction lives entirely in app.parsing.eml_parser and is left
    untouched, this is an independent (smaller — plain-text-only, no HTML `<a>` parsing) helper
    for Slack/Teams message text."""
    try:
        netloc = urlsplit(url).netloc
    except ValueError:
        return None
    if not netloc:
        return None
    netloc = netloc.rsplit("@", 1)[-1]
    netloc = netloc.split(":", 1)[0]
    return netloc.lower() or None


def extract_links_from_text(text: str) -> list[Link]:
    """Plain-text URL extraction for chat messages (no markup to parse, unlike HTML email
    bodies)."""
    links: list[Link] = []
    seen: set[str] = set()
    for match in _URL_RE.finditer(text):
        url = match.group(0)
        if url in seen:
            continue
        seen.add(url)
        links.append(Link(display_text=url, href=url, href_domain=domain_of(url)))
    return links
