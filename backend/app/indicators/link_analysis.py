"""Link-based indicators: display-vs-href mismatch, shorteners, suspicious TLDs, IP-literal hosts."""

from __future__ import annotations

import re

from app.indicators.base import make_indicator
from app.indicators.domain_utils import is_ip_literal_host, registrable_domain
from app.models.schemas import Indicator, Severity
from app.channels.message import Message

_KNOWN_SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly",
    "rebrand.ly", "cutt.ly", "shorturl.at", "rb.gy", "tiny.cc", "s.id",
}

_SUSPICIOUS_TLDS = {
    "zip", "mov", "top", "xyz", "click", "support", "gq", "tk", "ml", "cf",
    "work", "link", "rest", "country", "kim", "loan", "men", "date", "review",
    "download", "stream", "gdn", "icu",
}

# A bare-domain-looking string such as "paypal.com" or "www.example.com" appearing as link text.
_DOMAIN_LIKE_TEXT_RE = re.compile(
    r"^(?:https?://)?(?:www\.)?([a-z0-9][a-z0-9-]*\.)+[a-z]{2,}(?:/\S*)?$", re.IGNORECASE
)


def _tld_of(domain: str) -> str:
    return domain.rsplit(".", 1)[-1].lower()


def _display_text_domain(display_text: str) -> str | None:
    text = display_text.strip()
    if not _DOMAIN_LIKE_TEXT_RE.match(text):
        return None
    stripped = text.split("://", 1)[-1].split("/", 1)[0]
    return stripped.lower()


def evaluate(email: Message) -> list[Indicator]:
    mismatch_evidence: list[str] = []
    shortener_evidence: list[str] = []
    suspicious_tld_evidence: list[str] = []
    ip_literal_evidence: list[str] = []

    for link in email.links:
        href_domain = link.href_domain
        if not href_domain:
            continue

        display_domain = _display_text_domain(link.display_text)
        if display_domain and registrable_domain(display_domain) != registrable_domain(href_domain):
            mismatch_evidence.append(
                f"Displayed '{link.display_text.strip()}' links to '{link.href}' (domain: {href_domain})"
            )

        if href_domain in _KNOWN_SHORTENERS:
            shortener_evidence.append(f"{href_domain} ({link.href})")

        if _tld_of(href_domain) in _SUSPICIOUS_TLDS:
            suspicious_tld_evidence.append(f"{href_domain} ({link.href})")

        if is_ip_literal_host(href_domain):
            ip_literal_evidence.append(link.href)

    indicators: list[Indicator] = []

    if mismatch_evidence:
        indicators.append(
            make_indicator(
                id="LINK_DISPLAY_HREF_MISMATCH",
                category="link",
                title="Link display text does not match its destination",
                description=(
                    "One or more links show a domain or URL as their visible text but actually "
                    "point somewhere else — a classic technique to disguise a malicious "
                    "destination as a trusted one."
                ),
                evidence=mismatch_evidence,
                severity=Severity.HIGH,
                score=20,
            )
        )

    if shortener_evidence:
        indicators.append(
            make_indicator(
                id="LINK_SHORTENER",
                category="link",
                title="URL shortener used",
                description=(
                    "The message contains a link through a URL-shortening service, which hides "
                    "the true destination from the recipient."
                ),
                evidence=shortener_evidence,
                severity=Severity.MEDIUM,
                score=10,
            )
        )

    if suspicious_tld_evidence:
        indicators.append(
            make_indicator(
                id="LINK_SUSPICIOUS_TLD",
                category="link",
                title="Link uses a top-level domain commonly abused for phishing",
                description=(
                    "One or more links use a top-level domain that is disproportionately "
                    "associated with phishing and malware campaigns."
                ),
                evidence=suspicious_tld_evidence,
                severity=Severity.MEDIUM,
                score=10,
            )
        )

    if ip_literal_evidence:
        indicators.append(
            make_indicator(
                id="LINK_IP_LITERAL",
                category="link",
                title="Link points directly to an IP address",
                description=(
                    "A link uses a raw IP address instead of a domain name, which is unusual "
                    "for legitimate business communication and often used to evade domain-based "
                    "reputation filtering."
                ),
                evidence=ip_literal_evidence,
                severity=Severity.MEDIUM,
                score=15,
            )
        )

    return indicators
