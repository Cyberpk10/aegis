"""Sender/Reply-To mismatch and display-name spoofing checks."""

from __future__ import annotations

import re

from app.indicators.base import make_indicator
from app.indicators.domain_utils import registrable_domain
from app.models.schemas import Indicator, Severity
from app.channels.message import Message

_EMAIL_IN_TEXT_RE = re.compile(r"[\w.+-]+@[\w-]+\.[a-zA-Z]{2,}")


def _domain(address: str | None) -> str | None:
    if not address or "@" not in address:
        return None
    return address.rsplit("@", 1)[-1].lower()


def evaluate(email: Message) -> list[Indicator]:
    indicators: list[Indicator] = []

    from_domain = _domain(email.from_address)
    reply_to_domain = _domain(email.reply_to_address)

    if from_domain and reply_to_domain and registrable_domain(from_domain) != registrable_domain(
        reply_to_domain
    ):
        indicators.append(
            make_indicator(
                id="SENDER_REPLYTO_MISMATCH",
                category="sender",
                title="From and Reply-To domains differ",
                description=(
                    "The email's From address and Reply-To address point to different domains. "
                    "This is commonly used so replies (e.g. to a credential or payment request) "
                    "go to an attacker-controlled mailbox instead of the apparent sender."
                ),
                evidence=[
                    f"From: {email.from_address} (domain: {from_domain})",
                    f"Reply-To: {email.reply_to_address} (domain: {reply_to_domain})",
                ],
                severity=Severity.MEDIUM,
                score=15,
            )
        )

    if email.from_display:
        embedded_emails = {
            m.group(0).lower() for m in _EMAIL_IN_TEXT_RE.finditer(email.from_display)
        }
        actual = (email.from_address or "").lower()
        mismatched = {addr for addr in embedded_emails if addr != actual}
        if mismatched:
            indicators.append(
                make_indicator(
                    id="DISPLAY_NAME_EMAIL_MISMATCH",
                    category="sender",
                    title="Display name contains a different email address",
                    description=(
                        "The From header's display name itself contains an email address that "
                        "does not match the actual sending address — a common way to make a "
                        "spoofed message look like it came from a trusted mailbox."
                    ),
                    evidence=[
                        f"Display name: {email.from_display!r}",
                        f"Actual From address: {email.from_address}",
                        f"Embedded address(es): {', '.join(sorted(mismatched))}",
                    ],
                    severity=Severity.MEDIUM,
                    score=10,
                )
            )

    return indicators
