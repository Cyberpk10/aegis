"""Chat-specific indicators (M7 Stage B) — external DMs, public-channel link exposure, and
internal-display-name impersonation. Self-guard on `message.channel != Channel.EMAIL`, same
philosophy as every other indicator's data-presence guard (auth_failures.py only fires on a
non-default AuthResults, etc.) — no branching needed in the engine itself.
"""

from __future__ import annotations

from app.core.config import settings
from app.indicators.base import make_indicator
from app.indicators.domain_utils import is_ip_literal_host
from app.indicators.link_analysis import _KNOWN_SHORTENERS, _SUSPICIOUS_TLDS, _tld_of
from app.channels.message import Channel, Message
from app.models.schemas import Indicator, Severity


def _is_suspicious_link_domain(href_domain: str | None) -> bool:
    if not href_domain:
        return False
    return (
        href_domain in _KNOWN_SHORTENERS
        or _tld_of(href_domain) in _SUSPICIOUS_TLDS
        or is_ip_literal_host(href_domain)
    )


def _matches_protected_name(display_name: str, protected: str) -> bool:
    a = display_name.strip().casefold()
    b = protected.strip().casefold()
    if not a or not b:
        return False
    return a == b or a in b or b in a


def evaluate(message: Message) -> list[Indicator]:
    if message.channel == Channel.EMAIL:
        return []

    indicators: list[Indicator] = []

    if message.is_direct_message and message.is_external_sender and message.links:
        indicators.append(
            make_indicator(
                id="EXTERNAL_DM_WITH_LINK",
                category="chat",
                title="External user sent a direct message containing a link",
                description=(
                    "An account outside the organization direct-messaged a link — a common "
                    "chat-based phishing vector that bypasses email filtering entirely."
                ),
                evidence=[link.href for link in message.links],
                severity=Severity.HIGH,
                score=20,
            )
        )

    if not message.is_direct_message:
        suspicious_links = [
            link.href for link in message.links if _is_suspicious_link_domain(link.href_domain)
        ]
        if suspicious_links:
            indicators.append(
                make_indicator(
                    id="SUSPICIOUS_LINK_PUBLIC_CHANNEL",
                    category="chat",
                    title="Suspicious link posted in a public channel",
                    description=(
                        "A link matching known shortener/suspicious-TLD/IP-literal patterns was "
                        "posted somewhere visible to an entire channel, not just one recipient — "
                        "a wider blast radius than the same link in a single email."
                    ),
                    evidence=suspicious_links,
                    severity=Severity.MEDIUM,
                    score=15,
                )
            )

    protected_names = settings.chat_protected_display_names
    if message.is_external_sender and message.from_display and protected_names:
        matches = [
            name for name in protected_names if _matches_protected_name(message.from_display, name)
        ]
        if matches:
            indicators.append(
                make_indicator(
                    id="IMPERSONATED_DISPLAY_NAME",
                    category="chat",
                    title="External sender's display name matches a protected internal name",
                    description=(
                        "An account outside the organization is using a display name matching "
                        "a protected internal identity — a common impersonation technique in "
                        "chat platforms, where there is no authenticated email domain to check."
                    ),
                    evidence=[f"Display name '{message.from_display}' matches protected name(s): "
                              f"{', '.join(matches)}"],
                    severity=Severity.HIGH,
                    score=25,
                )
            )

    return indicators
