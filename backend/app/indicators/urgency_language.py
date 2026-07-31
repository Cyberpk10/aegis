"""Deterministic urgency/pressure language detection via a fixed phrase bank."""

from __future__ import annotations

import re

from app.indicators.base import make_indicator
from app.models.schemas import Indicator, Severity
from app.parsing.eml_parser import ParsedEmail

_URGENCY_PHRASES = [
    r"act now",
    r"act immediately",
    r"urgent(?:ly)?",
    r"immediate action required",
    r"final notice",
    r"final warning",
    r"account (?:will be|has been) (?:suspended|locked|closed|disabled|deactivated)",
    r"verify your account (?:now|immediately|within)",
    r"within\s+(?:24|48|72)\s*hours",
    r"expires? (?:today|soon|shortly)",
    r"failure to (?:comply|respond|act)",
    r"time[- ]sensitive",
    r"last chance",
    r"as soon as possible",
    r"do not ignore this",
    r"immediate attention",
]

_PATTERN = re.compile("|".join(f"(?:{p})" for p in _URGENCY_PHRASES), re.IGNORECASE)

_SCORE_PER_MATCH = 4
_MAX_SCORE = 16


def evaluate(email: ParsedEmail) -> list[Indicator]:
    text = " ".join(filter(None, [email.subject, email.body_text]))
    matches = sorted({m.group(0).strip().lower() for m in _PATTERN.finditer(text)})

    if not matches:
        return []

    score = min(_MAX_SCORE, _SCORE_PER_MATCH * len(matches))
    severity = Severity.HIGH if len(matches) >= 3 else Severity.MEDIUM if len(matches) >= 2 else Severity.LOW

    return [
        make_indicator(
            id="URGENCY_LANGUAGE",
            category="content",
            title="Urgency / pressure language detected",
            description=(
                "The message uses language designed to pressure the recipient into acting "
                "quickly without careful review — a common social-engineering technique."
            ),
            evidence=[f"Matched phrase: {phrase!r}" for phrase in matches],
            severity=severity,
            score=score,
        )
    ]
