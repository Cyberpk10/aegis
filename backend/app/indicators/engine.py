"""Runs the full set of deterministic indicator rules over a parsed email."""

from __future__ import annotations

from app.indicators import (
    attachment_risk,
    auth_failures,
    credential_payment,
    link_analysis,
    lookalike_domain,
    sender_mismatch,
    urgency_language,
)
from app.indicators.base import IndicatorRule
from app.models.schemas import Indicator
from app.parsing.eml_parser import ParsedEmail

_RULES: list[IndicatorRule] = [
    sender_mismatch.evaluate,
    lookalike_domain.evaluate,
    urgency_language.evaluate,
    credential_payment.evaluate,
    link_analysis.evaluate,
    attachment_risk.evaluate,
    auth_failures.evaluate,
]


def run_indicators(email: ParsedEmail) -> list[Indicator]:
    indicators: list[Indicator] = []
    for rule in _RULES:
        indicators.extend(rule(email))
    return indicators
