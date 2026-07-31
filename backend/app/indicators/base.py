"""Shared types for indicator rule modules."""

from __future__ import annotations

from typing import Callable

from app.models.schemas import Indicator, Severity
from app.parsing.eml_parser import ParsedEmail

# Each rule module exposes a top-level `evaluate(email) -> list[Indicator]` matching this shape.
IndicatorRule = Callable[[ParsedEmail], list[Indicator]]


def make_indicator(
    *,
    id: str,
    category: str,
    title: str,
    description: str,
    evidence: list[str],
    severity: Severity,
    score: float,
) -> Indicator:
    return Indicator(
        id=id,
        category=category,
        title=title,
        description=description,
        evidence=evidence,
        severity=severity,
        score=score,
    )
