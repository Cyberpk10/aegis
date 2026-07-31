"""Fuses indicator findings into a single 0-100 risk score and verdict band."""

from __future__ import annotations

from app.models.schemas import Indicator, Verdict

SAFE_MAX = 24
SUSPICIOUS_MAX = 54


def compute_score(indicators: list[Indicator]) -> int:
    total = sum(indicator.score for indicator in indicators)
    return max(0, min(100, round(total)))


def verdict_for_score(score: int) -> Verdict:
    if score <= SAFE_MAX:
        return Verdict.SAFE
    if score <= SUSPICIOUS_MAX:
        return Verdict.SUSPICIOUS
    return Verdict.MALICIOUS


def fuse(indicators: list[Indicator]) -> tuple[int, Verdict]:
    score = compute_score(indicators)
    return score, verdict_for_score(score)
