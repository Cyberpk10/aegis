"""Fuses indicator findings into a single 0-100 risk score and verdict band."""

from __future__ import annotations

from app.models.schemas import Indicator, Verdict

SAFE_MAX = 24
SUSPICIOUS_MAX = 54

# M3: the optional ML classifier signal (app.ml.classifier) nudges the rule-based score by at
# most this many points, in either direction. Bounded deliberately so the guardrail "ML alone
# never turns a benign case malicious" is true by construction, not just empirically observed:
# a case the rule engine already scores near 0 can reach at most ML_MAX_CONTRIBUTION_POINTS even
# at ml_probability=1.0 — well under SAFE_MAX, let alone SUSPICIOUS_MAX. The ML signal nudges the
# score; it never redefines what these verdict bands mean.
ML_MAX_CONTRIBUTION_POINTS = 15


def compute_score(indicators: list[Indicator], ml_probability: float | None = None) -> int:
    total = sum(indicator.score for indicator in indicators)
    if ml_probability is not None:
        total += (ml_probability - 0.5) * 2 * ML_MAX_CONTRIBUTION_POINTS
    return max(0, min(100, round(total)))


def verdict_for_score(score: int) -> Verdict:
    if score <= SAFE_MAX:
        return Verdict.SAFE
    if score <= SUSPICIOUS_MAX:
        return Verdict.SUSPICIOUS
    return Verdict.MALICIOUS


def fuse(indicators: list[Indicator], ml_probability: float | None = None) -> tuple[int, Verdict]:
    score = compute_score(indicators, ml_probability)
    return score, verdict_for_score(score)
