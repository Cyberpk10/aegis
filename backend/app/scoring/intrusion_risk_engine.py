"""Fuses detection findings into a single 0-100 risk score and verdict band — mirrors
app.scoring.risk_engine exactly, reusing the same bands so "suspicious"/"malicious" mean
the same thing platform-wide regardless of detection domain."""

from __future__ import annotations

from app.models.schemas import Finding, Verdict
from app.scoring.risk_engine import SAFE_MAX, SUSPICIOUS_MAX

__all__ = ["SAFE_MAX", "SUSPICIOUS_MAX", "compute_score", "verdict_for_score", "fuse"]


def compute_score(findings: list[Finding]) -> int:
    total = sum(finding.points for finding in findings)
    return max(0, min(100, round(total)))


def verdict_for_score(score: int) -> Verdict:
    if score <= SAFE_MAX:
        return Verdict.SAFE
    if score <= SUSPICIOUS_MAX:
        return Verdict.SUSPICIOUS
    return Verdict.MALICIOUS


def fuse(findings: list[Finding]) -> tuple[int, Verdict]:
    score = compute_score(findings)
    return score, verdict_for_score(score)
