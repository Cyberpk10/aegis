from __future__ import annotations

import pytest

from app.models.schemas import Indicator, Severity, Verdict
from app.scoring.risk_engine import compute_score, fuse, verdict_for_score


def _indicator(score: float) -> Indicator:
    return Indicator(
        id="TEST",
        category="test",
        title="test",
        description="test",
        evidence=[],
        severity=Severity.LOW,
        score=score,
    )


def test_no_indicators_scores_zero():
    assert compute_score([]) == 0


def test_score_sums_indicator_scores():
    assert compute_score([_indicator(10), _indicator(20)]) == 30


def test_score_caps_at_100():
    assert compute_score([_indicator(80), _indicator(80)]) == 100


@pytest.mark.parametrize(
    "score,expected",
    [
        (0, Verdict.SAFE),
        (24, Verdict.SAFE),
        (25, Verdict.SUSPICIOUS),
        (54, Verdict.SUSPICIOUS),
        (55, Verdict.MALICIOUS),
        (100, Verdict.MALICIOUS),
    ],
)
def test_verdict_bands(score, expected):
    assert verdict_for_score(score) == expected


def test_fuse_returns_score_and_verdict():
    score, verdict = fuse([_indicator(60)])
    assert score == 60
    assert verdict == Verdict.MALICIOUS
