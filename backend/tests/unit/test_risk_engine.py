from __future__ import annotations

import pytest

from app.models.schemas import Indicator, Severity, Verdict
from app.scoring.risk_engine import (
    ML_MAX_CONTRIBUTION_POINTS,
    SAFE_MAX,
    compute_score,
    fuse,
    verdict_for_score,
)


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


def test_ml_probability_none_is_a_no_op():
    """The default (no ML signal) path must be byte-identical to the pre-M3 behavior."""
    assert compute_score([_indicator(10)], ml_probability=None) == compute_score([_indicator(10)])


def test_ml_probability_at_one_adds_max_contribution():
    score = compute_score([_indicator(10)], ml_probability=1.0)
    assert score == 10 + ML_MAX_CONTRIBUTION_POINTS


def test_ml_probability_at_zero_subtracts_max_contribution():
    score = compute_score([_indicator(10)], ml_probability=0.0)
    assert score == max(0, 10 - ML_MAX_CONTRIBUTION_POINTS)


def test_ml_probability_at_half_is_a_no_op():
    """0.5 (maximally uncertain) contributes nothing — the blend is centered, not biased."""
    assert compute_score([_indicator(10)], ml_probability=0.5) == 10


@pytest.mark.parametrize("ml_probability", [0.0, 0.25, 0.5, 0.75, 1.0])
def test_ml_signal_alone_can_never_reach_malicious_from_a_clean_rule_score(ml_probability):
    """The guardrail, expressed structurally: with zero rule-based indicators, no ML
    probability (however confident) can push the score past SAFE_MAX, let alone into
    MALICIOUS — because ML_MAX_CONTRIBUTION_POINTS < SAFE_MAX by construction."""
    score, verdict = fuse([], ml_probability=ml_probability)
    assert score <= SAFE_MAX
    assert verdict == Verdict.SAFE
