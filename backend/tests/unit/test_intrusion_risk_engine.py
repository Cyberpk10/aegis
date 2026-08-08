from __future__ import annotations

import pytest

from app.models.schemas import Finding, Severity, Verdict
from app.scoring.intrusion_risk_engine import compute_score, fuse, verdict_for_score


def _finding(points: float) -> Finding:
    return Finding(
        id="TEST",
        category="test",
        title="test",
        description="test",
        severity=Severity.LOW,
        points=points,
        evidence_event_ids=[],
    )


def test_no_findings_scores_zero():
    assert compute_score([]) == 0


def test_score_sums_finding_points():
    assert compute_score([_finding(10), _finding(20)]) == 30


def test_score_caps_at_100():
    assert compute_score([_finding(80), _finding(80)]) == 100


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
def test_verdict_bands_match_email_risk_engine(score, expected):
    # Same bands as app.scoring.risk_engine — deliberately reused so "suspicious" and
    # "malicious" mean the same thing platform-wide, regardless of detection domain.
    assert verdict_for_score(score) == expected


def test_fuse_returns_score_and_verdict():
    score, verdict = fuse([_finding(60)])
    assert score == 60
    assert verdict == Verdict.MALICIOUS
