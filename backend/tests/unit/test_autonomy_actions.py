from __future__ import annotations

from app.autonomy.actions import ACTIONS, FINDING_ACTION_MAP, confidence_from_scores
from app.models.schemas import Finding, Severity


def _finding(points: float) -> Finding:
    return Finding(
        id="TEST", category="test", title="t", description="d", severity=Severity.LOW,
        points=points, evidence_event_ids=[],
    )


def test_every_mapped_finding_id_points_to_a_valid_action_type():
    assert FINDING_ACTION_MAP  # sanity: not empty
    for finding_id, action_type in FINDING_ACTION_MAP.items():
        assert action_type in ACTIONS, f"{finding_id} maps to unknown action {action_type!r}"


def test_no_destructive_action_exists_in_the_catalog():
    assert all(action.reversible for action in ACTIONS.values())


def test_confidence_from_scores_derives_points_over_100_clamped():
    assert confidence_from_scores([50]) == 0.5
    assert confidence_from_scores([150]) == 1.0  # clamped
    assert confidence_from_scores([-10]) == 0.0  # clamped


def test_confidence_from_scores_empty_is_zero():
    assert confidence_from_scores([]) == 0.0


def test_confidence_from_scores_uses_minimum_across_contributors():
    # The weakest contributing signal governs — this is a safety gate.
    assert confidence_from_scores([90, 20, 70]) == 0.2


def test_confidence_for_findings_matches_confidence_from_scores():
    from app.autonomy.actions import confidence_for_findings

    findings = [_finding(80), _finding(30)]
    assert confidence_for_findings(findings) == confidence_from_scores([80, 30])
