from __future__ import annotations

from app.autonomy.actions import ACTIONS, DISABLE_SESSION, FINDING_ACTION_MAP, confidence_from_scores
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


def test_only_the_known_irreversible_action_lacks_a_reverse_path():
    # Every action except DISABLE_SESSION has a working reverse() — DISABLE_SESSION is the
    # one deliberate exception (M6 Stage 2: Microsoft Graph has no API to un-revoke a
    # session, so there's nothing to technically reverse). This is an explicit allowlist,
    # not a blanket "everything must be reversible" — the actual safety property is that
    # nothing in the catalog *deletes or destroys* anything (see the module docstring), and
    # that any irreversible action always requires human approval, never auto-executes (see
    # app.autonomy.policy.evaluate and tests/unit/test_autonomy_policy.py). Adding a second
    # irreversible action to the catalog should be a deliberate choice that updates this test,
    # not something that silently slips through.
    irreversible = {name for name, action in ACTIONS.items() if not action.reversible}
    assert irreversible == {DISABLE_SESSION}


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
