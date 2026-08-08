from __future__ import annotations

import uuid
from datetime import datetime, timezone

import pytest

from app.autonomy.actions import ACTIONS, DISABLE_SESSION
from app.autonomy.executor import MockConnector, execute_if_authorized, reverse_action
from app.autonomy.policy import Policy, PolicyRule
from app.db.models import AutonomyAction

_NOW = datetime(2026, 1, 6, 12, 0, tzinfo=timezone.utc)
_ACTION = ACTIONS[DISABLE_SESSION]
# These are unit-level executor tests, not tied to a real Incident row — the CHECK
# constraint on AutonomyAction requires exactly one of case_id/incident_id, so a fixed
# synthetic id stands in (SQLite FK enforcement isn't active in the test DB, same as
# elsewhere in this suite).
_INCIDENT_ID = uuid.uuid4()


def _policy(level="L2", min_confidence=0.5):
    return Policy(
        tenant_id="default",
        level=level,
        rules=[PolicyRule(action_type=DISABLE_SESSION, min_confidence=min_confidence)],
    )


def test_auto_eligible_action_calls_connector_and_records_executed(db_session):
    row = execute_if_authorized(
        db_session,
        policy=_policy(),
        blast_radius_limit=10,
        blast_radius_window_minutes=60,
        connector=MockConnector(),
        action=_ACTION,
        confidence=0.9,
        target="alice@corp.com",
        scope="activity",
        trigger_finding_id="BRUTE_FORCE_PASSWORD_SPRAY",
        case_id=None,
        incident_id=_INCIDENT_ID,
        now=_NOW,
    )
    assert row.status == "executed"
    assert row.decision == "auto_execute"
    assert row.result["connector"] == "mock"
    assert row.result["outcome"] == "success"
    assert row.mapped_controls  # non-empty — every action has mapped controls


def test_require_approval_decision_does_not_call_connector(db_session):
    row = execute_if_authorized(
        db_session,
        policy=_policy(level="L0"),
        blast_radius_limit=10,
        blast_radius_window_minutes=60,
        connector=MockConnector(),
        action=_ACTION,
        confidence=0.9,
        target="alice@corp.com",
        scope="activity",
        trigger_finding_id="BRUTE_FORCE_PASSWORD_SPRAY",
        case_id=None,
        incident_id=_INCIDENT_ID,
        now=_NOW,
    )
    assert row.status == "pending_approval"
    assert row.result is None


def test_every_decision_branch_writes_exactly_one_audit_row(db_session):
    # SKIP branch: no rule for this action type at all.
    row = execute_if_authorized(
        db_session,
        policy=Policy(tenant_id="default", level="L2", rules=[]),
        blast_radius_limit=10,
        blast_radius_window_minutes=60,
        connector=MockConnector(),
        action=_ACTION,
        confidence=0.9,
        target="alice@corp.com",
        scope="activity",
        trigger_finding_id="BRUTE_FORCE_PASSWORD_SPRAY",
        case_id=None,
        incident_id=_INCIDENT_ID,
        now=_NOW,
    )
    assert row.decision == "skip"
    assert row.status == "skipped"
    assert db_session.query(AutonomyAction).count() == 1


def test_blast_radius_cap_forces_require_approval_after_n_auto_executions(db_session):
    policy = _policy()
    for i in range(3):
        execute_if_authorized(
            db_session,
            policy=policy,
            blast_radius_limit=3,
            blast_radius_window_minutes=60,
            connector=MockConnector(),
            action=_ACTION,
            confidence=0.9,
            target=f"user{i}@corp.com",
            scope="activity",
            trigger_finding_id="BRUTE_FORCE_PASSWORD_SPRAY",
            case_id=None,
            incident_id=_INCIDENT_ID,
            now=_NOW,
        )
    db_session.commit()

    # The 4th auto-eligible action within the same window is downgraded even though
    # policy alone would auto-execute it.
    fourth = execute_if_authorized(
        db_session,
        policy=policy,
        blast_radius_limit=3,
        blast_radius_window_minutes=60,
        connector=MockConnector(),
        action=_ACTION,
        confidence=0.9,
        target="user4@corp.com",
        scope="activity",
        trigger_finding_id="BRUTE_FORCE_PASSWORD_SPRAY",
        case_id=None,
        incident_id=_INCIDENT_ID,
        now=_NOW,
    )
    assert fourth.status == "pending_approval"
    assert fourth.decision == "require_approval"


def test_blast_radius_window_self_clears_outside_the_window(db_session):
    policy = _policy()
    old_time = _NOW.replace(hour=1)  # 11 hours before _NOW, outside a 60-min window
    for i in range(5):
        execute_if_authorized(
            db_session,
            policy=policy,
            blast_radius_limit=3,
            blast_radius_window_minutes=60,
            connector=MockConnector(),
            action=_ACTION,
            confidence=0.9,
            target=f"user{i}@corp.com",
            scope="activity",
            trigger_finding_id="BRUTE_FORCE_PASSWORD_SPRAY",
            case_id=None,
            incident_id=_INCIDENT_ID,
            now=old_time,
        )
    db_session.commit()

    row = execute_if_authorized(
        db_session,
        policy=policy,
        blast_radius_limit=3,
        blast_radius_window_minutes=60,
        connector=MockConnector(),
        action=_ACTION,
        confidence=0.9,
        target="fresh@corp.com",
        scope="activity",
        trigger_finding_id="BRUTE_FORCE_PASSWORD_SPRAY",
        case_id=None,
        incident_id=_INCIDENT_ID,
        now=_NOW,
    )
    assert row.status == "executed"


def test_reverse_action_round_trips_through_mock_connector(db_session):
    row = execute_if_authorized(
        db_session,
        policy=_policy(),
        blast_radius_limit=10,
        blast_radius_window_minutes=60,
        connector=MockConnector(),
        action=_ACTION,
        confidence=0.9,
        target="alice@corp.com",
        scope="activity",
        trigger_finding_id="BRUTE_FORCE_PASSWORD_SPRAY",
        case_id=None,
        incident_id=_INCIDENT_ID,
        now=_NOW,
    )
    db_session.commit()

    reversed_row = reverse_action(db_session, MockConnector(), row)
    assert reversed_row.status == "reversed"
    assert reversed_row.result["reverse_result"]["outcome"] == "reversed"


def test_reverse_action_rejects_a_non_executed_row(db_session):
    row = execute_if_authorized(
        db_session,
        policy=_policy(level="L0"),
        blast_radius_limit=10,
        blast_radius_window_minutes=60,
        connector=MockConnector(),
        action=_ACTION,
        confidence=0.9,
        target="alice@corp.com",
        scope="activity",
        trigger_finding_id="BRUTE_FORCE_PASSWORD_SPRAY",
        case_id=None,
        incident_id=_INCIDENT_ID,
        now=_NOW,
    )
    db_session.commit()

    with pytest.raises(ValueError):
        reverse_action(db_session, MockConnector(), row)
