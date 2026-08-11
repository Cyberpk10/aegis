from __future__ import annotations

import uuid
from datetime import datetime, timezone

import pytest

from app.autonomy.actions import ACTIONS, BLOCK_SENDER_DOMAIN, DISABLE_SESSION
from app.autonomy.executor import MockConnector, execute_if_authorized, reverse_action
from app.autonomy.policy import Policy, PolicyRule
from app.db.models import AutonomyAction

_NOW = datetime(2026, 1, 6, 12, 0, tzinfo=timezone.utc)
# BLOCK_SENDER_DOMAIN, not DISABLE_SESSION, is the generic "some containment action" test
# subject throughout this file — DISABLE_SESSION became reversible=False in M6 Stage 2
# (Microsoft Graph has no API to un-revoke a session), so it never reaches AUTO_EXECUTE/
# "executed" at all, which would break every test below that isn't specifically about that.
_ACTION = ACTIONS[BLOCK_SENDER_DOMAIN]
# These are unit-level executor tests, not tied to a real Incident row — the CHECK
# constraint on AutonomyAction requires exactly one of case_id/incident_id, so a fixed
# synthetic id stands in (SQLite FK enforcement isn't active in the test DB, same as
# elsewhere in this suite).
_INCIDENT_ID = uuid.uuid4()


_ACCOUNT_ID = uuid.uuid4()


def _policy(level="L2", min_confidence=0.5):
    return Policy(
        account_id=_ACCOUNT_ID,
        level=level,
        rules=[PolicyRule(action_type=BLOCK_SENDER_DOMAIN, min_confidence=min_confidence)],
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
        policy=Policy(account_id=_ACCOUNT_ID, level="L2", rules=[]),
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


def test_disable_session_never_reaches_executed_through_execute_if_authorized(db_session):
    # End-to-end confirmation (not just at the pure evaluate() layer) that DISABLE_SESSION's
    # reversible=False means it never auto-executes even under a policy that would auto
    # -execute any other containment action — this is the connector-facing guarantee that
    # actually matters: a real GraphConnector.execute() is never called for this action type
    # without a human approving first.
    policy = Policy(
        account_id=_ACCOUNT_ID,
        level="L3",
        rules=[PolicyRule(action_type=DISABLE_SESSION, min_confidence=0.1, full_auto=True)],
    )
    row = execute_if_authorized(
        db_session,
        policy=policy,
        blast_radius_limit=10,
        blast_radius_window_minutes=60,
        connector=MockConnector(),
        action=ACTIONS[DISABLE_SESSION],
        confidence=1.0,
        target="alice@corp.com",
        scope="activity",
        trigger_finding_id="BRUTE_FORCE_PASSWORD_SPRAY",
        case_id=None,
        incident_id=_INCIDENT_ID,
        now=_NOW,
    )
    assert row.status == "pending_approval"
    assert row.result is None


class _SpyConnector(MockConnector):
    """Records exactly what execute_if_authorized/reverse_action pass through, so tests can
    assert on the params-threading behavior without needing a real GraphConnector."""

    def __init__(self):
        self.execute_calls: list[tuple[str, str, dict]] = []
        self.reverse_calls: list[tuple[str, str, dict]] = []

    def execute(self, action_type, target, params):
        self.execute_calls.append((action_type, target, params))
        return super().execute(action_type, target, params)

    def reverse(self, action_type, target, params):
        self.reverse_calls.append((action_type, target, params))
        return super().reverse(action_type, target, params)


class _RaisingConnector(MockConnector):
    def execute(self, action_type, target, params):
        raise ConnectionError("simulated Graph outage")


def test_params_are_threaded_through_to_connector_execute(db_session):
    spy = _SpyConnector()
    execute_if_authorized(
        db_session,
        policy=_policy(),
        blast_radius_limit=10,
        blast_radius_window_minutes=60,
        connector=spy,
        action=_ACTION,
        confidence=0.9,
        target="evil.com",
        scope="activity",
        trigger_finding_id="BRUTE_FORCE_PASSWORD_SPRAY",
        case_id=None,
        incident_id=_INCIDENT_ID,
        now=_NOW,
        params={"recipient_mailboxes": ["alice@corp.com"]},
    )
    assert spy.execute_calls == [
        (BLOCK_SENDER_DOMAIN, "evil.com", {"recipient_mailboxes": ["alice@corp.com"]})
    ]


def test_omitting_params_defaults_to_empty_dict_backward_compatibly(db_session):
    spy = _SpyConnector()
    execute_if_authorized(
        db_session,
        policy=_policy(),
        blast_radius_limit=10,
        blast_radius_window_minutes=60,
        connector=spy,
        action=_ACTION,
        confidence=0.9,
        target="evil.com",
        scope="activity",
        trigger_finding_id="BRUTE_FORCE_PASSWORD_SPRAY",
        case_id=None,
        incident_id=_INCIDENT_ID,
        now=_NOW,
    )
    assert spy.execute_calls == [(BLOCK_SENDER_DOMAIN, "evil.com", {})]


def test_connector_execute_failure_is_recorded_not_raised(db_session):
    row = execute_if_authorized(
        db_session,
        policy=_policy(),
        blast_radius_limit=10,
        blast_radius_window_minutes=60,
        connector=_RaisingConnector(),
        action=_ACTION,
        confidence=0.9,
        target="evil.com",
        scope="activity",
        trigger_finding_id="BRUTE_FORCE_PASSWORD_SPRAY",
        case_id=None,
        incident_id=_INCIDENT_ID,
        now=_NOW,
    )
    assert row.status == "execution_failed"
    assert row.decision == "auto_execute"  # the decision itself was correct; execution failed
    assert row.result["outcome"] == "failed"
    assert "simulated Graph outage" in row.result["error"]


def test_reverse_action_passes_the_original_result_as_params(db_session):
    spy = _SpyConnector()
    row = execute_if_authorized(
        db_session,
        policy=_policy(),
        blast_radius_limit=10,
        blast_radius_window_minutes=60,
        connector=spy,
        action=_ACTION,
        confidence=0.9,
        target="evil.com",
        scope="activity",
        trigger_finding_id="BRUTE_FORCE_PASSWORD_SPRAY",
        case_id=None,
        incident_id=_INCIDENT_ID,
        now=_NOW,
    )
    db_session.commit()
    original_result = dict(row.result)

    reverse_action(db_session, spy, row)

    assert spy.reverse_calls == [(BLOCK_SENDER_DOMAIN, "evil.com", original_result)]


def test_reverse_action_connector_failure_raises_value_error(db_session):
    class _RaisingReverseConnector(MockConnector):
        def reverse(self, action_type, target, params):
            raise ConnectionError("simulated Graph outage")

    row = execute_if_authorized(
        db_session,
        policy=_policy(),
        blast_radius_limit=10,
        blast_radius_window_minutes=60,
        connector=MockConnector(),
        action=_ACTION,
        confidence=0.9,
        target="evil.com",
        scope="activity",
        trigger_finding_id="BRUTE_FORCE_PASSWORD_SPRAY",
        case_id=None,
        incident_id=_INCIDENT_ID,
        now=_NOW,
    )
    db_session.commit()

    with pytest.raises(ValueError, match="simulated Graph outage"):
        reverse_action(db_session, _RaisingReverseConnector(), row)
