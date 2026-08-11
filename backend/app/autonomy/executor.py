"""Enforces the policy decision, the blast-radius rate limit, and records everything
(M6 Stage 1). This is the only place that actually calls a connector — nowhere else in the
autonomy package performs I/O. Stage 1 shipped only MockConnector, fully offline/deterministic;
M6 Stage 2 adds a real one (app.autonomy.graph_connector.GraphConnector) implementing this same
ActionConnector interface — MockConnector remains the default everywhere it isn't explicitly
swapped out (see app.autonomy.connector_factory), so every existing offline test is unaffected.
"""

from __future__ import annotations

import uuid
from abc import ABC, abstractmethod
from datetime import datetime, timedelta, timezone

from sqlalchemy.orm import Session

from app.autonomy.actions import ActionDefinition
from app.autonomy.policy import Policy, PolicyDecision, evaluate, matching_rule
from app.db.models import AutonomyAction
from app.mapping.framework_mapper import map_indicators


class ActionConnector(ABC):
    """What a real integration (mailbox API, IdP session API, firewall/secure-web-gateway
    API, ...) would implement. Stage 1 ships only MockConnector."""

    @abstractmethod
    def execute(self, action_type: str, target: str, params: dict) -> dict: ...

    @abstractmethod
    def reverse(self, action_type: str, target: str, params: dict) -> dict: ...


class MockConnector(ActionConnector):
    """Deterministic, fully offline — simulates a result, performs no real I/O against any
    external system. The only connector wired in Stage 1."""

    def execute(self, action_type: str, target: str, params: dict) -> dict:
        return {
            "connector": "mock",
            "action_type": action_type,
            "target": target,
            "simulated": True,
            "outcome": "success",
        }

    def reverse(self, action_type: str, target: str, params: dict) -> dict:
        return {
            "connector": "mock",
            "action_type": action_type,
            "target": target,
            "simulated": True,
            "outcome": "reversed",
        }


def _mapped_controls_json(action_type: str) -> dict:
    return {
        key: [ref.model_dump(mode="json") for ref in refs]
        for key, refs in map_indicators([action_type]).items()
    }


def execute_if_authorized(
    db: Session,
    *,
    policy: Policy,
    blast_radius_limit: int,
    blast_radius_window_minutes: int,
    connector: ActionConnector,
    action: ActionDefinition,
    confidence: float,
    target: str,
    scope: str,
    trigger_finding_id: str,
    case_id: uuid.UUID | None,
    incident_id: uuid.UUID | None,
    now: datetime | None = None,
    params: dict | None = None,
) -> AutonomyAction:
    """Evaluates policy, applies the blast-radius override, executes via `connector` if
    authorized, and always writes exactly one AutonomyAction audit row — for every decision
    branch, not just auto-executed ones. Does not commit; the caller controls the
    transaction boundary (same pattern as app.baselines' _persist_baseline).

    `params` is extra context a real connector needs beyond the bare `target` string (e.g.
    GraphConnector needs the recipient mailbox + Message-ID to locate an email) — MockConnector
    ignores it entirely, so every existing caller that omits it is unaffected."""
    now = now or datetime.now(timezone.utc)
    params = params or {}

    decision = evaluate(policy, action, confidence, target, scope)

    if decision == PolicyDecision.AUTO_EXECUTE:
        window_start = now - timedelta(minutes=blast_radius_window_minutes)
        auto_count = (
            db.query(AutonomyAction)
            .filter(
                AutonomyAction.account_id == policy.account_id,
                AutonomyAction.decision == PolicyDecision.AUTO_EXECUTE.value,
                AutonomyAction.created_at >= window_start,
            )
            .count()
        )
        if auto_count >= blast_radius_limit:
            decision = PolicyDecision.REQUIRE_APPROVAL

    rule = matching_rule(policy, action.type, scope)
    policy_rule_snapshot = (
        {
            "action_type": rule.action_type,
            "min_confidence": rule.min_confidence,
            "scopes": rule.scopes,
            "full_auto": rule.full_auto,
        }
        if rule
        else None
    )

    result = None
    if decision == PolicyDecision.AUTO_EXECUTE:
        try:
            result = connector.execute(action.type, target, params)
            status = "executed"
        except Exception as exc:  # noqa: BLE001 - a real connector's network/API failure must
            # never crash the caller (this runs during a page-load, not a user-initiated
            # action) — record it as a failed action instead, same audit-trail guarantee as
            # every other branch.
            result = {"outcome": "failed", "error": str(exc)}
            status = "execution_failed"
    elif decision == PolicyDecision.REQUIRE_APPROVAL:
        status = "pending_approval"
    else:
        status = "skipped"

    row = AutonomyAction(
        id=uuid.uuid4(),
        account_id=policy.account_id,
        created_at=now,
        case_id=case_id,
        incident_id=incident_id,
        trigger_finding_id=trigger_finding_id,
        action_type=action.type,
        target=target,
        confidence=confidence,
        policy_rule=policy_rule_snapshot,
        decision=decision.value,
        status=status,
        result=result,
        reversible=action.reversible,
        mapped_controls=_mapped_controls_json(action.type),
    )
    db.add(row)
    db.flush()
    db.refresh(row)
    return row


def reverse_action(db: Session, connector: ActionConnector, row: AutonomyAction) -> AutonomyAction:
    """Undoes an executed, reversible action. Raises ValueError for anything else — the
    route layer translates that into a 400."""
    if row.status != "executed":
        raise ValueError(f"Action {row.id} is not in an executed state (status={row.status!r}).")
    if not row.reversible:
        raise ValueError(f"Action {row.id} ({row.action_type}) is not reversible.")

    # The original execute() result (e.g. GraphConnector's captured original_folder_id / rule
    # ids) is exactly what a real reverse needs to know what to undo — MockConnector.reverse()
    # ignores params entirely, so this is a no-op change for every existing test.
    try:
        result = connector.reverse(row.action_type, row.target, row.result or {})
    except Exception as exc:  # noqa: BLE001 - a user-initiated action; fail loudly, not silently
        raise ValueError(f"Failed to reverse action {row.id}: {exc}") from exc

    row.status = "reversed"
    row.result = {**(row.result or {}), "reverse_result": result}
    db.flush()
    db.refresh(row)
    return row
