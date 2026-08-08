"""Enforces the policy decision, the blast-radius rate limit, and records everything
(M6 Stage 1). This is the only place that actually calls a connector — nowhere else in the
autonomy package performs I/O. Stage 1 wires only MockConnector, per the explicit ask to
keep everything offline/deterministic; a real connector is a future stage's concern and
only needs to implement this same ActionConnector interface.
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
) -> AutonomyAction:
    """Evaluates policy, applies the blast-radius override, executes via `connector` if
    authorized, and always writes exactly one AutonomyAction audit row — for every decision
    branch, not just auto-executed ones. Does not commit; the caller controls the
    transaction boundary (same pattern as app.baselines' _persist_baseline)."""
    now = now or datetime.now(timezone.utc)

    decision = evaluate(policy, action, confidence, target, scope)

    if decision == PolicyDecision.AUTO_EXECUTE:
        window_start = now - timedelta(minutes=blast_radius_window_minutes)
        auto_count = (
            db.query(AutonomyAction)
            .filter(
                AutonomyAction.tenant_id == policy.tenant_id,
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
        result = connector.execute(action.type, target, {})
        status = "executed"
    elif decision == PolicyDecision.REQUIRE_APPROVAL:
        status = "pending_approval"
    else:
        status = "skipped"

    row = AutonomyAction(
        id=uuid.uuid4(),
        tenant_id=policy.tenant_id,
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

    result = connector.reverse(row.action_type, row.target, {})
    row.status = "reversed"
    row.result = {**(row.result or {}), "reverse_result": result}
    db.flush()
    db.refresh(row)
    return row
