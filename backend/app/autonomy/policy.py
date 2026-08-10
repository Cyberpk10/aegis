"""Pure autonomy policy decision engine (M6 Stage 1) — no DB/I/O here, mirrors every other
pure aggregation module in this codebase (app.dashboard.aggregation, app.baselines.aggregation,
...). The blast-radius rate limit is deliberately NOT here — it needs to read the audit log,
so it lives in app.autonomy.executor, which wraps this pure evaluate() with that one
DB-aware check.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from enum import Enum

from app.autonomy.actions import ActionDefinition

_LEVELS = ("L0", "L1", "L2", "L3")


class PolicyDecision(str, Enum):
    AUTO_EXECUTE = "auto_execute"
    REQUIRE_APPROVAL = "require_approval"
    SKIP = "skip"


@dataclass(frozen=True)
class PolicyRule:
    action_type: str
    min_confidence: float
    scopes: list[str] | None = None  # "email" | "activity"; None = applies to both
    full_auto: bool = False  # only honored at policy.level == "L3"


@dataclass(frozen=True)
class Policy:
    account_id: uuid.UUID
    level: str = "L0"
    rules: list[PolicyRule] = field(default_factory=list)
    exclusions: list[str] = field(default_factory=list)  # exact-match protected identities/assets


def matching_rule(policy: Policy, action_type: str, scope: str) -> PolicyRule | None:
    for rule in policy.rules:
        if rule.action_type != action_type:
            continue
        if rule.scopes is not None and scope not in rule.scopes:
            continue
        return rule
    return None


def evaluate(
    policy: Policy, action: ActionDefinition, confidence: float, target: str, scope: str
) -> PolicyDecision:
    """Evaluation order — each step is a hard gate, first failure wins. Pure function: same
    inputs always produce the same decision, no hidden state, fully unit-testable."""
    # 1. Exclusions always win — a protected identity/asset is never auto-actioned, at any
    # level, above any confidence. REQUIRE_APPROVAL (never SKIP): a protected identity's
    # detection still needs a human's eyes, just never Aegis's hands.
    if target in policy.exclusions:
        return PolicyDecision.REQUIRE_APPROVAL

    # 2. Irreversible actions are never auto-eligible. Dead code path today (the Stage 1
    # catalog has no irreversible action), but kept explicit and tested as a hard invariant.
    if not action.reversible:
        return PolicyDecision.REQUIRE_APPROVAL

    # 3. L0 is recommend-only, unconditionally.
    if policy.level == "L0":
        return PolicyDecision.REQUIRE_APPROVAL

    rule = matching_rule(policy, action.type, scope)
    # 4. No customer rule opts this action type in at all -> nothing to auto-run.
    if rule is None:
        return PolicyDecision.SKIP

    # 5. The action's own hard confidence floor — a rule can raise this bar, never lower it.
    if confidence < action.min_confidence_floor:
        return PolicyDecision.REQUIRE_APPROVAL

    # 6. L3 full-auto opt-in for this specific rule bypasses the confidence-threshold check
    # (the hard floor in step 5 still applied above).
    if rule.full_auto and policy.level == "L3":
        return PolicyDecision.AUTO_EXECUTE

    # 7. Containment actions need L2+; non-containment actions need L1+.
    required_level = "L2" if action.containment else "L1"
    if _LEVELS.index(policy.level) < _LEVELS.index(required_level):
        return PolicyDecision.REQUIRE_APPROVAL

    # 8. The customer-configured confidence threshold for this rule.
    if confidence >= rule.min_confidence:
        return PolicyDecision.AUTO_EXECUTE
    return PolicyDecision.REQUIRE_APPROVAL
