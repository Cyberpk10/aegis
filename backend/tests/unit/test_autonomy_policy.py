from __future__ import annotations

from app.autonomy.actions import ACTIONS, ActionDefinition, DISABLE_SESSION, QUARANTINE_EMAIL
from app.autonomy.policy import Policy, PolicyDecision, PolicyRule, evaluate

_DISABLE_SESSION = ACTIONS[DISABLE_SESSION]  # containment=True, floor=0.6
_QUARANTINE_EMAIL = ACTIONS[QUARANTINE_EMAIL]  # containment=False, floor=0.5


def _policy(level: str, rules: list[PolicyRule] | None = None, exclusions: list[str] | None = None) -> Policy:
    return Policy(tenant_id="default", level=level, rules=rules or [], exclusions=exclusions or [])


def test_l0_always_requires_approval_even_with_a_matching_high_confidence_rule():
    policy = _policy("L0", [PolicyRule(action_type=DISABLE_SESSION, min_confidence=0.1)])
    assert (
        evaluate(policy, _DISABLE_SESSION, 0.99, "alice@corp.com", "activity")
        == PolicyDecision.REQUIRE_APPROVAL
    )


def test_no_matching_rule_skips():
    policy = _policy("L2", rules=[])
    assert (
        evaluate(policy, _DISABLE_SESSION, 0.99, "alice@corp.com", "activity") == PolicyDecision.SKIP
    )


def test_confidence_below_hard_floor_requires_approval_even_if_rule_threshold_is_lower():
    # Rule says 0.1 is enough, but the action's own floor (0.6) always wins.
    policy = _policy("L2", [PolicyRule(action_type=DISABLE_SESSION, min_confidence=0.1)])
    assert (
        evaluate(policy, _DISABLE_SESSION, 0.55, "alice@corp.com", "activity")
        == PolicyDecision.REQUIRE_APPROVAL
    )


def test_non_containment_action_eligible_at_l1():
    policy = _policy("L1", [PolicyRule(action_type=QUARANTINE_EMAIL, min_confidence=0.5)])
    assert (
        evaluate(policy, _QUARANTINE_EMAIL, 0.9, "phish@evil.com", "email")
        == PolicyDecision.AUTO_EXECUTE
    )


def test_containment_action_not_eligible_at_l1():
    policy = _policy("L1", [PolicyRule(action_type=DISABLE_SESSION, min_confidence=0.5)])
    assert (
        evaluate(policy, _DISABLE_SESSION, 0.9, "alice@corp.com", "activity")
        == PolicyDecision.REQUIRE_APPROVAL
    )


def test_containment_action_eligible_at_l2():
    policy = _policy("L2", [PolicyRule(action_type=DISABLE_SESSION, min_confidence=0.5)])
    assert (
        evaluate(policy, _DISABLE_SESSION, 0.9, "alice@corp.com", "activity")
        == PolicyDecision.AUTO_EXECUTE
    )


def test_confidence_below_rule_threshold_requires_approval():
    policy = _policy("L2", [PolicyRule(action_type=DISABLE_SESSION, min_confidence=0.8)])
    assert (
        evaluate(policy, _DISABLE_SESSION, 0.65, "alice@corp.com", "activity")
        == PolicyDecision.REQUIRE_APPROVAL
    )


def test_full_auto_bypasses_confidence_threshold_only_at_l3():
    rule = PolicyRule(action_type=DISABLE_SESSION, min_confidence=0.99, full_auto=True)
    l2_policy = _policy("L2", [rule])
    l3_policy = _policy("L3", [rule])

    # Confidence (0.61) clears the hard floor (0.6) but not the rule's 0.99 threshold.
    assert (
        evaluate(l2_policy, _DISABLE_SESSION, 0.61, "alice@corp.com", "activity")
        == PolicyDecision.REQUIRE_APPROVAL
    )
    assert (
        evaluate(l3_policy, _DISABLE_SESSION, 0.61, "alice@corp.com", "activity")
        == PolicyDecision.AUTO_EXECUTE
    )


def test_excluded_target_always_requires_approval_even_at_l3_full_auto_above_threshold():
    rule = PolicyRule(action_type=DISABLE_SESSION, min_confidence=0.1, full_auto=True)
    policy = _policy("L3", [rule], exclusions=["ceo@corp.com"])
    assert (
        evaluate(policy, _DISABLE_SESSION, 0.99, "ceo@corp.com", "activity")
        == PolicyDecision.REQUIRE_APPROVAL
    )
    # A non-excluded target under the identical policy auto-executes — proves the
    # exclusion, not something else, is what's gating the excluded one.
    assert (
        evaluate(policy, _DISABLE_SESSION, 0.99, "bob@corp.com", "activity")
        == PolicyDecision.AUTO_EXECUTE
    )


def test_irreversible_action_always_requires_approval():
    # No action in the Stage 1 catalog is irreversible — this constructs a synthetic one
    # to prove the invariant is enforced in code, not just true by the current catalog's
    # contents.
    irreversible = ActionDefinition(
        type="DELETE_ACCOUNT",
        title="Delete account",
        reversible=False,
        containment=True,
        min_confidence_floor=0.0,
    )
    policy = _policy(
        "L3", [PolicyRule(action_type="DELETE_ACCOUNT", min_confidence=0.0, full_auto=True)]
    )
    assert (
        evaluate(policy, irreversible, 1.0, "alice@corp.com", "activity")
        == PolicyDecision.REQUIRE_APPROVAL
    )


def test_scoped_rule_only_applies_within_its_scope():
    policy = _policy(
        "L1", [PolicyRule(action_type=QUARANTINE_EMAIL, min_confidence=0.5, scopes=["email"])]
    )
    assert (
        evaluate(policy, _QUARANTINE_EMAIL, 0.9, "phish@evil.com", "email")
        == PolicyDecision.AUTO_EXECUTE
    )
    assert (
        evaluate(policy, _QUARANTINE_EMAIL, 0.9, "phish@evil.com", "activity")
        == PolicyDecision.SKIP
    )
