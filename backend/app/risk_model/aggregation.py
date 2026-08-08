"""Pure aggregation math for the financial risk model — no DB/SQLAlchemy here, same
separation as app.dashboard.aggregation (which this module reuses CaseRow/LabelRow from
directly rather than redefining them).
"""

from __future__ import annotations

from app.dashboard.aggregation import CaseRow, LabelRow
from app.risk_model.assumptions import RiskModelAssumptions

ATTACK_TYPE_BEC = "bec"
ATTACK_TYPE_CREDENTIAL_PHISHING = "credential_phishing"
ATTACK_TYPE_GENERIC_PHISHING = "generic_phishing"

ATTACK_TYPES = (ATTACK_TYPE_BEC, ATTACK_TYPE_CREDENTIAL_PHISHING, ATTACK_TYPE_GENERIC_PHISHING)


def classify_attack_type(indicator_ids: frozenset[str]) -> str:
    """Classifies a case's attack type from the indicators it fired. PAYMENT_REQUEST
    takes priority over CREDENTIAL_REQUEST since a payment/wire-transfer ask is the
    hallmark of BEC even when credential-harvesting language also appears in the same
    message."""
    if "PAYMENT_REQUEST" in indicator_ids:
        return ATTACK_TYPE_BEC
    if "CREDENTIAL_REQUEST" in indicator_ids:
        return ATTACK_TYPE_CREDENTIAL_PHISHING
    return ATTACK_TYPE_GENERIC_PHISHING


def _breakdown(
    cases: list[CaseRow], assumptions: RiskModelAssumptions, weight_for: callable
) -> dict:
    """Groups cases by attack type and sums `avg_loss * weight_for(case)` per bucket.
    Reports `prevention_weight` per bucket as the weighted-average weight actually
    applied (cases within a bucket can carry different weights, e.g. a mix of
    "malicious" and, if the operator opts in, "suspicious" verdicts) — the exact
    per-verdict weight values are always available in the response's `assumptions`
    block for full traceability."""
    subtotals = {
        attack_type: {"count": 0, "subtotal_usd": 0.0, "weight_sum": 0.0}
        for attack_type in ATTACK_TYPES
    }

    for case in cases:
        weight = weight_for(case)
        if weight == 0.0:
            continue
        indicator_ids = frozenset(indicator["id"] for indicator in case.indicators)
        attack_type = classify_attack_type(indicator_ids)
        avg_loss = assumptions.avg_loss_for_attack_type(attack_type)
        subtotals[attack_type]["count"] += 1
        subtotals[attack_type]["subtotal_usd"] += avg_loss * weight
        subtotals[attack_type]["weight_sum"] += weight

    by_attack_type = []
    for attack_type in ATTACK_TYPES:
        bucket = subtotals[attack_type]
        avg_weight = round(bucket["weight_sum"] / bucket["count"], 4) if bucket["count"] else 0.0
        by_attack_type.append(
            {
                "attack_type": attack_type,
                "count": bucket["count"],
                "avg_loss_usd": assumptions.avg_loss_for_attack_type(attack_type),
                "prevention_weight": avg_weight,
                "subtotal_usd": round(bucket["subtotal_usd"], 2),
            }
        )
    total_usd = round(sum(b["subtotal_usd"] for b in by_attack_type), 2)
    return {"total_usd": total_usd, "by_attack_type": by_attack_type}


def exposure_avoided(cases: list[CaseRow], assumptions: RiskModelAssumptions) -> dict:
    """Estimated loss avoided by Aegis's own detections in the period: non-safe cases,
    weighted by how much confidence the operator places in each verdict
    (verdict_prevention_weight), multiplied by the avg loss for the case's attack type."""

    def weight_for(case: CaseRow) -> float:
        return assumptions.prevention_weight(case.verdict)

    return _breakdown(cases, assumptions, weight_for)


def residual_risk(
    cases: list[CaseRow], latest_label_by_case: dict[str, LabelRow], assumptions: RiskModelAssumptions
) -> dict:
    """Estimated exposure Aegis's own labeled data shows was NOT caught: cases whose
    machine verdict was not "malicious" but whose latest analyst label says it actually
    was — i.e. analyst-confirmed false negatives within the period. Deliberately scoped
    only to Aegis's own labeled data, not an estimate of a wider unknown threat
    population (see the `note` field)."""
    false_negatives = [
        case
        for case in cases
        if case.verdict != "malicious"
        and case.id in latest_label_by_case
        and latest_label_by_case[case.id].analyst_verdict == "malicious"
    ]

    def weight_for(case: CaseRow) -> float:
        return 1.0

    result = _breakdown(false_negatives, assumptions, weight_for)
    result["false_negative_count"] = len(false_negatives)
    result["note"] = (
        "Scoped only to cases with an analyst label confirming a missed malicious "
        "verdict within this period — not an estimate of threats outside Aegis's own "
        "labeled data."
    )
    return result
