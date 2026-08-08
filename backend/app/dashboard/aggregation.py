"""Pure aggregation math for the Threat & Compliance Dashboard — no DB/SQLAlchemy here,
just plain dataclasses in, plain dicts out. Keeps the math testable in isolation from the
route/DB wiring (app/api/routes/dashboard.py), mirroring how app/scoring/risk_engine.py is
kept separate from app/api/routes/analyze.py.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime

VERDICTS = ("malicious", "suspicious", "safe")


@dataclass(frozen=True)
class CaseRow:
    id: str
    created_at: datetime
    verdict: str
    indicators: list[dict]
    framework_mappings: dict[str, list[dict]]


@dataclass(frozen=True)
class LabelRow:
    case_id: str
    analyst_verdict: str
    created_at: datetime


def verdict_counts(cases: list[CaseRow]) -> dict[str, int]:
    counts = {v: 0 for v in VERDICTS}
    for case in cases:
        if case.verdict in counts:
            counts[case.verdict] += 1
    return counts


def top_indicators(cases: list[CaseRow], top_n: int) -> list[dict]:
    counts: dict[str, int] = {}
    meta: dict[str, dict] = {}
    for case in cases:
        for indicator in case.indicators:
            indicator_id = indicator["id"]
            counts[indicator_id] = counts.get(indicator_id, 0) + 1
            meta.setdefault(
                indicator_id,
                {
                    "title": indicator.get("title", ""),
                    "category": indicator.get("category", ""),
                    "severity": indicator.get("severity", ""),
                },
            )

    ranked = sorted(counts.items(), key=lambda kv: kv[1], reverse=True)[:top_n]
    return [{"indicator_id": indicator_id, "count": count, **meta[indicator_id]} for indicator_id, count in ranked]


def monthly_threat_trend(cases: list[CaseRow]) -> list[dict]:
    """Counts of non-safe (suspicious + malicious) cases per month they occurred in.
    Only months with at least one threat are included (no zero-filled gaps)."""
    counts: dict[str, int] = {}
    for case in cases:
        if case.verdict == "safe":
            continue
        month_key = case.created_at.strftime("%Y-%m")
        counts[month_key] = counts.get(month_key, 0) + 1
    return [{"month": month, "count": counts[month]} for month in sorted(counts)]


def framework_coverage(
    cases: list[CaseRow], total_controls_by_framework: dict[str, int]
) -> list[dict]:
    """% of each framework's full control set (the YAML universe) that's actually
    referenced by at least one in-period case."""
    covered: dict[str, set[str]] = {key: set() for key in total_controls_by_framework}
    for case in cases:
        for framework_key, refs in case.framework_mappings.items():
            if framework_key not in covered:
                continue
            for ref in refs:
                covered[framework_key].add(ref["control_id"])

    result = []
    for framework_key, total in total_controls_by_framework.items():
        covered_count = len(covered[framework_key])
        pct = round(100 * covered_count / total, 2) if total else 0.0
        result.append(
            {
                "framework_key": framework_key,
                "total_controls": total,
                "covered_controls": covered_count,
                "coverage_pct": pct,
            }
        )
    return result


def agreement_rate(cases: list[CaseRow], latest_label_by_case: dict[str, LabelRow]) -> dict:
    """% of labeled in-period cases where the analyst's latest verdict matches the
    machine verdict. None (not 0%) when nothing's labeled yet."""
    labeled = [c for c in cases if c.id in latest_label_by_case]
    labeled_count = len(labeled)
    if labeled_count == 0:
        return {"rate_pct": None, "labeled_count": 0, "agreeing_count": 0}

    agreeing = sum(1 for c in labeled if latest_label_by_case[c.id].analyst_verdict == c.verdict)
    return {
        "rate_pct": round(100 * agreeing / labeled_count, 2),
        "labeled_count": labeled_count,
        "agreeing_count": agreeing,
    }


def kris(cases: list[CaseRow], latest_label_by_case: dict[str, LabelRow], now: datetime) -> dict:
    """Key risk indicators, using the analyst's latest label as ground truth on the
    binary malicious/not-malicious question:

    - malicious_catch_rate_pct = TP / (TP+FN)  — of cases the analyst says ARE malicious,
      what fraction did the machine also flag malicious (recall).
    - false_positive_rate_pct = FP / (FP+TN)  — of cases the analyst says are NOT
      malicious, what fraction did the machine wrongly flag malicious.
    - mean_unlabeled_backlog_days = average age of in-period cases with no label at all.

    Every rate/mean is None (not a fake 0) when its denominator is 0.
    """
    labeled = [c for c in cases if c.id in latest_label_by_case]
    unlabeled = [c for c in cases if c.id not in latest_label_by_case]

    tp = fn = fp = tn = 0
    for case in labeled:
        machine_malicious = case.verdict == "malicious"
        analyst_malicious = latest_label_by_case[case.id].analyst_verdict == "malicious"
        if machine_malicious and analyst_malicious:
            tp += 1
        elif not machine_malicious and analyst_malicious:
            fn += 1
        elif machine_malicious and not analyst_malicious:
            fp += 1
        else:
            tn += 1

    catch_rate = round(100 * tp / (tp + fn), 2) if (tp + fn) else None
    false_positive_rate = round(100 * fp / (fp + tn), 2) if (fp + tn) else None

    if unlabeled:
        backlog_days = [(now - case.created_at).total_seconds() / 86400 for case in unlabeled]
        mean_backlog = round(sum(backlog_days) / len(backlog_days), 2)
    else:
        mean_backlog = None

    return {
        "malicious_catch_rate_pct": catch_rate,
        "false_positive_rate_pct": false_positive_rate,
        "mean_unlabeled_backlog_days": mean_backlog,
        "unlabeled_count": len(unlabeled),
        "labeled_count": len(labeled),
    }
