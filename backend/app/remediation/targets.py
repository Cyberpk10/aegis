"""Pure per-recipient targeting aggregation — no DB here, plain dataclasses in, plain
dataclasses out. Mirrors app/dashboard/aggregation.py and app/audit/aggregation.py's
separation from route/DB wiring.
"""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass
from datetime import datetime


@dataclass(frozen=True)
class TargetCaseRow:
    id: str
    created_at: datetime
    verdict: str
    to_addresses: list[str]
    indicators: list[dict]


@dataclass(frozen=True)
class TargetSummary:
    recipient: str
    hit_count: int
    flagged_for_training: bool
    top_indicator_id: str | None
    top_indicator_title: str | None
    recommendation: str | None
    sample_case_ids: list[str]


def aggregate_targets(cases: list[TargetCaseRow], threshold: int) -> list[TargetSummary]:
    """Only non-safe cases count as a "hit" — being targeted by an actual flagged
    attempt, not just any analyzed mail. For each recipient, the most frequent indicator
    id among their hits is treated as "the specific tactic" that targeted them; a
    recommendation string is only populated once hit_count crosses `threshold`. Sorted by
    hit_count descending.
    """
    by_recipient: dict[str, list[TargetCaseRow]] = {}
    for case in cases:
        if case.verdict == "safe":
            continue
        for raw_recipient in case.to_addresses:
            recipient = raw_recipient.strip().lower()
            if not recipient:
                continue
            by_recipient.setdefault(recipient, []).append(case)

    summaries: list[TargetSummary] = []
    for recipient, hit_cases in by_recipient.items():
        indicator_counts: Counter[str] = Counter()
        indicator_titles: dict[str, str] = {}
        for case in hit_cases:
            for indicator in case.indicators:
                indicator_id = indicator["id"]
                indicator_counts[indicator_id] += 1
                indicator_titles.setdefault(indicator_id, indicator.get("title", indicator_id))

        top_indicator_id: str | None = None
        top_indicator_title: str | None = None
        top_count = 0
        if indicator_counts:
            top_indicator_id, top_count = indicator_counts.most_common(1)[0]
            top_indicator_title = indicator_titles[top_indicator_id]

        hit_count = len(hit_cases)
        flagged = hit_count >= threshold
        recommendation: str | None = None
        if flagged and top_indicator_id:
            recommendation = (
                f'Recommend micro-training on "{top_indicator_title}" — this tactic '
                f"appeared in {top_count} of {hit_count} flagged attempts targeting this "
                "recipient."
            )

        sample_case_ids = [
            c.id for c in sorted(hit_cases, key=lambda c: c.created_at, reverse=True)[:5]
        ]

        summaries.append(
            TargetSummary(
                recipient=recipient,
                hit_count=hit_count,
                flagged_for_training=flagged,
                top_indicator_id=top_indicator_id,
                top_indicator_title=top_indicator_title,
                recommendation=recommendation,
                sample_case_ids=sample_case_ids,
            )
        )

    summaries.sort(key=lambda s: s.hit_count, reverse=True)
    return summaries
