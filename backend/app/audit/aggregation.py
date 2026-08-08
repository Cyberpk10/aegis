"""Pure evidence-aggregation math for Audit Mode — no DB here, plain dataclasses in,
plain dataclasses out. Mirrors app/dashboard/aggregation.py's separation from route/DB
wiring, and reuses its CaseRow (same shape: id, created_at, verdict, framework_mappings)
rather than duplicating it.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime

from app.dashboard.aggregation import CaseRow

DEFAULT_SAMPLE_SIZE = 5


@dataclass(frozen=True)
class CaseRef:
    id: str
    verdict: str
    created_at: datetime


@dataclass(frozen=True)
class ControlEvidence:
    control_id: str
    control_name: str
    detection_count: int
    supporting_case_ids: list[str]
    sample_cases: list[CaseRef]
    operating: bool


def evidence_for_framework(
    cases: list[CaseRow],
    controls_by_id: dict[str, dict],
    framework_key: str,
    sample_size: int = DEFAULT_SAMPLE_SIZE,
) -> list[ControlEvidence]:
    """For every control in `controls_by_id` (the framework's full control universe — so
    a control with zero evidence still appears, marked not-operating, rather than being
    silently omitted), collects the in-period cases whose `framework_mappings[framework_key]`
    reference it. A case counts once per control even if multiple of its indicators map to
    the same control — `detection_count` is "supporting cases," not a raw indicator-hit
    count. `supporting_case_ids` is the *full* set (so callers can compute distinct-case
    totals across every control); `sample_cases` is just the most recent `sample_size` of
    those, for auditor spot-checking/display."""
    cases_by_control: dict[str, list[CaseRow]] = {control_id: [] for control_id in controls_by_id}

    for case in cases:
        refs = case.framework_mappings.get(framework_key, [])
        seen_controls: set[str] = set()
        for ref in refs:
            control_id = ref["control_id"]
            if control_id not in cases_by_control or control_id in seen_controls:
                continue
            seen_controls.add(control_id)
            cases_by_control[control_id].append(case)

    result = []
    for control_id, control in controls_by_id.items():
        supporting = sorted(cases_by_control[control_id], key=lambda c: c.created_at, reverse=True)
        samples = supporting[:sample_size]
        result.append(
            ControlEvidence(
                control_id=control_id,
                control_name=control["name"],
                detection_count=len(supporting),
                supporting_case_ids=[c.id for c in supporting],
                sample_cases=[
                    CaseRef(id=c.id, verdict=c.verdict, created_at=c.created_at) for c in samples
                ],
                operating=len(supporting) > 0,
            )
        )
    return result
