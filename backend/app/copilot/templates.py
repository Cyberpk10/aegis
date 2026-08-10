"""The whitelist of safe, parameterized query templates the copilot's LLM call can pick
from — and nothing else. app/copilot/llm.py never lets Claude produce free-form output;
it can only select one of these template names and fill in the corresponding Pydantic
model's fields (`extra="forbid"` — unexpected fields are a hard validation error, not
silently dropped). Every executor is a plain SQLAlchemy ORM query plus the same pure
aggregation functions the Dashboard/Audit/Remediation features already use and already
test — there is no raw SQL, and no string-built query, anywhere in this module.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy.orm import Session

from app.audit.aggregation import evidence_for_framework
from app.core.config import settings
from app.dashboard.aggregation import CaseRow
from app.dashboard.aggregation import top_indicators as _top_indicators
from app.dashboard.aggregation import verdict_counts as _verdict_counts
from app.db.models import Case
from app.mapping.framework_mapper import get_framework, resolve_framework_alias
from app.models.schemas import AuditFramework
from app.remediation.targets import TargetCaseRow, aggregate_targets


class _BaseParams(BaseModel):
    model_config = ConfigDict(extra="forbid")


class _DateRangeParams(_BaseParams):
    date_from: datetime | None = None
    date_to: datetime | None = None


class VerdictCountsParams(_DateRangeParams):
    pass


class TopIndicatorsParams(_DateRangeParams):
    top_n: int = Field(default=5, ge=1, le=20)


class IndicatorCaseCountParams(_DateRangeParams):
    indicator_id: str


class TargetLookupParams(_DateRangeParams):
    recipient: str


class FrameworkCoverageParams(_DateRangeParams):
    framework: AuditFramework


class UnsupportedQuestionParams(_BaseParams):
    reason: str


def _cases_in_range(
    db: Session, account_id: UUID, date_from: datetime | None, date_to: datetime | None
) -> list[Case]:
    query = db.query(Case).filter(Case.account_id == account_id)
    if date_from is not None:
        query = query.filter(Case.created_at >= date_from)
    if date_to is not None:
        query = query.filter(Case.created_at <= date_to)
    return query.all()


def _to_case_row(case: Case) -> CaseRow:
    return CaseRow(
        id=str(case.id),
        created_at=case.created_at,
        verdict=case.verdict,
        indicators=case.indicators,
        framework_mappings=case.framework_mappings,
    )


def _to_target_row(case: Case) -> TargetCaseRow:
    return TargetCaseRow(
        id=str(case.id),
        created_at=case.created_at,
        verdict=case.verdict,
        to_addresses=case.to_addresses,
        indicators=case.indicators,
    )


def _iso(value: datetime | None) -> str | None:
    return value.isoformat() if value else None


def _execute_verdict_counts(params: VerdictCountsParams, db: Session, account_id: UUID) -> dict:
    cases = [
        _to_case_row(c) for c in _cases_in_range(db, account_id, params.date_from, params.date_to)
    ]
    counts = _verdict_counts(cases)
    return {
        "date_from": _iso(params.date_from),
        "date_to": _iso(params.date_to),
        "counts": counts,
        "total": sum(counts.values()),
    }


def _execute_top_indicators(params: TopIndicatorsParams, db: Session, account_id: UUID) -> dict:
    cases = [
        _to_case_row(c) for c in _cases_in_range(db, account_id, params.date_from, params.date_to)
    ]
    return {
        "date_from": _iso(params.date_from),
        "date_to": _iso(params.date_to),
        "top_indicators": _top_indicators(cases, params.top_n),
    }


def _execute_indicator_case_count(
    params: IndicatorCaseCountParams, db: Session, account_id: UUID
) -> dict:
    cases_orm = _cases_in_range(db, account_id, params.date_from, params.date_to)
    matching = [
        c for c in cases_orm if any(i.get("id") == params.indicator_id for i in c.indicators)
    ]
    return {
        "indicator_id": params.indicator_id,
        "date_from": _iso(params.date_from),
        "date_to": _iso(params.date_to),
        "count": len(matching),
        "sample_case_ids": [
            str(c.id) for c in sorted(matching, key=lambda c: c.created_at, reverse=True)[:5]
        ],
    }


def _execute_target_lookup(params: TargetLookupParams, db: Session, account_id: UUID) -> dict:
    recipient = params.recipient.strip().lower()
    cases = [
        _to_target_row(c)
        for c in _cases_in_range(db, account_id, params.date_from, params.date_to)
    ]
    summaries = aggregate_targets(cases, threshold=settings.target_training_threshold)
    match = next((s for s in summaries if s.recipient == recipient), None)

    base = {
        "recipient": recipient,
        "date_from": _iso(params.date_from),
        "date_to": _iso(params.date_to),
    }
    if match is None:
        return {
            **base,
            "hit_count": 0,
            "flagged_for_training": False,
            "top_indicator_id": None,
            "top_indicator_title": None,
            "recommendation": None,
        }
    return {
        **base,
        "hit_count": match.hit_count,
        "flagged_for_training": match.flagged_for_training,
        "top_indicator_id": match.top_indicator_id,
        "top_indicator_title": match.top_indicator_title,
        "recommendation": match.recommendation,
    }


def _execute_framework_coverage(
    params: FrameworkCoverageParams, db: Session, account_id: UUID
) -> dict:
    framework_key = resolve_framework_alias(params.framework)
    loaded = get_framework(framework_key)
    base = {
        "framework": params.framework.value,
        "date_from": _iso(params.date_from),
        "date_to": _iso(params.date_to),
    }
    if loaded is None:
        return {**base, "error": "Framework is not loaded."}

    cases = [
        _to_case_row(c) for c in _cases_in_range(db, account_id, params.date_from, params.date_to)
    ]
    evidence = evidence_for_framework(cases, loaded.controls_by_id, framework_key)
    operating = sum(1 for e in evidence if e.operating)

    return {
        **base,
        "framework_name": loaded.name,
        "total_controls": len(evidence),
        "operating_controls": operating,
        "coverage_pct": round(100 * operating / len(evidence), 2) if evidence else 0.0,
        "controls": [
            {
                "control_id": e.control_id,
                "control_name": e.control_name,
                "detection_count": e.detection_count,
                "operating": e.operating,
            }
            for e in evidence
        ],
    }


def _execute_unsupported_question(
    params: UnsupportedQuestionParams, db: Session, account_id: UUID
) -> dict:
    return {"answerable": False, "reason": params.reason}


@dataclass(frozen=True)
class CopilotTemplate:
    name: str
    description: str
    param_model: type[BaseModel]
    executor: Callable[[BaseModel, Session, UUID], dict]


TEMPLATE_REGISTRY: dict[str, CopilotTemplate] = {
    t.name: t
    for t in [
        CopilotTemplate(
            "verdict_counts",
            "Count analyzed emails by verdict (malicious/suspicious/safe), optionally "
            "within a date range.",
            VerdictCountsParams,
            _execute_verdict_counts,
        ),
        CopilotTemplate(
            "top_indicators",
            "List the most frequently triggered phishing indicators, optionally within "
            "a date range.",
            TopIndicatorsParams,
            _execute_top_indicators,
        ),
        CopilotTemplate(
            "indicator_case_count",
            "Count how many cases triggered a specific named indicator id (e.g. "
            "CREDENTIAL_REQUEST, LOOKALIKE_DOMAIN, AI_AUTHORED_SUSPECTED), optionally "
            "within a date range.",
            IndicatorCaseCountParams,
            _execute_indicator_case_count,
        ),
        CopilotTemplate(
            "target_lookup",
            "Look up how many times a specific recipient email address has been "
            "targeted by non-safe cases, and whether they're flagged for micro-training.",
            TargetLookupParams,
            _execute_target_lookup,
        ),
        CopilotTemplate(
            "framework_coverage",
            "Get compliance-framework control coverage (nist, iso, soc2, or mitre) — "
            "how many controls have at least one supporting detection, optionally "
            "within a date range.",
            FrameworkCoverageParams,
            _execute_framework_coverage,
        ),
        CopilotTemplate(
            "unsupported_question",
            "Use this when the question cannot be answered from Aegis's case data "
            "using any of the other available templates.",
            UnsupportedQuestionParams,
            _execute_unsupported_question,
        ),
    ]
}


def execute_template(
    template_name: str, raw_params: dict, db: Session, account_id: UUID
) -> tuple[str, BaseModel, dict]:
    """The single, whitelist-enforcing entry point for running a copilot query.

    Raises KeyError for a template name that isn't a literal key in TEMPLATE_REGISTRY,
    and pydantic.ValidationError for missing/invalid/extra parameters — callers turn both
    into an HTTP 400. This function never executes anything outside the fixed registry no
    matter what template_name/raw_params it is given, which is the actual security
    boundary: even if the LLM call that produced these values were fully compromised, the
    worst it can do is fail this lookup/validation. `account_id` is always the
    authenticated caller's own (see app.api.routes.copilot) — never LLM- or
    client-supplied — so a copilot query can never cross into another account's data.
    """
    template = TEMPLATE_REGISTRY[template_name]
    params = template.param_model(**raw_params)
    result = template.executor(params, db, account_id)
    return template.name, params, result
