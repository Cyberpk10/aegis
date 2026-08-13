"""GET /api/dashboard/summary — read-only aggregation over cases/labels for a board-level
Threat & Compliance view. Nothing new is stored here; pure reporting over what Stages 2-3
already persist. Requires auth; scoped to the authenticated user's account (M8 Stage 2).
"""

from __future__ import annotations

from datetime import datetime, timedelta

from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session

from app.auth.dependencies import get_current_user
from app.core.time import to_naive_utc
from app.dashboard.aggregation import (
    CaseRow,
    LabelRow,
    agreement_rate,
    framework_coverage,
    kris,
    monthly_threat_trend,
    top_indicators,
    verdict_counts,
)
from app.db.models import Case, Label, User
from app.db.session import get_db
from app.mapping.framework_mapper import framework_display_names, total_controls_by_framework
from app.models.schemas import (
    AgreementRate,
    DashboardSummaryResponse,
    FrameworkCoverage,
    KRIs,
    MonthlyThreatCount,
    PeriodCount,
    TopIndicator,
    VerdictCounts,
)

router = APIRouter(prefix="/api/dashboard", tags=["dashboard"])

DEFAULT_PERIOD_DAYS = 30


def _resolve_period(
    date_from: datetime | None, date_to: datetime | None
) -> tuple[datetime, datetime, datetime, datetime]:
    """Current period defaults to the last 30 days ending now. The previous period (for
    deltas) is an equal-length window immediately before the current one, end-exclusive
    so a case can't land in both windows."""
    period_end = date_to or datetime.utcnow()
    period_start = date_from or (period_end - timedelta(days=DEFAULT_PERIOD_DAYS))
    period_length = period_end - period_start
    previous_period_end = period_start
    previous_period_start = period_start - period_length
    return period_start, period_end, previous_period_start, previous_period_end


def _to_case_row(case: Case) -> CaseRow:
    return CaseRow(
        id=str(case.id),
        # Postgres (production) returns an aware datetime for a DateTime(timezone=True)
        # column; SQLite (tests) returns naive. kris() subtracts this from a naive
        # datetime.utcnow(), which raises TypeError if the two sides disagree — normalize
        # here so both dialects behave the same.
        created_at=to_naive_utc(case.created_at),
        verdict=case.verdict,
        indicators=case.indicators,
        framework_mappings=case.framework_mappings,
    )


def _period_delta(current: int, previous: int) -> PeriodCount:
    delta = current - previous
    delta_pct = round(100 * delta / previous, 2) if previous else None
    return PeriodCount(current=current, previous=previous, delta=delta, delta_pct=delta_pct)


@router.get("/summary", response_model=DashboardSummaryResponse)
async def dashboard_summary(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
    date_from: datetime | None = None,
    date_to: datetime | None = None,
    top_n: int = Query(10, ge=1, le=50),
) -> DashboardSummaryResponse:
    period_start, period_end, previous_period_start, previous_period_end = _resolve_period(
        date_from, date_to
    )

    current_cases_orm = (
        db.query(Case)
        .filter(
            Case.account_id == current_user.account_id,
            Case.created_at >= period_start,
            Case.created_at <= period_end,
        )
        .all()
    )
    previous_cases_orm = (
        db.query(Case)
        .filter(
            Case.account_id == current_user.account_id,
            Case.created_at >= previous_period_start,
            Case.created_at < previous_period_end,
        )
        .all()
    )

    current_cases = [_to_case_row(c) for c in current_cases_orm]
    previous_cases = [_to_case_row(c) for c in previous_cases_orm]

    current_case_ids = [c.id for c in current_cases_orm]
    labels_orm = (
        db.query(Label)
        .filter(Label.account_id == current_user.account_id, Label.case_id.in_(current_case_ids))
        .order_by(Label.case_id, Label.created_at.desc())
        .all()
        if current_case_ids
        else []
    )
    # Ordered by case_id, then created_at desc: the first row seen per case_id is the
    # latest label for that case (same pattern as app/api/routes/labels.py's export).
    latest_label_by_case: dict[str, LabelRow] = {}
    for label in labels_orm:
        case_id = str(label.case_id)
        latest_label_by_case.setdefault(
            case_id,
            LabelRow(
                case_id=case_id,
                analyst_verdict=label.analyst_verdict,
                created_at=label.created_at,
            ),
        )

    current_verdicts = verdict_counts(current_cases)
    previous_verdicts = verdict_counts(previous_cases)
    verdict_counts_response = VerdictCounts(
        malicious=_period_delta(current_verdicts["malicious"], previous_verdicts["malicious"]),
        suspicious=_period_delta(current_verdicts["suspicious"], previous_verdicts["suspicious"]),
        safe=_period_delta(current_verdicts["safe"], previous_verdicts["safe"]),
    )

    total_analyzed = _period_delta(len(current_cases), len(previous_cases))
    agreement = agreement_rate(current_cases, latest_label_by_case)
    top = top_indicators(current_cases, top_n)
    trend = monthly_threat_trend(current_cases)
    risk_indicators = kris(current_cases, latest_label_by_case, datetime.utcnow())

    display_names = framework_display_names()
    coverage = framework_coverage(current_cases, total_controls_by_framework())

    return DashboardSummaryResponse(
        period_start=period_start,
        period_end=period_end,
        previous_period_start=previous_period_start,
        previous_period_end=previous_period_end,
        total_analyzed=total_analyzed,
        verdict_counts=verdict_counts_response,
        analyst_agreement=AgreementRate(**agreement),
        top_indicators=[TopIndicator(**t) for t in top],
        monthly_threat_trend=[MonthlyThreatCount(**m) for m in trend],
        kris=KRIs(**risk_indicators),
        framework_coverage=[
            FrameworkCoverage(
                framework_name=display_names.get(c["framework_key"], c["framework_key"]), **c
            )
            for c in coverage
        ],
    )
