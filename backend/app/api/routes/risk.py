"""GET /api/risk/financial — read-only financial risk quantification over cases/labels.
Defensive/reporting only: a simplified, deterministic, FAIR-style point estimate built
from editable, cited assumptions (see app.risk_model.assumptions.sources.md). Every
response always echoes the assumptions that produced it — never a black-box number.
"""

from __future__ import annotations

from datetime import datetime

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app.dashboard.aggregation import CaseRow, LabelRow, verdict_counts
from app.db.models import Case, Label
from app.db.session import get_db
from app.models.schemas import (
    FinancialRiskResponse,
    RiskAssumption,
    RiskAttackTypeBreakdown,
    RiskDetectionCounts,
    RiskExposureAvoided,
    RiskResidualRisk,
)
from app.risk_model.aggregation import exposure_avoided, residual_risk
from app.risk_model.assumptions import risk_assumptions

router = APIRouter(prefix="/api/risk", tags=["risk"])


def _current_quarter_bounds(now: datetime) -> tuple[datetime, datetime]:
    """Start (inclusive) and end (exclusive) of the calendar quarter `now` falls in."""
    quarter_start_month = ((now.month - 1) // 3) * 3 + 1
    period_start = datetime(now.year, quarter_start_month, 1)
    if quarter_start_month + 3 > 12:
        period_end = datetime(now.year + 1, quarter_start_month + 3 - 12, 1)
    else:
        period_end = datetime(now.year, quarter_start_month + 3, 1)
    return period_start, period_end


def _resolve_period(date_from: datetime | None, date_to: datetime | None) -> tuple[datetime, datetime]:
    if date_from and date_to:
        return date_from, date_to
    quarter_start, quarter_end = _current_quarter_bounds(datetime.utcnow())
    return date_from or quarter_start, date_to or quarter_end


def _to_case_row(case: Case) -> CaseRow:
    return CaseRow(
        id=str(case.id),
        created_at=case.created_at,
        verdict=case.verdict,
        indicators=case.indicators,
        framework_mappings=case.framework_mappings,
    )


def _to_breakdown(entries: list[dict]) -> list[RiskAttackTypeBreakdown]:
    return [RiskAttackTypeBreakdown(**entry) for entry in entries]


@router.get("/financial", response_model=FinancialRiskResponse)
async def financial_risk(
    db: Session = Depends(get_db),
    date_from: datetime | None = None,
    date_to: datetime | None = None,
) -> FinancialRiskResponse:
    period_start, period_end = _resolve_period(date_from, date_to)

    cases_orm = (
        db.query(Case)
        .filter(Case.created_at >= period_start, Case.created_at <= period_end)
        .all()
    )
    cases = [_to_case_row(c) for c in cases_orm]

    case_ids = [c.id for c in cases_orm]
    labels_orm = (
        db.query(Label).filter(Label.case_id.in_(case_ids)).order_by(Label.case_id, Label.created_at.desc()).all()
        if case_ids
        else []
    )
    latest_label_by_case: dict[str, LabelRow] = {}
    for label in labels_orm:
        case_id = str(label.case_id)
        latest_label_by_case.setdefault(
            case_id,
            LabelRow(case_id=case_id, analyst_verdict=label.analyst_verdict, created_at=label.created_at),
        )

    exposure = exposure_avoided(cases, risk_assumptions)
    residual = residual_risk(cases, latest_label_by_case, risk_assumptions)
    counts = verdict_counts(cases)

    return FinancialRiskResponse(
        period_start=period_start,
        period_end=period_end,
        exposure_avoided=RiskExposureAvoided(
            total_usd=exposure["total_usd"], by_attack_type=_to_breakdown(exposure["by_attack_type"])
        ),
        residual_risk=RiskResidualRisk(
            total_usd=residual["total_usd"],
            false_negative_count=residual["false_negative_count"],
            by_attack_type=_to_breakdown(residual["by_attack_type"]),
            note=residual["note"],
        ),
        detection_counts=RiskDetectionCounts(**counts),
        assumptions={
            key: RiskAssumption(**value) for key, value in risk_assumptions.to_response_dict().items()
        },
        generated_at=datetime.utcnow(),
    )
