"""GET/DELETE endpoints for browsing and managing persisted analysis cases, plus the
analyst-feedback POST .../label endpoint (Stage 3)."""

from __future__ import annotations

from datetime import datetime
from uuid import UUID

from fastapi import APIRouter, Depends, Header, HTTPException, Query
from sqlalchemy.orm import Session

from app.core.config import settings
from app.db.models import Case, Label
from app.db.session import get_db
from app.models.schemas import (
    CaseDetailResponse,
    CaseListResponse,
    CaseSummary,
    LabelRequest,
    LabelResponse,
    Verdict,
)
from app.storage.raw_email_store import delete_raw_email

router = APIRouter(prefix="/api/cases", tags=["cases"])


def _latest_label(db: Session, case_id: UUID) -> Label | None:
    return (
        db.query(Label)
        .filter(Label.case_id == case_id)
        .order_by(Label.created_at.desc())
        .first()
    )


def _to_case_detail(case: Case, latest_label: Label | None) -> CaseDetailResponse:
    return CaseDetailResponse(
        id=case.id,
        created_at=case.created_at,
        filename=case.filename,
        verdict=case.verdict,
        score=case.score,
        from_addr=case.from_addr,
        subject=case.subject,
        indicators=case.indicators,
        framework_mappings=case.framework_mappings,
        analyst_narrative=case.analyst_narrative,
        analyst_model=case.analyst_model,
        latest_label=LabelResponse.model_validate(latest_label) if latest_label else None,
    )


@router.get("", response_model=CaseListResponse)
async def list_cases(
    db: Session = Depends(get_db),
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    verdict: Verdict | None = None,
    date_from: datetime | None = None,
    date_to: datetime | None = None,
) -> CaseListResponse:
    query = db.query(Case)
    if verdict is not None:
        query = query.filter(Case.verdict == verdict.value)
    if date_from is not None:
        query = query.filter(Case.created_at >= date_from)
    if date_to is not None:
        query = query.filter(Case.created_at <= date_to)

    total = query.count()
    rows = (
        query.order_by(Case.created_at.desc())
        .offset((page - 1) * page_size)
        .limit(page_size)
        .all()
    )

    return CaseListResponse(
        items=[CaseSummary.model_validate(row) for row in rows],
        total=total,
        page=page,
        page_size=page_size,
    )


@router.get("/{case_id}", response_model=CaseDetailResponse)
async def get_case(case_id: UUID, db: Session = Depends(get_db)) -> CaseDetailResponse:
    case = db.get(Case, case_id)
    if case is None:
        raise HTTPException(status_code=404, detail="Case not found.")
    return _to_case_detail(case, _latest_label(db, case_id))


@router.delete("/{case_id}", status_code=204)
async def delete_case(case_id: UUID, db: Session = Depends(get_db)) -> None:
    case = db.get(Case, case_id)
    if case is None:
        raise HTTPException(status_code=404, detail="Case not found.")
    db.delete(case)
    db.commit()
    delete_raw_email(case_id)


@router.post("/{case_id}/label", response_model=LabelResponse)
async def label_case(
    case_id: UUID,
    body: LabelRequest,
    db: Session = Depends(get_db),
    x_analyst_id: str | None = Header(default=None),
) -> LabelResponse:
    """Record an analyst's verdict on a case. Append-only — relabeling inserts a new row
    rather than overwriting the previous one, so the full labeling history is preserved."""
    case = db.get(Case, case_id)
    if case is None:
        raise HTTPException(status_code=404, detail="Case not found.")

    label = Label(
        case_id=case_id,
        analyst_verdict=body.analyst_verdict.value,
        note=body.note,
        labeled_by=x_analyst_id or settings.default_analyst_id,
    )
    db.add(label)
    db.commit()
    db.refresh(label)

    return LabelResponse.model_validate(label)
