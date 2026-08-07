"""GET/DELETE endpoints for browsing and managing persisted analysis cases."""

from __future__ import annotations

from datetime import datetime
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session

from app.db.models import Case
from app.db.session import get_db
from app.models.schemas import CaseDetailResponse, CaseListResponse, CaseSummary, Verdict
from app.storage.raw_email_store import delete_raw_email

router = APIRouter(prefix="/api/cases", tags=["cases"])


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
    return CaseDetailResponse.model_validate(case)


@router.delete("/{case_id}", status_code=204)
async def delete_case(case_id: UUID, db: Session = Depends(get_db)) -> None:
    case = db.get(Case, case_id)
    if case is None:
        raise HTTPException(status_code=404, detail="Case not found.")
    db.delete(case)
    db.commit()
    delete_raw_email(case_id)
