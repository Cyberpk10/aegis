"""GET /api/labels/export — labeled cases as JSONL, the future ML training-set format.
Scoped to the authenticated user's account (M8 Stage 2)."""

from __future__ import annotations

import json
import uuid
from collections.abc import Iterator
from uuid import UUID

from fastapi import APIRouter, Depends
from fastapi.responses import StreamingResponse
from sqlalchemy.orm import Session

from app.auth.dependencies import get_current_user
from app.db.models import Case, Label, User
from app.db.session import get_db

router = APIRouter(prefix="/api/labels", tags=["labels"])


def _latest_labels_by_case(db: Session, account_id: UUID) -> dict[uuid.UUID, Label]:
    # Ordered by case_id, then created_at desc: the first row seen per case_id is that
    # case's latest label. Avoids a join/subquery tie-break on timestamps.
    latest: dict[uuid.UUID, Label] = {}
    query = (
        db.query(Label)
        .filter(Label.account_id == account_id)
        .order_by(Label.case_id, Label.created_at.desc())
    )
    for label in query.all():
        latest.setdefault(label.case_id, label)
    return latest


def _export_lines(db: Session, account_id: UUID) -> Iterator[str]:
    latest_by_case = _latest_labels_by_case(db, account_id)
    cases = (
        db.query(Case)
        .filter(Case.account_id == account_id, Case.id.in_(latest_by_case.keys()))
        .order_by(Case.created_at)
        .all()
    )
    for case in cases:
        label = latest_by_case[case.id]
        record = {
            "case_id": str(case.id),
            "case_created_at": case.created_at.isoformat(),
            "filename": case.filename,
            "from_addr": case.from_addr,
            "subject": case.subject,
            "machine_verdict": case.verdict,
            "machine_score": case.score,
            "indicators": case.indicators,
            "framework_mappings": case.framework_mappings,
            "analyst_verdict": label.analyst_verdict,
            "note": label.note,
            "labeled_by": label.labeled_by,
            "labeled_at": label.created_at.isoformat(),
        }
        yield json.dumps(record) + "\n"


@router.get("/export")
async def export_labels(
    db: Session = Depends(get_db), current_user: User = Depends(get_current_user)
) -> StreamingResponse:
    return StreamingResponse(
        _export_lines(db, current_user.account_id), media_type="application/x-ndjson"
    )
