"""GET /api/labels/export — labeled cases as JSONL, the future ML training-set format."""

from __future__ import annotations

import json
import uuid
from collections.abc import Iterator

from fastapi import APIRouter, Depends
from fastapi.responses import StreamingResponse
from sqlalchemy.orm import Session

from app.db.models import Case, Label
from app.db.session import get_db

router = APIRouter(prefix="/api/labels", tags=["labels"])


def _latest_labels_by_case(db: Session) -> dict[uuid.UUID, Label]:
    # Ordered by case_id, then created_at desc: the first row seen per case_id is that
    # case's latest label. Avoids a join/subquery tie-break on timestamps.
    latest: dict[uuid.UUID, Label] = {}
    for label in db.query(Label).order_by(Label.case_id, Label.created_at.desc()).all():
        latest.setdefault(label.case_id, label)
    return latest


def _export_lines(db: Session) -> Iterator[str]:
    latest_by_case = _latest_labels_by_case(db)
    cases = (
        db.query(Case)
        .filter(Case.id.in_(latest_by_case.keys()))
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
async def export_labels(db: Session = Depends(get_db)) -> StreamingResponse:
    return StreamingResponse(_export_lines(db), media_type="application/x-ndjson")
