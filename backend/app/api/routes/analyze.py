"""POST /api/analyze — analyze a single uploaded .eml file for phishing indicators. Requires
auth (M8 Stage 2); the resulting Case is scoped to the authenticated user's account."""

from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends, HTTPException, UploadFile
from sqlalchemy.orm import Session

from app.analysis.email_pipeline import run_email_pipeline
from app.auth.dependencies import get_current_user
from app.core.config import settings
from app.db.models import Case, User
from app.db.session import get_db
from app.models.schemas import AnalyzeResponse, EmailSummary
from app.storage.raw_email_store import save_raw_email

router = APIRouter(prefix="/api", tags=["analyze"])


@router.post("/analyze", response_model=AnalyzeResponse)
async def analyze_email(
    file: UploadFile,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> AnalyzeResponse:
    if not file.filename or not file.filename.lower().endswith(".eml"):
        raise HTTPException(status_code=400, detail="Uploaded file must have a .eml extension.")

    raw_bytes = await file.read()
    if not raw_bytes:
        raise HTTPException(status_code=400, detail="Uploaded file is empty.")
    if len(raw_bytes) > settings.max_upload_bytes:
        raise HTTPException(status_code=400, detail="Uploaded file exceeds the maximum allowed size.")

    try:
        result = run_email_pipeline(raw_bytes)
    except Exception as exc:  # noqa: BLE001 - surface parse failures as a 400, not a 500
        raise HTTPException(status_code=400, detail=f"Failed to parse .eml file: {exc}") from exc

    parsed = result.parsed
    summary = EmailSummary(
        from_display=parsed.from_display,
        from_address=parsed.from_address,
        reply_to_address=parsed.reply_to_address,
        to=parsed.to_addresses,
        subject=parsed.subject,
        date=parsed.date,
        auth_results=parsed.auth_results,
        link_count=len(parsed.links),
        attachment_count=len(parsed.attachments),
    )

    case_id = uuid.uuid4()
    raw_email_path = save_raw_email(case_id, raw_bytes)

    indicators_json = [i.model_dump(mode="json") for i in result.indicators]
    framework_mappings_json = {
        key: [ref.model_dump(mode="json") for ref in refs]
        for key, refs in result.framework_mappings.items()
    }

    case = Case(
        id=case_id,
        account_id=current_user.account_id,
        filename=file.filename,
        verdict=result.verdict.value,
        score=result.score,
        from_addr=parsed.from_address,
        subject=parsed.subject,
        to_addresses=parsed.to_addresses,
        indicators=indicators_json,
        framework_mappings=framework_mappings_json,
        analyst_narrative=result.analyst_narrative,
        analyst_model=result.analyst_model,
        raw_email_path=raw_email_path,
    )
    db.add(case)
    db.commit()
    db.refresh(case)

    return AnalyzeResponse(
        id=case.id,
        created_at=case.created_at,
        verdict=result.verdict,
        score=result.score,
        summary=summary,
        indicators=result.indicators,
        framework_mappings=result.framework_mappings,
        analyst_narrative=result.analyst_narrative,
        analyst_model=result.analyst_model,
    )
