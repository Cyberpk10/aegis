"""POST /api/analyze — analyze a single uploaded .eml file for phishing indicators."""

from __future__ import annotations

from fastapi import APIRouter, HTTPException, UploadFile

from app.core.config import settings
from app.indicators.engine import run_indicators
from app.mapping.framework_mapper import map_indicators
from app.models.schemas import AnalyzeResponse, EmailSummary
from app.parsing.eml_parser import parse_eml
from app.scoring.risk_engine import fuse

router = APIRouter(prefix="/api", tags=["analyze"])


@router.post("/analyze", response_model=AnalyzeResponse)
async def analyze_email(file: UploadFile) -> AnalyzeResponse:
    if not file.filename or not file.filename.lower().endswith(".eml"):
        raise HTTPException(status_code=400, detail="Uploaded file must have a .eml extension.")

    raw_bytes = await file.read()
    if not raw_bytes:
        raise HTTPException(status_code=400, detail="Uploaded file is empty.")
    if len(raw_bytes) > settings.max_upload_bytes:
        raise HTTPException(status_code=400, detail="Uploaded file exceeds the maximum allowed size.")

    try:
        parsed = parse_eml(raw_bytes)
    except Exception as exc:  # noqa: BLE001 - surface parse failures as a 400, not a 500
        raise HTTPException(status_code=400, detail=f"Failed to parse .eml file: {exc}") from exc

    indicators = run_indicators(parsed)
    score, verdict = fuse(indicators)
    framework_mappings = map_indicators([i.id for i in indicators])

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

    return AnalyzeResponse(
        verdict=verdict,
        score=score,
        summary=summary,
        indicators=indicators,
        framework_mappings=framework_mappings,
    )
