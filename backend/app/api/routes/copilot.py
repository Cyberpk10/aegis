"""POST /api/copilot/query — natural-language threat copilot over Aegis's own data.

Defensive/reporting only. The LLM never generates or influences an actual database
query: it can only pick one of app.copilot.templates.TEMPLATE_REGISTRY's whitelisted,
parameterized templates (app.copilot.llm.select_template, a forced tool-use call), which
this route re-validates against the whitelist before executing anything
(app.copilot.templates.execute_template). A second, tool-free call narrates the already-
retrieved figures — see app/copilot/llm.py for the full security rationale.
"""

from __future__ import annotations

import os
from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException
from pydantic import ValidationError
from sqlalchemy.orm import Session

from app.copilot.llm import narrate, select_template
from app.copilot.templates import execute_template
from app.core.config import settings
from app.db.session import get_db
from app.models.schemas import CopilotQueryRequest, CopilotQueryResponse, CopilotTemplateUsed

router = APIRouter(prefix="/api/copilot", tags=["copilot"])


@router.post("/query", response_model=CopilotQueryResponse)
async def copilot_query(
    body: CopilotQueryRequest, db: Session = Depends(get_db)
) -> CopilotQueryResponse:
    if not settings.enable_copilot:
        raise HTTPException(
            status_code=503, detail="The copilot is not enabled on this deployment."
        )

    api_key = os.environ.get("ANTHROPIC_API_KEY")
    if not api_key:
        raise HTTPException(
            status_code=503, detail="The copilot is not configured (missing ANTHROPIC_API_KEY)."
        )

    selection = select_template(body.question, model=settings.llm_model, api_key=api_key)
    if selection is None:
        raise HTTPException(
            status_code=502, detail="Could not determine how to answer that question right now."
        )
    template_name, raw_params = selection

    # Never trust the LLM's output directly: template_name must be a literal whitelist
    # key and raw_params must pass that template's own extra="forbid" schema. This is
    # the real security boundary — it holds even if select_template's output were fully
    # attacker-controlled.
    try:
        resolved_name, params, result = execute_template(template_name, raw_params, db)
    except KeyError as exc:
        raise HTTPException(
            status_code=400, detail=f"Unknown query template: {template_name!r}."
        ) from exc
    except ValidationError as exc:
        raise HTTPException(
            status_code=400, detail=f"Invalid parameters for template {template_name!r}: {exc}"
        ) from exc

    narrative = narrate(
        body.question, resolved_name, result, model=settings.llm_model, api_key=api_key
    )
    if narrative is None:
        narrative = (
            "Here are the figures retrieved for your question (narration is temporarily "
            "unavailable, but the data below is accurate)."
        )

    return CopilotQueryResponse(
        question=body.question,
        narrative=narrative,
        template_used=CopilotTemplateUsed(
            template=resolved_name, params=params.model_dump(mode="json")
        ),
        result=result,
        generated_at=datetime.utcnow(),
    )
