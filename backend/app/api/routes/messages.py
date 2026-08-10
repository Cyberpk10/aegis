"""POST /api/messages/analyze — analyze an already-normalized Slack/Teams chat message (M7
Stage B). Source-agnostic: the request body is the same shape
app.channels.slack_adapter.normalize_slack_message / teams_adapter.normalize_teams_message
produce — a caller runs the adapter first, then POSTs the common shape here. Reuses the exact
same run_indicators -> fuse -> map_indicators pipeline app.api.routes.analyze uses, and persists
into the same `cases` table (with channel="slack"/"teams"), so chat cases show up side-by-side
with email cases in GET /api/cases.
"""

from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app.channels.message import Channel, Link, Message, domain_of
from app.db.models import Case
from app.db.session import get_db
from app.indicators.engine import run_indicators
from app.mapping.framework_mapper import map_indicators
from app.models.schemas import ChatMessageSummary, MessageAnalyzeRequest, MessageAnalyzeResponse
from app.scoring.risk_engine import fuse

router = APIRouter(prefix="/api/messages", tags=["messages"])


@router.post("/analyze", response_model=MessageAnalyzeResponse)
async def analyze_message(
    body: MessageAnalyzeRequest, db: Session = Depends(get_db)
) -> MessageAnalyzeResponse:
    # href_domain is server-computed, never trusted from the client — same principle as
    # eml_parser computing it from parsed HTML/text rather than accepting it as input.
    links = [
        Link(display_text=link.display_text, href=link.href, href_domain=domain_of(link.href))
        for link in body.links
    ]

    message = Message(
        channel=Channel(body.channel),
        from_display=body.from_display,
        from_address=body.from_address,
        body_text=body.text,
        links=links,
        mentions=body.mentions,
        is_direct_message=body.is_direct_message,
        is_external_sender=body.is_external_sender,
        channel_name=body.channel_name,
        date=body.timestamp.isoformat() if body.timestamp else None,
    )

    indicators = run_indicators(message)
    score, verdict = fuse(indicators)
    framework_mappings = map_indicators([i.id for i in indicators])

    case_id = uuid.uuid4()
    indicators_json = [i.model_dump(mode="json") for i in indicators]
    framework_mappings_json = {
        key: [ref.model_dump(mode="json") for ref in refs]
        for key, refs in framework_mappings.items()
    }

    case = Case(
        id=case_id,
        filename=f"{body.channel}:{case_id}",
        channel=body.channel,
        verdict=verdict.value,
        score=score,
        from_addr=body.from_address,
        subject=None,
        indicators=indicators_json,
        framework_mappings=framework_mappings_json,
    )
    db.add(case)
    db.commit()
    db.refresh(case)

    summary = ChatMessageSummary(
        channel=body.channel,
        channel_name=body.channel_name,
        from_display=body.from_display,
        from_address=body.from_address,
        is_direct_message=body.is_direct_message,
        link_count=len(body.links),
        mentions_count=len(body.mentions),
    )

    return MessageAnalyzeResponse(
        id=case.id,
        created_at=case.created_at,
        verdict=verdict,
        score=score,
        summary=summary,
        indicators=indicators,
        framework_mappings=framework_mappings,
    )
