"""Shared raw-bytes -> parsed -> indicators -> score -> framework-mappings pipeline (M8
Stage 3). Extracted out of app.api.routes.analyze so the new inbound-email webhook
(app.api.routes.inbound) doesn't need a third copy of this sequence. app.api.routes.messages
has its own independent, smaller pipeline (no eml parsing/raw storage/LLM narrative involved
there) — left as-is, out of scope.
"""

from __future__ import annotations

from dataclasses import dataclass

from app.core.config import settings
from app.indicators.engine import run_indicators
from app.mapping.framework_mapper import map_indicators
from app.models.schemas import FrameworkControlRef, Indicator, Verdict
from app.parsing.eml_parser import ParsedEmail, parse_eml
from app.reasoning.llm_analyst import generate_analyst_narrative
from app.scoring.risk_engine import fuse


@dataclass(frozen=True)
class PipelineResult:
    parsed: ParsedEmail
    indicators: list[Indicator]
    score: int
    verdict: Verdict
    framework_mappings: dict[str, list[FrameworkControlRef]]
    analyst_narrative: str | None
    analyst_model: str | None


def run_email_pipeline(raw_bytes: bytes) -> PipelineResult:
    """Parses raw .eml bytes and runs the full rule-based + optional LLM analysis. Raises
    whatever parse_eml raises on malformed input — callers translate that into their own
    error response (a 400 for a direct upload, a quiet reject for a webhook)."""
    parsed = parse_eml(raw_bytes)

    indicators = run_indicators(parsed)
    score, verdict = fuse(indicators)
    framework_mappings = map_indicators([i.id for i in indicators])

    analyst_narrative: str | None = None
    analyst_model: str | None = None
    if settings.enable_llm_reasoning:
        analyst_narrative, analyst_model = generate_analyst_narrative(
            parsed, indicators, score, verdict
        )

    return PipelineResult(
        parsed=parsed,
        indicators=indicators,
        score=score,
        verdict=verdict,
        framework_mappings=framework_mappings,
        analyst_narrative=analyst_narrative,
        analyst_model=analyst_model,
    )
