"""Shared types for detection rule modules (M5 Stage 1) — mirrors app.indicators.base."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Callable

from app.events.schema import ActivityEvent
from app.models.schemas import Finding, Severity


@dataclass(frozen=True)
class ActorEventWindow:
    """One actor's events within the current detection lookback window, sorted by
    timestamp. Every detection rule reads from this — never the DB directly — so rules
    stay pure and unit-testable without a database."""

    actor: str
    events: list[ActivityEvent]


# Each rule module exposes a top-level `evaluate(window) -> list[Finding]` matching this shape.
DetectionRule = Callable[[ActorEventWindow], list[Finding]]


def make_finding(
    *,
    id: str,
    category: str,
    title: str,
    description: str,
    severity: Severity,
    points: float,
    evidence_event_ids: list,
) -> Finding:
    return Finding(
        id=id,
        category=category,
        title=title,
        description=description,
        severity=severity,
        points=points,
        evidence_event_ids=evidence_event_ids,
    )
