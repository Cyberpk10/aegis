"""Shared types for detection rule modules (M5 Stage 1) — mirrors app.indicators.base."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Callable

from app.baselines.aggregation import BaselineSnapshot
from app.events.schema import ActivityEvent
from app.models.schemas import Finding, Severity


@dataclass(frozen=True)
class ActorEventWindow:
    """One actor's events within the current detection lookback window, sorted by
    timestamp. Every detection rule reads from this — never the DB directly — so rules
    stay pure and unit-testable without a database."""

    actor: str
    events: list[ActivityEvent]


# Each rule module exposes a top-level `evaluate(window, baseline) -> list[Finding]` matching
# this shape. `baseline` is None for an actor with no stored history yet — every rule that
# uses it (M5 Stage 2) must degrade to a sensible static-threshold fallback in that case;
# rules that don't use behavioral baselines (brute_force, impossible_travel,
# data_exfiltration, privilege_escalation) simply ignore the parameter.
DetectionRule = Callable[[ActorEventWindow, "BaselineSnapshot | None"], list[Finding]]


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
