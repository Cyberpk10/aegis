"""Registry + runner for detection rules — mirrors app.indicators.engine exactly."""

from __future__ import annotations

from app.detections import (
    brute_force,
    data_exfiltration,
    impossible_travel,
    mass_file_access,
    off_hours_access,
    privilege_escalation,
)
from app.detections.base import ActorEventWindow, DetectionRule
from app.models.schemas import Finding

_RULES: list[DetectionRule] = [
    brute_force.evaluate,
    impossible_travel.evaluate,
    off_hours_access.evaluate,
    mass_file_access.evaluate,
    data_exfiltration.evaluate,
    privilege_escalation.evaluate,
]


def run_detections(window: ActorEventWindow) -> list[Finding]:
    findings: list[Finding] = []
    for rule in _RULES:
        findings.extend(rule(window))
    return findings
