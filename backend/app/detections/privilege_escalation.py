"""Privilege escalation: any privilege_change event, with severity bumped when it's
chained after other suspicious activity (auth failures) from the same actor."""

from __future__ import annotations

from app.baselines.aggregation import BaselineSnapshot
from app.detections.base import ActorEventWindow, make_finding
from app.models.schemas import Finding, Severity


def evaluate(window: ActorEventWindow, baseline: BaselineSnapshot | None = None) -> list[Finding]:
    # Doesn't use behavioral baselines — any privilege change is worth surfacing regardless
    # of the actor's history. Accepts the parameter only for a uniform engine signature.
    priv_changes = [e for e in window.events if e.action == "privilege_change"]
    if not priv_changes:
        return []

    first_change_ts = min(e.timestamp for e in priv_changes)
    preceding_auth_fails = [
        e for e in window.events if e.action == "auth_fail" and e.timestamp < first_change_ts
    ]

    chained = bool(preceding_auth_fails)
    severity = Severity.HIGH if chained else Severity.MEDIUM
    points = 40 if chained else 25

    description = f"{len(priv_changes)} privilege change(s) for '{window.actor}'."
    if chained:
        description += (
            f" Preceded by {len(preceding_auth_fails)} failed authentication attempt(s) "
            "in the same window — possible compromised-account escalation."
        )

    evidence_events = priv_changes + (preceding_auth_fails if chained else [])

    return [
        make_finding(
            id="PRIVILEGE_ESCALATION",
            category="access",
            title="Privilege escalation",
            description=description,
            severity=severity,
            points=points,
            evidence_event_ids=[e.id for e in evidence_events if e.id is not None],
        )
    ]
