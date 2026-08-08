"""Data exfiltration: a large single transfer/download to an unfamiliar destination, or
a large database export."""

from __future__ import annotations

from app.core.config import settings
from app.detections.base import ActorEventWindow, make_finding
from app.models.schemas import Finding, Severity

_TRANSFER_ACTIONS = frozenset({"data_transfer", "file_download"})


def _is_allowlisted(target: str | None) -> bool:
    if target is None:
        return False
    return target in settings.exfil_allowlisted_destinations


def evaluate(window: ActorEventWindow) -> list[Finding]:
    findings: list[Finding] = []

    large_transfers = [
        e
        for e in window.events
        if e.action in _TRANSFER_ACTIONS
        and (e.bytes or 0) > settings.exfil_large_transfer_bytes
        and not _is_allowlisted(e.target)
    ]
    if large_transfers:
        total_bytes = sum(e.bytes or 0 for e in large_transfers)
        severity = Severity.HIGH if len(large_transfers) > 1 else Severity.MEDIUM
        points = min(60, 30 + 10 * (len(large_transfers) - 1))
        findings.append(
            make_finding(
                id="DATA_EXFIL_LARGE_TRANSFER",
                category="exfiltration",
                title="Large transfer to an unfamiliar destination",
                description=(
                    f"'{window.actor}' transferred {total_bytes:,} bytes across "
                    f"{len(large_transfers)} transfer(s) to destination(s) not on the "
                    f"known-good allowlist."
                ),
                severity=severity,
                points=points,
                evidence_event_ids=[e.id for e in large_transfers if e.id is not None],
            )
        )

    large_exports = [
        e
        for e in window.events
        if e.action == "db_query" and (e.bytes or 0) > settings.exfil_large_db_export_bytes
    ]
    if large_exports:
        total_bytes = sum(e.bytes or 0 for e in large_exports)
        severity = Severity.HIGH if len(large_exports) > 1 else Severity.MEDIUM
        points = min(60, 35 + 10 * (len(large_exports) - 1))
        findings.append(
            make_finding(
                id="DATA_EXFIL_LARGE_DB_EXPORT",
                category="exfiltration",
                title="Large database export",
                description=(
                    f"'{window.actor}' ran {len(large_exports)} database quer(y/ies) "
                    f"returning {total_bytes:,} bytes total."
                ),
                severity=severity,
                points=points,
                evidence_event_ids=[e.id for e in large_exports if e.id is not None],
            )
        )

    return findings
