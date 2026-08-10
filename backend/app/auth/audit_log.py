"""Audit logging of logins and privileged actions (M8 Stage 2) — a distinct concept from
Audit Mode/AuditReport (detection-control coverage evidence for compliance frameworks); this is
"who did what to this account," append-only, never updated or deleted by the app itself.
"""

from __future__ import annotations

import uuid

from sqlalchemy.orm import Session

from app.db.models import AuditLogEntry


def log_event(
    db: Session,
    *,
    event_type: str,
    account_id: uuid.UUID | None = None,
    user_id: uuid.UUID | None = None,
    detail: dict | None = None,
    ip_address: str | None = None,
) -> None:
    """Adds the row to the current session — does not commit. Callers already commit as
    part of their own request handling; this just needs to be flushed in the same
    transaction as whatever it's recording, not as a separate round-trip."""
    db.add(
        AuditLogEntry(
            account_id=account_id,
            user_id=user_id,
            event_type=event_type,
            detail=detail,
            ip_address=ip_address,
        )
    )
