"""Thin DB-access helpers shared between app.api.routes.autonomy (the management surface)
and the playbook-fetch wiring in app.api.routes.remediation (the actual evaluation
trigger) — kept out of both route modules to avoid one importing internals from the other.
"""

from __future__ import annotations

import uuid

from sqlalchemy.orm import Session

from app.autonomy.policy import Policy, PolicyRule
from app.db.models import AutonomyPolicy


def get_or_create_policy_row(db: Session, account_id: uuid.UUID) -> AutonomyPolicy:
    row = db.query(AutonomyPolicy).filter(AutonomyPolicy.account_id == account_id).first()
    if row is not None:
        return row
    row = AutonomyPolicy(account_id=account_id)
    db.add(row)
    db.commit()
    db.refresh(row)
    return row


def to_policy_dataclass(row: AutonomyPolicy) -> Policy:
    """Converts the persisted row into the pure app.autonomy.policy.Policy the evaluation
    engine/executor actually consume — the DB row is the storage form, not the interface."""
    return Policy(
        account_id=row.account_id,
        level=row.level,
        rules=[PolicyRule(**rule) for rule in row.rules],
        exclusions=list(row.exclusions),
    )
