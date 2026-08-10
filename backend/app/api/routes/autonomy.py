"""Autonomy policy management, the kill switch, the audit log, and undo (M6 Stage 1).

Defensive containment only. Nothing in this module executes an action directly — that only
ever happens inside app.autonomy.executor.execute_if_authorized, itself only reachable from
the playbook-fetch wiring in app.api.routes.remediation, and only ever through
app.autonomy.executor.MockConnector in this stage. This module is the read/manage surface:
inspect and configure the policy, halt everything, browse what happened and why, and undo a
reversible action. Requires auth; scoped to the authenticated user's account (M8 Stage 2) —
policy view/actions/reverse are available to any account member, but changing the policy or
pulling the kill switch is admin-only and audit-logged.
"""

from __future__ import annotations

from datetime import datetime, timezone
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from sqlalchemy.orm import Session

from app.auth.audit_log import log_event
from app.auth.dependencies import get_current_user, require_admin
from app.autonomy.executor import MockConnector, reverse_action
from app.autonomy.store import get_or_create_policy_row
from app.db.models import AutonomyAction, AutonomyPolicy, User
from app.db.session import get_db
from app.models.schemas import (
    AutonomyActionListResponse,
    AutonomyActionResponse,
    AutonomyHaltResponse,
    AutonomyPolicyRequest,
    AutonomyPolicyResponse,
    AutonomyPolicyRuleSchema,
)

router = APIRouter(prefix="/api/autonomy", tags=["autonomy"])

# Stage 1 ships only MockConnector — see app.autonomy.executor. A single module-level
# instance is fine since it holds no state and performs no real I/O.
_connector = MockConnector()


def _client_ip(request: Request) -> str | None:
    return request.client.host if request.client else None


def _to_policy_response(row: AutonomyPolicy) -> AutonomyPolicyResponse:
    return AutonomyPolicyResponse(
        account_id=row.account_id,
        level=row.level,
        rules=[AutonomyPolicyRuleSchema(**rule) for rule in row.rules],
        exclusions=row.exclusions,
        blast_radius_limit=row.blast_radius_limit,
        blast_radius_window_minutes=row.blast_radius_window_minutes,
        halted_at=row.halted_at,
        updated_at=row.updated_at,
    )


@router.get("/policy", response_model=AutonomyPolicyResponse)
async def get_policy(
    db: Session = Depends(get_db), current_user: User = Depends(get_current_user)
) -> AutonomyPolicyResponse:
    row = get_or_create_policy_row(db, current_user.account_id)
    return _to_policy_response(row)


@router.put("/policy", response_model=AutonomyPolicyResponse)
async def put_policy(
    body: AutonomyPolicyRequest,
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_admin),
) -> AutonomyPolicyResponse:
    row = get_or_create_policy_row(db, current_user.account_id)

    row.level = body.level.value
    row.rules = [rule.model_dump(mode="json") for rule in body.rules]
    row.exclusions = body.exclusions
    row.blast_radius_limit = body.blast_radius_limit
    row.blast_radius_window_minutes = body.blast_radius_window_minutes

    log_event(
        db,
        event_type="autonomy_policy_updated",
        account_id=current_user.account_id,
        user_id=current_user.id,
        detail={"level": row.level},
        ip_address=_client_ip(request),
    )

    db.commit()
    db.refresh(row)
    return _to_policy_response(row)


@router.post("/halt", response_model=AutonomyHaltResponse)
async def halt(
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_admin),
) -> AutonomyHaltResponse:
    """The kill switch: drops the account to L0 and stops pending actions — every
    AutonomyAction row currently `status="pending_approval"` for this account is flipped to
    `status="halted"` so it no longer lingers as actionable."""
    row = get_or_create_policy_row(db, current_user.account_id)

    now = datetime.now(timezone.utc)
    row.level = "L0"
    row.halted_at = now

    halted_count = (
        db.query(AutonomyAction)
        .filter(
            AutonomyAction.account_id == current_user.account_id,
            AutonomyAction.status == "pending_approval",
        )
        .update({"status": "halted"}, synchronize_session=False)
    )

    log_event(
        db,
        event_type="autonomy_halted",
        account_id=current_user.account_id,
        user_id=current_user.id,
        detail={"halted_pending_count": halted_count},
        ip_address=_client_ip(request),
    )

    db.commit()
    db.refresh(row)

    return AutonomyHaltResponse(
        account_id=current_user.account_id,
        level=row.level,
        halted_at=row.halted_at,
        halted_pending_count=halted_count,
    )


@router.get("/actions", response_model=AutonomyActionListResponse)
async def list_actions(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    case_id: UUID | None = None,
    incident_id: UUID | None = None,
    action_type: str | None = None,
    decision: str | None = None,
    status: str | None = None,
    date_from: datetime | None = None,
    date_to: datetime | None = None,
) -> AutonomyActionListResponse:
    """The filterable audit log — this doubles as the compliance-evidence export; every
    decision (auto_execute, require_approval, AND skip) is a row here, not just executed
    ones."""
    query = db.query(AutonomyAction).filter(AutonomyAction.account_id == current_user.account_id)

    if case_id is not None:
        query = query.filter(AutonomyAction.case_id == case_id)
    if incident_id is not None:
        query = query.filter(AutonomyAction.incident_id == incident_id)
    if action_type is not None:
        query = query.filter(AutonomyAction.action_type == action_type)
    if decision is not None:
        query = query.filter(AutonomyAction.decision == decision)
    if status is not None:
        query = query.filter(AutonomyAction.status == status)
    if date_from is not None:
        query = query.filter(AutonomyAction.created_at >= date_from)
    if date_to is not None:
        query = query.filter(AutonomyAction.created_at <= date_to)

    total = query.count()
    rows = (
        query.order_by(AutonomyAction.created_at.desc())
        .offset((page - 1) * page_size)
        .limit(page_size)
        .all()
    )

    return AutonomyActionListResponse(
        items=[AutonomyActionResponse.model_validate(row) for row in rows],
        total=total,
        page=page,
        page_size=page_size,
    )


@router.post("/actions/{action_id}/reverse", response_model=AutonomyActionResponse)
async def reverse(
    action_id: UUID,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> AutonomyActionResponse:
    row = db.get(AutonomyAction, action_id)
    if row is None or row.account_id != current_user.account_id:
        raise HTTPException(status_code=404, detail="Action not found.")

    try:
        row = reverse_action(db, _connector, row)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    db.commit()
    db.refresh(row)
    return AutonomyActionResponse.model_validate(row)
