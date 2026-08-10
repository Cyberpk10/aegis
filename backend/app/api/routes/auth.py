"""Authentication and account management (M8 Stage 2) — prefix /api/auth.

Defensive-product security posture: Argon2id password hashing, short-lived JWT access
tokens + rotating server-side-revocable refresh tokens (app.auth.security), rate limiting
on every credential-adjacent endpoint (app.auth.rate_limit), and an audit log entry for
every login and privileged action (app.auth.audit_log). Passwords are never logged —
no request body or field containing one is ever passed to a log call anywhere here.
"""

from __future__ import annotations

from datetime import datetime, timedelta
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy.orm import Session

from app.auth.audit_log import log_event
from app.auth.dependencies import get_current_user, require_admin
from app.auth.rate_limit import AUTH_RATE_LIMIT, limiter
from app.auth.security import (
    create_access_token,
    generate_inbound_token,
    generate_opaque_token,
    hash_password,
    hash_token,
    refresh_token_expiry,
    verify_password,
)
from app.core.config import settings
from app.db.models import Account, Invite, PasswordResetToken, RefreshToken, User
from app.db.session import get_db
from app.models.schemas import (
    InviteAcceptRequest,
    InviteRequest,
    InviteResponse,
    LoginRequest,
    LogoutRequest,
    PasswordResetConfirmRequest,
    PasswordResetRequestRequest,
    PasswordResetRequestResponse,
    RefreshRequest,
    SignupRequest,
    TokenResponse,
    UserListResponse,
    UserResponse,
    UserRoleUpdateRequest,
)

router = APIRouter(prefix="/api/auth", tags=["auth"])

_PASSWORD_RESET_TTL = timedelta(hours=1)
_INVITE_TTL = timedelta(days=7)
_GENERIC_LOGIN_ERROR = "Invalid email or password."


def _client_ip(request: Request) -> str | None:
    return request.client.host if request.client else None


def _forwarding_address(account: Account) -> str:
    return f"pilot-{account.inbound_token}@{settings.inbound_email_domain}"


def _to_user_response(user: User, account: Account) -> UserResponse:
    return UserResponse(
        id=user.id,
        email=user.email,
        role=user.role,
        account_id=user.account_id,
        account_name=account.name,
        forwarding_address=_forwarding_address(account),
        is_active=user.is_active,
        created_at=user.created_at,
        last_login_at=user.last_login_at,
    )


def _issue_tokens(db: Session, user: User, account: Account) -> tuple[TokenResponse, RefreshToken]:
    access_token = create_access_token(user.id)
    raw_refresh = generate_opaque_token()
    refresh_row = RefreshToken(
        user_id=user.id,
        token_hash=hash_token(raw_refresh),
        expires_at=refresh_token_expiry(),
    )
    db.add(refresh_row)
    db.flush()
    response = TokenResponse(
        access_token=access_token,
        refresh_token=raw_refresh,
        user=_to_user_response(user, account),
    )
    return response, refresh_row


def _revoke_all_refresh_tokens(db: Session, user_id: UUID) -> None:
    db.query(RefreshToken).filter(
        RefreshToken.user_id == user_id, RefreshToken.revoked_at.is_(None)
    ).update({"revoked_at": datetime.utcnow()}, synchronize_session=False)


@router.post("/signup", response_model=TokenResponse)
@limiter.limit(AUTH_RATE_LIMIT)
async def signup(request: Request, body: SignupRequest, db: Session = Depends(get_db)) -> TokenResponse:
    email = body.email.strip().lower()
    if db.query(User).filter(User.email == email).first() is not None:
        raise HTTPException(status_code=409, detail="An account with this email already exists.")

    account = Account(name=body.account_name.strip(), inbound_token=generate_inbound_token())
    db.add(account)
    db.flush()

    user = User(
        account_id=account.id,
        email=email,
        password_hash=hash_password(body.password),
        role="admin",
    )
    db.add(user)
    db.flush()

    log_event(
        db,
        event_type="account_created",
        account_id=account.id,
        user_id=user.id,
        ip_address=_client_ip(request),
    )
    response, _ = _issue_tokens(db, user, account)
    db.commit()
    return response


@router.post("/login", response_model=TokenResponse)
@limiter.limit(AUTH_RATE_LIMIT)
async def login(request: Request, body: LoginRequest, db: Session = Depends(get_db)) -> TokenResponse:
    email = body.email.strip().lower()
    ip = _client_ip(request)
    user = db.query(User).filter(User.email == email).first()

    if user is None or not user.is_active or not verify_password(body.password, user.password_hash):
        log_event(
            db,
            event_type="login_failure",
            account_id=user.account_id if user else None,
            user_id=user.id if user else None,
            detail=None if user else {"email": email},
            ip_address=ip,
        )
        db.commit()
        raise HTTPException(status_code=401, detail=_GENERIC_LOGIN_ERROR)

    account = db.get(Account, user.account_id)
    user.last_login_at = datetime.utcnow()
    log_event(
        db, event_type="login_success", account_id=user.account_id, user_id=user.id, ip_address=ip
    )
    response, _ = _issue_tokens(db, user, account)
    db.commit()
    return response


@router.post("/logout", status_code=204)
async def logout(body: LogoutRequest, db: Session = Depends(get_db)) -> None:
    row = db.query(RefreshToken).filter(RefreshToken.token_hash == hash_token(body.refresh_token)).first()
    if row is not None and row.revoked_at is None:
        row.revoked_at = datetime.utcnow()
        user = db.get(User, row.user_id)
        log_event(
            db,
            event_type="logout",
            account_id=user.account_id if user else None,
            user_id=row.user_id,
        )
    db.commit()


@router.post("/refresh", response_model=TokenResponse)
async def refresh(body: RefreshRequest, db: Session = Depends(get_db)) -> TokenResponse:
    row = db.query(RefreshToken).filter(RefreshToken.token_hash == hash_token(body.refresh_token)).first()
    if row is None:
        raise HTTPException(status_code=401, detail="Invalid refresh token.")

    if row.revoked_at is not None:
        # Reuse of an already-rotated/revoked token — treat as theft: revoke the whole
        # chain so a stolen token can't be replayed even once more.
        _revoke_all_refresh_tokens(db, row.user_id)
        log_event(db, event_type="refresh_token_reuse_detected", user_id=row.user_id)
        db.commit()
        raise HTTPException(status_code=401, detail="Invalid refresh token.")

    if row.expires_at < datetime.utcnow():
        raise HTTPException(status_code=401, detail="Refresh token expired.")

    user = db.get(User, row.user_id)
    if user is None or not user.is_active:
        raise HTTPException(status_code=401, detail="Invalid refresh token.")
    account = db.get(Account, user.account_id)

    row.revoked_at = datetime.utcnow()
    response, new_row = _issue_tokens(db, user, account)
    row.replaced_by_id = new_row.id
    db.commit()
    return response


@router.get("/me", response_model=UserResponse)
async def me(current_user: User = Depends(get_current_user), db: Session = Depends(get_db)) -> UserResponse:
    account = db.get(Account, current_user.account_id)
    return _to_user_response(current_user, account)


@router.post("/invite", response_model=InviteResponse)
@limiter.limit(AUTH_RATE_LIMIT)
async def invite(
    request: Request,
    body: InviteRequest,
    current_user: User = Depends(require_admin),
    db: Session = Depends(get_db),
) -> InviteResponse:
    email = body.email.strip().lower()
    if db.query(User).filter(User.email == email).first() is not None:
        raise HTTPException(status_code=409, detail="A user with this email already exists.")

    raw_token = generate_opaque_token()
    invite_row = Invite(
        account_id=current_user.account_id,
        email=email,
        role=body.role.value,
        token_hash=hash_token(raw_token),
        invited_by_user_id=current_user.id,
        expires_at=datetime.utcnow() + _INVITE_TTL,
    )
    db.add(invite_row)
    db.flush()

    log_event(
        db,
        event_type="invite_sent",
        account_id=current_user.account_id,
        user_id=current_user.id,
        detail={"invited_email": email, "role": body.role.value},
        ip_address=_client_ip(request),
    )
    db.commit()

    return InviteResponse(
        id=invite_row.id,
        email=invite_row.email,
        role=invite_row.role,
        expires_at=invite_row.expires_at,
        # Stubbed email delivery (M8 Stage 2) — see app/db/models.py::Invite.
        invite_link=f"/accept-invite?token={raw_token}",
    )


@router.post("/invite/accept", response_model=TokenResponse)
@limiter.limit(AUTH_RATE_LIMIT)
async def accept_invite(
    request: Request, body: InviteAcceptRequest, db: Session = Depends(get_db)
) -> TokenResponse:
    invite_row = db.query(Invite).filter(Invite.token_hash == hash_token(body.token)).first()
    if invite_row is None or invite_row.accepted_at is not None or invite_row.expires_at < datetime.utcnow():
        raise HTTPException(status_code=400, detail="This invite is invalid or has expired.")

    if db.query(User).filter(User.email == invite_row.email).first() is not None:
        raise HTTPException(status_code=409, detail="A user with this email already exists.")

    user = User(
        account_id=invite_row.account_id,
        email=invite_row.email,
        password_hash=hash_password(body.password),
        role=invite_row.role,
    )
    db.add(user)
    db.flush()
    invite_row.accepted_at = datetime.utcnow()

    account = db.get(Account, invite_row.account_id)
    log_event(
        db,
        event_type="invite_accepted",
        account_id=invite_row.account_id,
        user_id=user.id,
        ip_address=_client_ip(request),
    )
    response, _ = _issue_tokens(db, user, account)
    db.commit()
    return response


@router.post("/password-reset/request", response_model=PasswordResetRequestResponse)
@limiter.limit(AUTH_RATE_LIMIT)
async def request_password_reset(
    request: Request, body: PasswordResetRequestRequest, db: Session = Depends(get_db)
) -> PasswordResetRequestResponse:
    email = body.email.strip().lower()
    user = db.query(User).filter(User.email == email).first()

    # Always the same generic response regardless of whether the email exists —
    # otherwise this endpoint becomes a user-enumeration oracle.
    generic = PasswordResetRequestResponse(
        message="If that email is registered, a password reset link has been generated."
    )
    if user is None or not user.is_active:
        return generic

    raw_token = generate_opaque_token()
    db.add(
        PasswordResetToken(
            user_id=user.id,
            token_hash=hash_token(raw_token),
            expires_at=datetime.utcnow() + _PASSWORD_RESET_TTL,
        )
    )
    log_event(
        db,
        event_type="password_reset_requested",
        account_id=user.account_id,
        user_id=user.id,
        ip_address=_client_ip(request),
    )
    db.commit()

    # Stubbed email delivery (M8 Stage 2) — see app/db/models.py::PasswordResetToken.
    generic.reset_link = f"/reset-password?token={raw_token}"
    return generic


@router.post("/password-reset/confirm", status_code=204)
async def confirm_password_reset(body: PasswordResetConfirmRequest, db: Session = Depends(get_db)) -> None:
    token_row = (
        db.query(PasswordResetToken)
        .filter(PasswordResetToken.token_hash == hash_token(body.token))
        .first()
    )
    if token_row is None or token_row.used_at is not None or token_row.expires_at < datetime.utcnow():
        raise HTTPException(status_code=400, detail="This reset link is invalid or has expired.")

    user = db.get(User, token_row.user_id)
    if user is None:
        raise HTTPException(status_code=400, detail="This reset link is invalid or has expired.")

    user.password_hash = hash_password(body.new_password)
    token_row.used_at = datetime.utcnow()
    # Force re-login everywhere — a password reset should invalidate every existing session.
    _revoke_all_refresh_tokens(db, user.id)
    log_event(db, event_type="password_reset_completed", account_id=user.account_id, user_id=user.id)
    db.commit()


@router.get("/users", response_model=UserListResponse)
async def list_users(
    current_user: User = Depends(get_current_user), db: Session = Depends(get_db)
) -> UserListResponse:
    account = db.get(Account, current_user.account_id)
    rows = db.query(User).filter(User.account_id == current_user.account_id).order_by(User.created_at).all()
    return UserListResponse(items=[_to_user_response(u, account) for u in rows])


@router.patch("/users/{user_id}", response_model=UserResponse)
async def update_user_role(
    user_id: UUID,
    body: UserRoleUpdateRequest,
    current_user: User = Depends(require_admin),
    db: Session = Depends(get_db),
) -> UserResponse:
    target = db.get(User, user_id)
    if target is None or target.account_id != current_user.account_id:
        raise HTTPException(status_code=404, detail="User not found.")

    target.role = body.role.value
    log_event(
        db,
        event_type="role_changed",
        account_id=current_user.account_id,
        user_id=current_user.id,
        detail={"target_user_id": str(user_id), "new_role": body.role.value},
    )
    db.commit()
    db.refresh(target)
    account = db.get(Account, current_user.account_id)
    return _to_user_response(target, account)


@router.delete("/users/{user_id}", status_code=204)
async def delete_user(
    user_id: UUID,
    current_user: User = Depends(require_admin),
    db: Session = Depends(get_db),
) -> None:
    if user_id == current_user.id:
        raise HTTPException(status_code=400, detail="You cannot remove your own account.")

    target = db.get(User, user_id)
    if target is None or target.account_id != current_user.account_id:
        raise HTTPException(status_code=404, detail="User not found.")

    log_event(
        db,
        event_type="user_removed",
        account_id=current_user.account_id,
        user_id=current_user.id,
        detail={"target_user_id": str(user_id)},
    )
    db.delete(target)
    db.commit()
