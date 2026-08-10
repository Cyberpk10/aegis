from __future__ import annotations

import uuid

import pytest
from fastapi import HTTPException

from app.auth.dependencies import get_current_user, require_admin
from app.auth.security import create_access_token, generate_inbound_token, hash_password
from app.db.models import Account, User


def _make_user(db_session, *, role="analyst", is_active=True) -> User:
    account = Account(id=uuid.uuid4(), name="Test Account", inbound_token=generate_inbound_token())
    db_session.add(account)
    db_session.flush()
    user = User(
        id=uuid.uuid4(),
        account_id=account.id,
        email=f"{uuid.uuid4()}@example.com",
        password_hash=hash_password("Str0ngPassw0rd!"),
        role=role,
        is_active=is_active,
    )
    db_session.add(user)
    db_session.commit()
    db_session.refresh(user)
    return user


def test_get_current_user_returns_the_user_for_a_valid_token(db_session):
    user = _make_user(db_session)
    token = create_access_token(user.id)

    result = get_current_user(authorization=f"Bearer {token}", db=db_session)

    assert result.id == user.id


def test_get_current_user_rejects_missing_authorization_header(db_session):
    with pytest.raises(HTTPException) as exc_info:
        get_current_user(authorization=None, db=db_session)
    assert exc_info.value.status_code == 401


def test_get_current_user_rejects_a_header_without_the_bearer_prefix(db_session):
    user = _make_user(db_session)
    token = create_access_token(user.id)

    with pytest.raises(HTTPException) as exc_info:
        get_current_user(authorization=token, db=db_session)
    assert exc_info.value.status_code == 401


def test_get_current_user_rejects_a_malformed_token(db_session):
    with pytest.raises(HTTPException) as exc_info:
        get_current_user(authorization="Bearer not-a-real-jwt", db=db_session)
    assert exc_info.value.status_code == 401


def test_get_current_user_rejects_a_token_for_a_deleted_user(db_session):
    token = create_access_token(uuid.uuid4())  # no matching row in the DB

    with pytest.raises(HTTPException) as exc_info:
        get_current_user(authorization=f"Bearer {token}", db=db_session)
    assert exc_info.value.status_code == 401


def test_get_current_user_rejects_a_deactivated_user(db_session):
    user = _make_user(db_session, is_active=False)
    token = create_access_token(user.id)

    with pytest.raises(HTTPException) as exc_info:
        get_current_user(authorization=f"Bearer {token}", db=db_session)
    assert exc_info.value.status_code == 401


def test_require_admin_allows_an_admin_user():
    admin = User(role="admin")
    assert require_admin(user=admin) is admin


def test_require_admin_rejects_an_analyst_user():
    analyst = User(role="analyst")
    with pytest.raises(HTTPException) as exc_info:
        require_admin(user=analyst)
    assert exc_info.value.status_code == 403
