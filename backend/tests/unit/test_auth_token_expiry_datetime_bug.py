"""Regression tests for the same naive/aware datetime bug class fixed in dashboard.py and
monitoring.py (see 42a9cd4, "Fix dashboard crash: naive/aware datetime mismatch on
Postgres"): RefreshToken/Invite/PasswordResetToken.expires_at are all
`DateTime(timezone=True)` columns. Postgres (production) returns an aware datetime for
these on read; SQLite (the test suite's DB) silently strips tzinfo on round-trip (verified
empirically — see the security-review conversation this file came out of). Three routes in
app.api.routes.auth compare a freshly-DB-loaded `.expires_at` against a naive
`datetime.utcnow()` in plain Python, which raises
`TypeError: can't compare offset-naive and offset-aware datetimes` the moment `.expires_at`
is actually aware — i.e. on every single call in production. This is invisible to the
SQLite-backed integration suite (tests/integration/test_auth_endpoints.py's refresh/invite/
password-reset tests all pass today) because SQLite never hands back an aware value to
trigger it.

To reproduce the real production behavior without a live Postgres instance, a SQLAlchemy
`"load"` event handler forces tzinfo onto these three models' `expires_at` the instant they
come back from a fresh query — exactly what psycopg actually does for a
`DateTime(timezone=True)` column, and precisely how a brand-new per-request Session (as
app.db.session.get_db hands out) would see it.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy import event

from app.auth.security import generate_inbound_token, hash_password, hash_token
from app.db.models import Account, Invite, PasswordResetToken, RefreshToken, User


def _force_aware(target, _context) -> None:
    if target.expires_at is not None and target.expires_at.tzinfo is None:
        target.expires_at = target.expires_at.replace(tzinfo=timezone.utc)


@pytest.fixture(autouse=True)
def _simulate_postgres_aware_datetime_columns():
    """Registered/removed around every test in this file — makes RefreshToken/Invite/
    PasswordResetToken.expires_at come back timezone-aware on load, the way Postgres
    actually behaves, instead of SQLite's naive round-trip."""
    for model in (RefreshToken, Invite, PasswordResetToken):
        event.listen(model, "load", _force_aware)
    yield
    for model in (RefreshToken, Invite, PasswordResetToken):
        event.remove(model, "load", _force_aware)


def _make_account_and_user(db_session) -> User:
    account = Account(id=uuid.uuid4(), name="T", inbound_token=generate_inbound_token())
    db_session.add(account)
    db_session.flush()
    user = User(
        id=uuid.uuid4(),
        account_id=account.id,
        email="a@example.com",
        password_hash=hash_password("Str0ngTestPassw0rd!"),
        role="admin",
    )
    db_session.add(user)
    db_session.commit()
    db_session.refresh(user)
    return user


def test_refresh_token_expiry_check_survives_an_aware_expires_at(client, db_session):
    """Reproduces the production crash: a valid, unexpired RefreshToken whose expires_at
    comes back timezone-aware (as it always does on Postgres) must not blow up
    POST /api/auth/refresh with an unhandled TypeError/500 — it should simply succeed."""
    user = _make_account_and_user(db_session)
    raw_token = "a-raw-refresh-token"
    row = RefreshToken(
        user_id=user.id,
        token_hash=hash_token(raw_token),
        expires_at=datetime.utcnow() + timedelta(days=7),
    )
    db_session.add(row)
    db_session.commit()

    response = client.post("/api/auth/refresh", json={"refresh_token": raw_token})
    assert response.status_code == 200, response.text


def test_refresh_token_expiry_check_still_rejects_an_actually_expired_token(client, db_session):
    user = _make_account_and_user(db_session)
    raw_token = "an-expired-raw-refresh-token"
    row = RefreshToken(
        user_id=user.id,
        token_hash=hash_token(raw_token),
        expires_at=datetime.utcnow() - timedelta(days=1),
    )
    db_session.add(row)
    db_session.commit()

    response = client.post("/api/auth/refresh", json={"refresh_token": raw_token})
    assert response.status_code == 401
    assert "expired" in response.json()["detail"].lower()


def test_invite_accept_survives_an_aware_expires_at(client, db_session):
    user = _make_account_and_user(db_session)
    raw_token = "a-raw-invite-token"
    invite = Invite(
        account_id=user.account_id,
        email="new-hire@example.com",
        role="analyst",
        token_hash=hash_token(raw_token),
        invited_by_user_id=user.id,
        expires_at=datetime.utcnow() + timedelta(days=7),
    )
    db_session.add(invite)
    db_session.commit()

    response = client.post(
        "/api/auth/invite/accept",
        json={"token": raw_token, "password": "Str0ngTestPassw0rd!"},
    )
    assert response.status_code == 200, response.text


def test_invite_accept_still_rejects_an_actually_expired_invite(client, db_session):
    user = _make_account_and_user(db_session)
    raw_token = "an-expired-raw-invite-token"
    invite = Invite(
        account_id=user.account_id,
        email="new-hire@example.com",
        role="analyst",
        token_hash=hash_token(raw_token),
        invited_by_user_id=user.id,
        expires_at=datetime.utcnow() - timedelta(days=1),
    )
    db_session.add(invite)
    db_session.commit()

    response = client.post(
        "/api/auth/invite/accept",
        json={"token": raw_token, "password": "Str0ngTestPassw0rd!"},
    )
    assert response.status_code == 400


def test_password_reset_confirm_survives_an_aware_expires_at(client, db_session):
    user = _make_account_and_user(db_session)
    raw_token = "a-raw-reset-token"
    reset = PasswordResetToken(
        user_id=user.id,
        token_hash=hash_token(raw_token),
        expires_at=datetime.utcnow() + timedelta(hours=1),
    )
    db_session.add(reset)
    db_session.commit()

    response = client.post(
        "/api/auth/password-reset/confirm",
        json={"token": raw_token, "new_password": "AnotherStr0ngPassw0rd!"},
    )
    assert response.status_code == 204, response.text


def test_password_reset_confirm_still_rejects_an_actually_expired_token(client, db_session):
    user = _make_account_and_user(db_session)
    raw_token = "an-expired-raw-reset-token"
    reset = PasswordResetToken(
        user_id=user.id,
        token_hash=hash_token(raw_token),
        expires_at=datetime.utcnow() - timedelta(hours=1),
    )
    db_session.add(reset)
    db_session.commit()

    response = client.post(
        "/api/auth/password-reset/confirm",
        json={"token": raw_token, "new_password": "AnotherStr0ngPassw0rd!"},
    )
    assert response.status_code == 400
