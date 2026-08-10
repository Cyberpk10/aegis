"""Password hashing, JWT access tokens, and opaque (refresh/reset/invite) tokens (M8 Stage 2).

Password hashing uses Argon2id (`argon2-cffi`), OWASP's current #1 recommendation for password
storage (ahead of bcrypt) — verified against the live OWASP Password Storage Cheat Sheet.

Access tokens are short-lived, stateless JWTs carrying only a user id + expiry — every other
fact about the user (account_id, role, is_active) is loaded fresh from the DB on every request
(see app.auth.dependencies.get_current_user), so a role change or account deactivation takes
effect immediately rather than waiting out the token's TTL.

Refresh/password-reset/invite tokens are opaque random strings, never JWTs — only their SHA-256
hash is ever persisted (same principle as password storage: a DB leak shouldn't hand out live
tokens). SHA-256 (not Argon2) is correct here — these are already high-entropy random values, not
low-entropy human-chosen secrets, so a fast deterministic hash for O(1) lookup-by-hash is the
right tool, not a slow, salted password KDF.
"""

from __future__ import annotations

import hashlib
import secrets
import uuid
from datetime import datetime, timedelta, timezone

import jwt
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError, InvalidHashError

from app.core.config import settings

_password_hasher = PasswordHasher()

_JWT_ALGORITHM = "HS256"
_ACCESS_TOKEN_TYPE = "access"


def hash_password(password: str) -> str:
    return _password_hasher.hash(password)


def verify_password(password: str, password_hash: str) -> bool:
    try:
        return _password_hasher.verify(password_hash, password)
    except (VerifyMismatchError, InvalidHashError, ValueError):
        return False


def create_access_token(user_id: uuid.UUID) -> str:
    now = datetime.now(timezone.utc)
    payload = {
        "sub": str(user_id),
        "type": _ACCESS_TOKEN_TYPE,
        "iat": now,
        "exp": now + timedelta(minutes=settings.jwt_access_token_ttl_minutes),
    }
    return jwt.encode(payload, settings.jwt_secret_key, algorithm=_JWT_ALGORITHM)


def decode_access_token(token: str) -> uuid.UUID:
    """Returns the user id encoded in a valid, unexpired access token. Raises
    `jwt.PyJWTError` (caught by the caller — see app.auth.dependencies) on anything wrong:
    expired, malformed, wrong signature, or not actually an access token."""
    payload = jwt.decode(token, settings.jwt_secret_key, algorithms=[_JWT_ALGORITHM])
    if payload.get("type") != _ACCESS_TOKEN_TYPE:
        raise jwt.InvalidTokenError("Not an access token")
    return uuid.UUID(payload["sub"])


def generate_opaque_token() -> str:
    """A high-entropy random token for refresh/password-reset/invite links — the raw value
    is returned to the caller exactly once and never stored; only `hash_token()` of it is."""
    return secrets.token_urlsafe(32)


def hash_token(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def refresh_token_expiry() -> datetime:
    # Naive UTC, not aware — this value is stored in a DB DateTime(timezone=True) column
    # and later compared against datetime.utcnow() in route code. SQLite (used by the test
    # suite) silently strips tzinfo on round-trip, so mixing naive/aware here would raise
    # TypeError on comparison — same reasoning as every other DB-persisted timestamp
    # comparison in this codebase (see app.api.routes.dashboard/risk/monitoring).
    return datetime.utcnow() + timedelta(days=settings.jwt_refresh_token_ttl_days)
