"""FastAPI auth dependencies (M8 Stage 2) — the two dependencies every route needs.

`get_current_user` is the only place that decodes a JWT; every route depends on it (directly
or via `require_admin`) rather than touching tokens itself. Deliberately reloads the User row
from the DB on every request instead of trusting claims embedded in the token, so a role change
or account deactivation takes effect immediately rather than waiting out the access token's TTL.
"""

from __future__ import annotations

import jwt
from fastapi import Depends, Header, HTTPException
from sqlalchemy.orm import Session

from app.auth.security import decode_access_token
from app.db.models import User
from app.db.session import get_db

_UNAUTHORIZED = HTTPException(status_code=401, detail="Not authenticated.")


def get_current_user(
    authorization: str | None = Header(default=None),
    db: Session = Depends(get_db),
) -> User:
    if not authorization or not authorization.lower().startswith("bearer "):
        raise _UNAUTHORIZED

    token = authorization.split(" ", 1)[1].strip()
    try:
        user_id = decode_access_token(token)
    except jwt.PyJWTError:
        raise _UNAUTHORIZED from None

    user = db.get(User, user_id)
    if user is None or not user.is_active:
        raise _UNAUTHORIZED
    return user


def require_admin(user: User = Depends(get_current_user)) -> User:
    if user.role != "admin":
        raise HTTPException(status_code=403, detail="This action requires an admin role.")
    return user
