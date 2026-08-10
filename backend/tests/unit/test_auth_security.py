from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone

import jwt
import pytest

from app.auth.security import (
    create_access_token,
    decode_access_token,
    generate_opaque_token,
    hash_password,
    hash_token,
    verify_password,
)
from app.core.config import settings


def test_hash_password_round_trips_via_verify():
    password = "correct horse battery staple"
    hashed = hash_password(password)
    assert hashed != password
    assert hashed.startswith("$argon2id$")
    assert verify_password(password, hashed) is True


def test_verify_password_rejects_wrong_password():
    hashed = hash_password("the-real-password")
    assert verify_password("not-the-real-password", hashed) is False


def test_verify_password_rejects_garbage_hash_without_raising():
    assert verify_password("anything", "not-a-real-argon2-hash") is False


def test_access_token_round_trips_to_the_same_user_id():
    user_id = uuid.uuid4()
    token = create_access_token(user_id)
    assert decode_access_token(token) == user_id


def test_expired_access_token_is_rejected():
    user_id = uuid.uuid4()
    now = datetime.now(timezone.utc)
    expired_payload = {
        "sub": str(user_id),
        "type": "access",
        "iat": now - timedelta(minutes=30),
        "exp": now - timedelta(minutes=15),
    }
    expired_token = jwt.encode(expired_payload, settings.jwt_secret_key, algorithm="HS256")

    with pytest.raises(jwt.PyJWTError):
        decode_access_token(expired_token)


def test_token_signed_with_a_different_secret_is_rejected():
    user_id = uuid.uuid4()
    now = datetime.now(timezone.utc)
    forged_payload = {
        "sub": str(user_id),
        "type": "access",
        "iat": now,
        "exp": now + timedelta(minutes=15),
    }
    forged_token = jwt.encode(forged_payload, "attacker-controlled-secret", algorithm="HS256")

    with pytest.raises(jwt.PyJWTError):
        decode_access_token(forged_token)


def test_a_token_that_is_not_an_access_token_is_rejected():
    # Same shape as create_access_token, but a different `type` claim — e.g. what a refresh
    # token would look like if it were (incorrectly) a JWT. decode_access_token must reject
    # anything that isn't explicitly an access token, even with a valid signature.
    user_id = uuid.uuid4()
    now = datetime.now(timezone.utc)
    payload = {
        "sub": str(user_id),
        "type": "refresh",
        "iat": now,
        "exp": now + timedelta(minutes=15),
    }
    token = jwt.encode(payload, settings.jwt_secret_key, algorithm="HS256")

    with pytest.raises(jwt.PyJWTError):
        decode_access_token(token)


def test_generate_opaque_token_produces_unique_high_entropy_values():
    a = generate_opaque_token()
    b = generate_opaque_token()
    assert a != b
    assert len(a) >= 32


def test_hash_token_is_deterministic_and_never_equals_the_raw_token():
    token = generate_opaque_token()
    first = hash_token(token)
    second = hash_token(token)
    assert first == second
    assert first != token
