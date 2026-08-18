"""Adversarial authentication-bypass and privilege-escalation tests, hitting real HTTP
routes with forged/tampered credentials the way an actual attacker would — complements the
already-thorough unit-level coverage in tests/unit/test_auth_dependencies.py and
test_auth_security.py (which call get_current_user/decode_access_token directly) by proving
the same holds true through the full FastAPI dependency-injection chain, and by sweeping
every admin-only route in one place instead of one-off tests scattered per router.

Written as part of an authorized internal security review (dev/local only, SQLite in-memory
per test — see tests/conftest.py). No production system is touched by anything here.
"""

from __future__ import annotations

import base64
import json
import uuid

import jwt
import pytest

from app.auth.security import create_access_token
from app.core.config import settings
from app.db.models import Case, Incident

# A representative slice of protected routes across every resource family — not
# exhaustive, but enough to catch a route that forgot Depends(get_current_user) entirely.
PROTECTED_ROUTES = [
    ("GET", "/api/cases"),
    ("GET", "/api/incidents"),
    ("GET", "/api/auth/me"),
    ("GET", "/api/auth/users"),
    ("GET", "/api/autonomy/policy"),
    ("GET", "/api/autonomy/actions"),
    ("GET", "/api/labels/export"),
    ("GET", "/api/dashboard/summary"),
    ("GET", "/api/risk/financial"),
    ("GET", "/api/monitoring/controls"),
]


def _b64url(obj: dict) -> str:
    raw = json.dumps(obj, separators=(",", ":")).encode()
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


@pytest.mark.parametrize("method,path", PROTECTED_ROUTES)
def test_no_credentials_rejected(client, method, path):
    response = client.request(method, path)
    assert response.status_code == 401


@pytest.mark.parametrize("method,path", PROTECTED_ROUTES)
def test_garbage_bearer_token_rejected(client, method, path):
    response = client.request(method, path, headers={"Authorization": "Bearer not-a-real-jwt"})
    assert response.status_code == 401


def test_tampered_signature_rejected_end_to_end(client, test_account):
    token = create_access_token(test_account.user.id)
    # Flip the last few characters of the signature segment — a corrupted-in-transit or
    # bit-flipped-by-an-attacker token must never be accepted.
    header, payload, signature = token.split(".")
    tampered_signature = ("A" if signature[-1] != "A" else "B") + signature[1:]
    tampered = f"{header}.{payload}.{tampered_signature}"

    response = client.get("/api/cases", headers={"Authorization": f"Bearer {tampered}"})
    assert response.status_code == 401


def test_token_forged_with_a_guessed_secret_rejected(client, test_account):
    forged = jwt.encode(
        {"sub": str(test_account.user.id), "type": "access"},
        "attacker-guessed-secret-value",
        algorithm="HS256",
    )
    response = client.get("/api/cases", headers={"Authorization": f"Bearer {forged}"})
    assert response.status_code == 401


def test_alg_none_confusion_attack_rejected(client, test_account):
    """Classic JWT 'alg=none' attack: an attacker who can control the header claims a token
    is unsigned and omits the signature entirely, hoping a permissive verifier accepts it
    without checking a MAC at all. app.auth.security.decode_access_token pins
    algorithms=["HS256"] explicitly, so this must be rejected outright."""
    header = _b64url({"alg": "none", "typ": "JWT"})
    payload = _b64url({"sub": str(test_account.user.id), "type": "access"})
    forged = f"{header}.{payload}."

    response = client.get("/api/cases", headers={"Authorization": f"Bearer {forged}"})
    assert response.status_code == 401


def test_expired_token_rejected_end_to_end(client, test_account):
    import time

    forged = jwt.encode(
        {"sub": str(test_account.user.id), "type": "access", "exp": int(time.time()) - 60},
        settings.jwt_secret_key,
        algorithm="HS256",
    )
    response = client.get("/api/cases", headers={"Authorization": f"Bearer {forged}"})
    assert response.status_code == 401


def test_token_for_nonexistent_user_rejected(client):
    forged = jwt.encode(
        {"sub": str(uuid.uuid4()), "type": "access"}, settings.jwt_secret_key, algorithm="HS256"
    )
    response = client.get("/api/cases", headers={"Authorization": f"Bearer {forged}"})
    assert response.status_code == 401


def test_refresh_token_cannot_be_used_as_an_access_token(client, test_account):
    """A refresh token is a high-entropy opaque string, not a JWT — but confirm the actual
    live login response's refresh_token value is rejected by every protected route if an
    attacker who stole it tries to replay it directly as a Bearer access token."""
    login = client.post(
        "/api/auth/signup",
        json={
            "account_name": "Refresh Confusion Co",
            "email": "refresh-confuse@example.com",
            "password": "Str0ngTestPassw0rd!",
        },
    )
    refresh_token = login.json()["refresh_token"]

    response = client.get("/api/cases", headers={"Authorization": f"Bearer {refresh_token}"})
    assert response.status_code == 401


def test_jwt_typed_as_refresh_cannot_authenticate_a_protected_route(client, test_account):
    """A JWT with the right signature/subject but the wrong `type` claim (e.g. an attacker
    who found a way to mint a 'refresh'-typed JWT) must not authenticate anything — only
    type == 'access' is accepted (app.auth.security.decode_access_token)."""
    forged = jwt.encode(
        {"sub": str(test_account.user.id), "type": "refresh"},
        settings.jwt_secret_key,
        algorithm="HS256",
    )
    response = client.get("/api/cases", headers={"Authorization": f"Bearer {forged}"})
    assert response.status_code == 401


# --- Privilege escalation: analyst hitting admin-only actions -----------------------------


def _seed_case(db_session, account_id) -> uuid.UUID:
    case = Case(
        id=uuid.uuid4(),
        account_id=account_id,
        filename="t.eml",
        verdict="malicious",
        score=90,
        from_addr="a@example.com",
        subject="s",
        indicators=[],
        framework_mappings={},
    )
    db_session.add(case)
    db_session.commit()
    return case.id


def _seed_incident(db_session, account_id) -> uuid.UUID:
    from datetime import datetime, timezone

    incident = Incident(
        id=uuid.uuid4(),
        account_id=account_id,
        title="t",
        actor="alice@corp.com",
        verdict="malicious",
        score=90,
        detection_types=["BRUTE_FORCE_PASSWORD_SPRAY"],
        findings=[],
        framework_mappings={},
        window_start=datetime(2026, 1, 1, tzinfo=timezone.utc),
        window_end=datetime(2026, 1, 1, 1, tzinfo=timezone.utc),
    )
    db_session.add(incident)
    db_session.commit()
    return incident.id


def test_analyst_cannot_delete_a_case(analyst_authed_client, db_session, test_account):
    case_id = _seed_case(db_session, test_account.account.id)
    response = analyst_authed_client.delete(f"/api/cases/{case_id}")
    assert response.status_code == 403


def test_analyst_cannot_delete_an_incident(analyst_authed_client, db_session, test_account):
    incident_id = _seed_incident(db_session, test_account.account.id)
    response = analyst_authed_client.delete(f"/api/incidents/{incident_id}")
    assert response.status_code == 403


def test_analyst_cannot_delete_a_user(analyst_authed_client, db_session, test_account):
    from app.auth.security import generate_inbound_token, hash_password
    from app.db.models import User

    victim = User(
        id=uuid.uuid4(),
        account_id=test_account.account.id,
        email="victim@example.com",
        password_hash=hash_password("Str0ngTestPassw0rd!"),
        role="analyst",
    )
    db_session.add(victim)
    db_session.commit()

    response = analyst_authed_client.delete(f"/api/auth/users/{victim.id}")
    assert response.status_code == 403


@pytest.mark.parametrize(
    "method,path,body",
    [
        ("PUT", "/api/autonomy/policy", {"level": "L3", "rules": [], "exclusions": [], "blast_radius_limit": 10, "blast_radius_window_minutes": 60}),
        ("POST", "/api/autonomy/halt", None),
        ("PUT", "/api/autonomy/graph-integration", {"tenant_id": "attacker-tenant"}),
        ("POST", "/api/auth/invite", {"email": "new@example.com", "role": "admin"}),
    ],
)
def test_analyst_cannot_perform_admin_only_actions(analyst_authed_client, method, path, body):
    response = analyst_authed_client.request(method, path, json=body)
    assert response.status_code == 403, f"{method} {path} should 403 for a non-admin, got {response.status_code}"
