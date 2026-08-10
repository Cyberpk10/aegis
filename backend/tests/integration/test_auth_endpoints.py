from __future__ import annotations

from app.db.models import RefreshToken

_STRONG_PASSWORD = "Str0ngPassw0rd!"


def _signup(client, *, email="admin@example.com", account_name="Acme Corp", password=_STRONG_PASSWORD):
    response = client.post(
        "/api/auth/signup",
        json={"account_name": account_name, "email": email, "password": password},
    )
    assert response.status_code == 200, response.text
    return response.json()


def _auth_headers(token_response: dict) -> dict:
    return {"Authorization": f"Bearer {token_response['access_token']}"}


# --- Signup / login -----------------------------------------------------------------


def test_signup_creates_account_and_returns_tokens(client):
    body = _signup(client)
    assert body["token_type"] == "bearer"
    assert body["access_token"]
    assert body["refresh_token"]
    assert body["user"]["email"] == "admin@example.com"
    assert body["user"]["role"] == "admin"
    assert body["user"]["account_name"] == "Acme Corp"


def test_signup_rejects_duplicate_email(client):
    _signup(client, email="dupe@example.com")
    response = client.post(
        "/api/auth/signup",
        json={"account_name": "Other Co", "email": "dupe@example.com", "password": _STRONG_PASSWORD},
    )
    assert response.status_code == 409


def test_signup_rejects_a_password_below_the_minimum_length(client):
    response = client.post(
        "/api/auth/signup",
        json={"account_name": "Acme Corp", "email": "short@example.com", "password": "tooshort"},
    )
    assert response.status_code == 422


def test_login_succeeds_with_correct_credentials(client):
    _signup(client, email="login@example.com")
    response = client.post(
        "/api/auth/login", json={"email": "login@example.com", "password": _STRONG_PASSWORD}
    )
    assert response.status_code == 200
    assert response.json()["user"]["email"] == "login@example.com"


def test_login_fails_with_wrong_password_and_does_not_leak_which_field_was_wrong(client):
    _signup(client, email="wrongpw@example.com")
    wrong_password_response = client.post(
        "/api/auth/login", json={"email": "wrongpw@example.com", "password": "TotallyWrongPassword!"}
    )
    unknown_email_response = client.post(
        "/api/auth/login", json={"email": "nobody-here@example.com", "password": _STRONG_PASSWORD}
    )
    assert wrong_password_response.status_code == 401
    assert unknown_email_response.status_code == 401
    assert wrong_password_response.json()["detail"] == unknown_email_response.json()["detail"]


def test_login_rate_limited_after_ten_attempts_per_minute(client):
    for _ in range(10):
        response = client.post(
            "/api/auth/login", json={"email": "nobody@example.com", "password": "whatever12345"}
        )
        assert response.status_code == 401

    eleventh = client.post(
        "/api/auth/login", json={"email": "nobody@example.com", "password": "whatever12345"}
    )
    assert eleventh.status_code == 429


# --- Refresh / logout -----------------------------------------------------------------


def test_refresh_rotates_the_token_and_the_old_one_is_then_rejected(client, db_session):
    tokens = _signup(client, email="rotate@example.com")
    old_refresh = tokens["refresh_token"]

    refreshed = client.post("/api/auth/refresh", json={"refresh_token": old_refresh})
    assert refreshed.status_code == 200
    assert refreshed.json()["refresh_token"] != old_refresh

    replay = client.post("/api/auth/refresh", json={"refresh_token": old_refresh})
    assert replay.status_code == 401


def test_refresh_reuse_revokes_the_entire_token_chain(client, db_session):
    tokens = _signup(client, email="reuse@example.com")
    old_refresh = tokens["refresh_token"]

    first_rotation = client.post("/api/auth/refresh", json={"refresh_token": old_refresh})
    new_refresh = first_rotation.json()["refresh_token"]

    # Replaying the already-rotated token is theft-shaped — it must revoke the *new* token too.
    reuse_response = client.post("/api/auth/refresh", json={"refresh_token": old_refresh})
    assert reuse_response.status_code == 401

    blocked = client.post("/api/auth/refresh", json={"refresh_token": new_refresh})
    assert blocked.status_code == 401

    rows = db_session.query(RefreshToken).all()
    assert all(row.revoked_at is not None for row in rows)


def test_logout_revokes_the_refresh_token(client):
    tokens = _signup(client, email="logout@example.com")

    logout_response = client.post("/api/auth/logout", json={"refresh_token": tokens["refresh_token"]})
    assert logout_response.status_code == 204

    refresh_after_logout = client.post(
        "/api/auth/refresh", json={"refresh_token": tokens["refresh_token"]}
    )
    assert refresh_after_logout.status_code == 401


# --- Protected-route gating -------------------------------------------------------------


def test_me_returns_the_authenticated_users_account(client):
    tokens = _signup(client, email="me@example.com")
    response = client.get("/api/auth/me", headers=_auth_headers(tokens))
    assert response.status_code == 200
    assert response.json()["email"] == "me@example.com"


def test_unauthenticated_request_to_a_protected_route_is_rejected(client):
    response = client.get("/api/cases")
    assert response.status_code == 401


def test_request_with_a_garbage_bearer_token_is_rejected(client):
    response = client.get("/api/cases", headers={"Authorization": "Bearer not-a-real-token"})
    assert response.status_code == 401


# --- Invites -----------------------------------------------------------------------------


def test_invite_requires_admin_role(client):
    admin_tokens = _signup(client, email="inviter-admin@example.com")
    invite_response = client.post(
        "/api/auth/invite",
        json={"email": "teammate@example.com", "role": "analyst"},
        headers=_auth_headers(admin_tokens),
    )
    assert invite_response.status_code == 200
    assert invite_response.json()["invite_link"].startswith("/accept-invite?token=")


def test_analyst_cannot_send_invites(client):
    admin_tokens = _signup(client, email="admin-for-analyst-test@example.com")
    invite_response = client.post(
        "/api/auth/invite",
        json={"email": "teammate2@example.com", "role": "analyst"},
        headers=_auth_headers(admin_tokens),
    )
    invite_link = invite_response.json()["invite_link"]
    token = invite_link.split("token=")[1]
    accept_response = client.post(
        "/api/auth/invite/accept", json={"token": token, "password": _STRONG_PASSWORD}
    )
    analyst_tokens = accept_response.json()

    forbidden = client.post(
        "/api/auth/invite",
        json={"email": "someone-else@example.com", "role": "analyst"},
        headers=_auth_headers(analyst_tokens),
    )
    assert forbidden.status_code == 403


def test_invite_accept_creates_a_user_with_the_invited_role_in_the_same_account(client):
    admin_tokens = _signup(client, email="team-admin@example.com", account_name="Team Co")
    invite_response = client.post(
        "/api/auth/invite",
        json={"email": "newhire@example.com", "role": "analyst"},
        headers=_auth_headers(admin_tokens),
    )
    token = invite_response.json()["invite_link"].split("token=")[1]

    accept_response = client.post(
        "/api/auth/invite/accept", json={"token": token, "password": _STRONG_PASSWORD}
    )
    assert accept_response.status_code == 200
    body = accept_response.json()
    assert body["user"]["email"] == "newhire@example.com"
    assert body["user"]["role"] == "analyst"
    assert body["user"]["account_name"] == "Team Co"
    assert body["user"]["account_id"] == admin_tokens["user"]["account_id"]


def test_invite_token_cannot_be_used_twice(client):
    admin_tokens = _signup(client, email="reuse-invite-admin@example.com")
    invite_response = client.post(
        "/api/auth/invite",
        json={"email": "onetime@example.com", "role": "analyst"},
        headers=_auth_headers(admin_tokens),
    )
    token = invite_response.json()["invite_link"].split("token=")[1]

    first = client.post("/api/auth/invite/accept", json={"token": token, "password": _STRONG_PASSWORD})
    assert first.status_code == 200

    second = client.post("/api/auth/invite/accept", json={"token": token, "password": _STRONG_PASSWORD})
    assert second.status_code == 400


# --- Password reset ------------------------------------------------------------------------


def test_password_reset_request_does_not_reveal_whether_the_email_exists(client):
    _signup(client, email="reset-me@example.com")

    known = client.post("/api/auth/password-reset/request", json={"email": "reset-me@example.com"})
    unknown = client.post(
        "/api/auth/password-reset/request", json={"email": "never-signed-up@example.com"}
    )

    assert known.status_code == 200
    assert unknown.status_code == 200
    assert known.json()["message"] == unknown.json()["message"]
    assert known.json()["reset_link"] is not None
    assert unknown.json()["reset_link"] is None


def test_password_reset_confirm_changes_password_and_revokes_existing_sessions(client):
    tokens = _signup(client, email="reset-flow@example.com")

    reset_request = client.post(
        "/api/auth/password-reset/request", json={"email": "reset-flow@example.com"}
    )
    reset_token = reset_request.json()["reset_link"].split("token=")[1]

    confirm = client.post(
        "/api/auth/password-reset/confirm",
        json={"token": reset_token, "new_password": "AnEvenStr0ngerPassw0rd!"},
    )
    assert confirm.status_code == 204

    # The refresh token issued at signup must no longer work — password reset force-revokes
    # every existing session.
    stale_refresh = client.post("/api/auth/refresh", json={"refresh_token": tokens["refresh_token"]})
    assert stale_refresh.status_code == 401

    old_password_login = client.post(
        "/api/auth/login", json={"email": "reset-flow@example.com", "password": _STRONG_PASSWORD}
    )
    assert old_password_login.status_code == 401

    new_password_login = client.post(
        "/api/auth/login",
        json={"email": "reset-flow@example.com", "password": "AnEvenStr0ngerPassw0rd!"},
    )
    assert new_password_login.status_code == 200


# --- User management / roster ---------------------------------------------------------------


def test_users_list_is_scoped_to_the_callers_own_account(client):
    account_a = _signup(client, email="account-a-admin@example.com", account_name="Account A")
    account_b = _signup(client, email="account-b-admin@example.com", account_name="Account B")

    listing_a = client.get("/api/auth/users", headers=_auth_headers(account_a))
    assert listing_a.status_code == 200
    emails_a = {u["email"] for u in listing_a.json()["items"]}
    assert emails_a == {"account-a-admin@example.com"}

    listing_b = client.get("/api/auth/users", headers=_auth_headers(account_b))
    emails_b = {u["email"] for u in listing_b.json()["items"]}
    assert emails_b == {"account-b-admin@example.com"}


def test_update_user_role_requires_admin(client):
    admin_tokens = _signup(client, email="role-admin@example.com")
    invite_response = client.post(
        "/api/auth/invite",
        json={"email": "role-analyst@example.com", "role": "analyst"},
        headers=_auth_headers(admin_tokens),
    )
    invite_token = invite_response.json()["invite_link"].split("token=")[1]
    analyst_tokens = client.post(
        "/api/auth/invite/accept", json={"token": invite_token, "password": _STRONG_PASSWORD}
    ).json()
    analyst_id = analyst_tokens["user"]["id"]

    forbidden = client.patch(
        f"/api/auth/users/{analyst_id}",
        json={"role": "admin"},
        headers=_auth_headers(analyst_tokens),
    )
    assert forbidden.status_code == 403

    allowed = client.patch(
        f"/api/auth/users/{analyst_id}",
        json={"role": "admin"},
        headers=_auth_headers(admin_tokens),
    )
    assert allowed.status_code == 200
    assert allowed.json()["role"] == "admin"


def test_delete_user_cannot_remove_self(client):
    tokens = _signup(client, email="self-delete@example.com")
    user_id = tokens["user"]["id"]

    response = client.delete(f"/api/auth/users/{user_id}", headers=_auth_headers(tokens))
    assert response.status_code == 400


def test_cannot_update_or_delete_a_user_in_another_account(client):
    account_a = _signup(client, email="isolated-a-admin@example.com", account_name="Isolated A")
    account_b = _signup(client, email="isolated-b-admin@example.com", account_name="Isolated B")
    other_user_id = account_b["user"]["id"]

    update_response = client.patch(
        f"/api/auth/users/{other_user_id}",
        json={"role": "admin"},
        headers=_auth_headers(account_a),
    )
    assert update_response.status_code == 404

    delete_response = client.delete(
        f"/api/auth/users/{other_user_id}", headers=_auth_headers(account_a)
    )
    assert delete_response.status_code == 404
