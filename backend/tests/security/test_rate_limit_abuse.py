"""Rate-limit / abuse adversarial tests. tests/integration/test_auth_endpoints.py already
proves the 10/minute AUTH_RATE_LIMIT holds for /api/auth/login, and
tests/integration/test_inbound_email_endpoint.py already proves the per-account business-logic
cap (inbound_email_rate_limit_per_account_per_hour) holds. What's new here: the COARSE,
per-IP slowapi limiter on the inbound webhook itself (_WEBHOOK_RATE_LIMIT = "120/minute",
app.api.routes.inbound) — a separate layer from the per-account cap, meant to catch gross
abuse (e.g. garbage/unsigned requests) before a single byte of Mailgun-signature-checking
logic even runs — plus a live-fire smoke test against a real running dev server, since
in-process TestClient requests all share one fake test IP and never exercise a real
socket/event-loop under concurrent load.
"""

from __future__ import annotations

from app.core.config import settings

_URL = "/api/inbound/email/mime"


def test_webhook_ip_rate_limit_returns_429_after_120_requests_per_minute(client, monkeypatch):
    """slowapi's @limiter.limit(...) decorator runs before any route-body logic (including
    signature verification), so even a flood of requests with a garbage/empty signature
    must trip the coarse per-IP limiter at request 121 — proving this layer isn't
    dependent on ever reaching a "real" webhook call."""
    monkeypatch.setattr(settings, "mailgun_webhook_signing_key", "some-signing-key")

    last_status = None
    for i in range(121):
        response = client.post(
            _URL,
            data={
                "timestamp": "1",
                "token": f"t{i}",
                "signature": "invalid",
                "recipient": "pilot-doesnotexist@in.aegis.example.com",
            },
        )
        last_status = response.status_code

    assert last_status == 429


def test_webhook_disabled_without_signing_key_regardless_of_request_volume(client):
    """Confirms the fail-closed default holds even under repeated hammering: with no
    signing key configured, every single request is a 503, never a 200/401 that might
    suggest partial processing."""
    for _ in range(5):
        response = client.post(
            _URL,
            data={"timestamp": "1", "token": "t", "signature": "x", "recipient": "pilot-x@in.aegis.example.com"},
        )
        assert response.status_code == 503
