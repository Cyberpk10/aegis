"""Mailgun inbound-webhook signature verification and payload extraction (M8 Stage 3).

Signature scheme: HMAC-SHA256 over the raw concatenation `timestamp + token` (no separator),
keyed by the account's HTTP webhook signing key (Sending -> Webhooks in the Mailgun dashboard —
a distinct value from the API key), compared with `hmac.compare_digest`. Same shape as the
token-hashing code in app.auth.security — no new dependency. A timestamp freshness check is
added on top as replay-attack defense in depth; Mailgun's own signature never expires on its own.
"""

from __future__ import annotations

import hashlib
import hmac
import time
from collections.abc import Mapping
from email.message import EmailMessage
from typing import Any


def verify_signature(
    *,
    timestamp: str,
    token: str,
    signature: str,
    signing_key: str,
    max_age_seconds: int,
) -> bool:
    """Never raises — a malformed/missing field is just a failed verification, not an error."""
    if not signing_key or not timestamp or not token or not signature:
        return False

    try:
        timestamp_int = int(timestamp)
    except (TypeError, ValueError):
        return False

    if abs(time.time() - timestamp_int) > max_age_seconds:
        return False

    expected = hmac.new(
        key=signing_key.encode("utf-8"),
        msg=f"{timestamp}{token}".encode("utf-8"),
        digestmod=hashlib.sha256,
    ).hexdigest()
    return hmac.compare_digest(expected, signature)


def extract_raw_email(form: Mapping[str, Any]) -> bytes:
    """Prefers Mailgun's `body-mime` field — the complete original raw email, present when the
    route's forward-destination URL ends in `/mime` (see DEPLOYMENT.md) — but synthesizes a raw
    message from the individually-parsed fields if it's ever absent, so a route misconfigured
    without the `/mime` suffix degrades gracefully instead of silently dropping every email."""
    body_mime = form.get("body-mime")
    if body_mime:
        return body_mime.encode("utf-8") if isinstance(body_mime, str) else bytes(body_mime)

    synthetic = EmailMessage()
    synthetic["From"] = form.get("from") or form.get("sender") or ""
    synthetic["To"] = form.get("recipient") or ""
    synthetic["Subject"] = form.get("subject") or ""
    synthetic.set_content(form.get("body-plain") or "")
    return synthetic.as_bytes()
