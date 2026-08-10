"""Rate limiting for the auth endpoints (M8 Stage 2) — login/signup/password-reset/invite-accept
are the endpoints an attacker would brute-force or abuse, so they're the only ones limited.

In-memory storage (slowapi's default) — correct for the current single-instance Render
deployment (`render.yaml` has no `numInstances` override, i.e. it's 1). A multi-instance
deployment would need a shared backend (e.g. Redis) since each instance would otherwise track
its own independent counters; not built now — a real scope boundary, not an oversight.
"""

from __future__ import annotations

from slowapi import Limiter
from slowapi.util import get_remote_address

limiter = Limiter(key_func=get_remote_address)

AUTH_RATE_LIMIT = "10/minute"
