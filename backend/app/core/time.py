"""Naive-UTC datetime normalization.

This codebase compares DB-persisted timestamps as naive UTC throughout (see
app.auth.security.refresh_token_expiry): SQLite (used by the test suite) round-trips
DateTime(timezone=True) columns as naive, while Postgres (production) returns them
timezone-aware via psycopg. Mixing the two raises `TypeError` on subtraction/comparison —
anything read from the DB for Python-side datetime arithmetic should be normalized with this
first.
"""

from __future__ import annotations

from datetime import datetime


def to_naive_utc(value: datetime) -> datetime:
    """Strips tzinfo from an aware datetime (assumed already UTC — true for every
    DateTime(timezone=True) column in this app); a no-op for an already-naive datetime."""
    if value.tzinfo is not None:
        return value.replace(tzinfo=None)
    return value
