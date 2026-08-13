from __future__ import annotations

from datetime import datetime, timezone

from app.core.time import to_naive_utc


def test_aware_datetime_is_stripped_to_naive():
    aware = datetime(2026, 1, 1, 12, 0, 0, tzinfo=timezone.utc)
    result = to_naive_utc(aware)
    assert result.tzinfo is None
    assert result == datetime(2026, 1, 1, 12, 0, 0)


def test_naive_datetime_is_unchanged():
    naive = datetime(2026, 1, 1, 12, 0, 0)
    assert to_naive_utc(naive) == naive
    assert to_naive_utc(naive).tzinfo is None
