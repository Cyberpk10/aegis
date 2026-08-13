from __future__ import annotations

import uuid
from datetime import datetime, timezone

from app.api.routes.dashboard import _to_case_row
from app.dashboard.aggregation import kris
from app.db.models import Case


def _in_memory_case(created_at: datetime) -> Case:
    """Never committed — just an ORM object built in Python memory, so this works
    regardless of which DB dialect is configured."""
    return Case(
        id=uuid.uuid4(),
        account_id=uuid.uuid4(),
        filename="test.eml",
        verdict="malicious",
        score=80,
        indicators=[],
        framework_mappings={},
        created_at=created_at,
    )


def test_to_case_row_strips_tzinfo_from_an_aware_created_at():
    """Postgres (production) returns an aware datetime for Case.created_at; SQLite (tests)
    returns naive. _to_case_row must normalize either input to naive, since kris() below
    subtracts it from a naive datetime.utcnow()."""
    case = _in_memory_case(datetime(2026, 1, 1, tzinfo=timezone.utc))
    row = _to_case_row(case)
    assert row.created_at.tzinfo is None


def test_kris_does_not_raise_when_case_created_at_was_originally_aware():
    """Regression test for the production crash: 'TypeError: can't subtract offset-naive
    and offset-aware datetimes' in kris() when Case.created_at came back tz-aware from
    Postgres. Exercises the exact _to_case_row -> kris() path the real endpoint uses."""
    case = _in_memory_case(datetime(2026, 1, 1, tzinfo=timezone.utc))
    row = _to_case_row(case)

    result = kris([row], {}, datetime(2026, 1, 5))

    assert result["unlabeled_count"] == 1
    assert result["mean_unlabeled_backlog_days"] == 4.0
