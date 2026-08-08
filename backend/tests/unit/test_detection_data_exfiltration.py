from __future__ import annotations

from datetime import datetime, timezone

from app.core.config import settings
from app.detections.base import ActorEventWindow
from app.detections.data_exfiltration import evaluate
from app.events.schema import ActivityEvent, EventAction

_TS = datetime(2026, 1, 6, 14, 0, tzinfo=timezone.utc)


def _transfer(bytes_: int, target: str = "unknown-host.example.net") -> ActivityEvent:
    return ActivityEvent(
        timestamp=_TS,
        actor="erin@corp.com",
        action=EventAction.DATA_TRANSFER,
        target=target,
        bytes=bytes_,
        outcome="success",
    )


def _db_export(bytes_: int) -> ActivityEvent:
    return ActivityEvent(
        timestamp=_TS,
        actor="frank@corp.com",
        action=EventAction.DB_QUERY,
        target="customers_db",
        bytes=bytes_,
        outcome="success",
    )


def test_fires_for_large_transfer_to_unfamiliar_destination():
    window = ActorEventWindow(actor="erin@corp.com", events=[_transfer(600_000_000)])
    findings = evaluate(window)
    ids = [f.id for f in findings]
    assert "DATA_EXFIL_LARGE_TRANSFER" in ids


def test_does_not_fire_for_small_transfer():
    window = ActorEventWindow(actor="erin@corp.com", events=[_transfer(1_000_000)])
    assert evaluate(window) == []


def test_does_not_fire_for_large_transfer_to_allowlisted_destination(monkeypatch):
    monkeypatch.setattr(settings, "exfil_allowlisted_destinations", ["trusted.example.com"])
    window = ActorEventWindow(
        actor="erin@corp.com", events=[_transfer(600_000_000, target="trusted.example.com")]
    )
    assert evaluate(window) == []


def test_fires_for_large_db_export():
    window = ActorEventWindow(actor="frank@corp.com", events=[_db_export(300_000_000)])
    findings = evaluate(window)
    ids = [f.id for f in findings]
    assert "DATA_EXFIL_LARGE_DB_EXPORT" in ids


def test_does_not_fire_for_small_db_query():
    window = ActorEventWindow(actor="frank@corp.com", events=[_db_export(5_000_000)])
    assert evaluate(window) == []


def test_both_findings_can_fire_independently_in_same_window():
    window = ActorEventWindow(
        actor="erin@corp.com", events=[_transfer(600_000_000), _db_export(300_000_000)]
    )
    ids = {f.id for f in evaluate(window)}
    assert ids == {"DATA_EXFIL_LARGE_TRANSFER", "DATA_EXFIL_LARGE_DB_EXPORT"}
