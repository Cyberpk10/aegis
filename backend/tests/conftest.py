from __future__ import annotations

import json
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.core.config import settings
from app.db.session import Base, get_db
from app.main import app
from app.parsing.eml_parser import ParsedEmail, parse_eml

FIXTURES_DIR = Path(__file__).parent / "fixtures" / "emails"
EVENTS_FIXTURES_DIR = Path(__file__).parent / "fixtures" / "events"


@pytest.fixture(autouse=True)
def _deterministic_llm_settings(monkeypatch):
    """Pin the shared settings singleton to the offline default for every test.

    config.py auto-loads a local .env, so a developer's own backend/.env (e.g. with
    ENABLE_LLM_REASONING=true for manual testing) must never change default test
    behavior. Tests that want the LLM path opt in explicitly via monkeypatch.
    """
    monkeypatch.setattr(settings, "enable_llm_reasoning", False)
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)


@pytest.fixture()
def _test_engine():
    """A fresh in-memory SQLite database per test, regardless of a developer's local
    DATABASE_URL — the suite must stay offline and isolated."""
    engine = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(bind=engine)
    yield engine
    Base.metadata.drop_all(bind=engine)
    engine.dispose()


@pytest.fixture(autouse=True)
def _test_database(monkeypatch, tmp_path, _test_engine):
    """Point the app's get_db dependency at _test_engine, and redirect raw email storage
    to a per-test tmp_path so tests never touch the real data/ dir."""
    TestingSessionLocal = sessionmaker(bind=_test_engine, autoflush=False, autocommit=False)

    def _override_get_db():
        db = TestingSessionLocal()
        try:
            yield db
        finally:
            db.close()

    app.dependency_overrides[get_db] = _override_get_db
    monkeypatch.setattr(settings, "raw_email_storage_dir", str(tmp_path / "raw_emails"))
    monkeypatch.setattr(settings, "audit_report_storage_dir", str(tmp_path / "audit_reports"))

    yield

    app.dependency_overrides.pop(get_db, None)


@pytest.fixture()
def db_session(_test_engine):
    """A plain SQLAlchemy session bound to the same test database the app is using, for
    tests that need to assert on rows directly (e.g. label history) rather than through
    an API response shape."""
    TestingSessionLocal = sessionmaker(bind=_test_engine, autoflush=False, autocommit=False)
    session = TestingSessionLocal()
    try:
        yield session
    finally:
        session.close()


@pytest.fixture()
def client() -> TestClient:
    return TestClient(app)


@pytest.fixture()
def load_eml():
    def _load(filename: str) -> bytes:
        return (FIXTURES_DIR / filename).read_bytes()

    return _load


@pytest.fixture()
def parse_fixture():
    def _parse(filename: str) -> ParsedEmail:
        return parse_eml((FIXTURES_DIR / filename).read_bytes())

    return _parse


@pytest.fixture()
def labeled_samples() -> dict[str, str]:
    return json.loads((FIXTURES_DIR / "labels.json").read_text())


@pytest.fixture()
def load_events_fixture():
    def _load(filename: str) -> list[dict]:
        return json.loads((EVENTS_FIXTURES_DIR / filename).read_text())

    return _load


@pytest.fixture()
def build_event_window():
    """Loads a JSON event fixture and returns an ActorEventWindow ready for a detection
    rule's evaluate(), mirroring parse_fixture's role for email indicators."""
    from app.detections.base import ActorEventWindow
    from app.events.schema import ActivityEvent

    def _build(filename: str) -> ActorEventWindow:
        raw_events = json.loads((EVENTS_FIXTURES_DIR / filename).read_text())
        events = [ActivityEvent.model_validate(e) for e in raw_events]
        actor = events[0].actor
        return ActorEventWindow(actor=actor, events=events)

    return _build
