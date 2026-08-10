from __future__ import annotations

import json
import uuid
from dataclasses import dataclass
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from app.auth.rate_limit import limiter
from app.auth.security import create_access_token, hash_password
from app.core.config import settings
from app.db.models import Account, User
from app.db.session import Base, get_db
from app.main import app
from app.parsing.eml_parser import ParsedEmail, parse_eml

FIXTURES_DIR = Path(__file__).parent / "fixtures" / "emails"
EVENTS_FIXTURES_DIR = Path(__file__).parent / "fixtures" / "events"


@pytest.fixture(autouse=True)
def _reset_auth_rate_limiter():
    """slowapi's in-memory limiter is a module-level singleton shared across the whole
    test session, keyed by remote address — and every TestClient request looks like it
    comes from the same address. Without resetting per test, an unrelated earlier test
    hitting a rate-limited endpoint (e.g. /api/auth/login) would bleed its counter into
    this one, causing order-dependent 429s that have nothing to do with the test itself."""
    limiter.reset()
    yield


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


@dataclass
class AuthedActor:
    account: Account
    user: User
    token: str


def _create_account_and_user(
    db: Session,
    *,
    email: str,
    role: str = "admin",
    account_id: uuid.UUID | None = None,
    account_name: str = "Test Account",
) -> AuthedActor:
    if account_id is None:
        account = Account(id=uuid.uuid4(), name=account_name)
        db.add(account)
        db.flush()
    else:
        account = db.get(Account, account_id)

    user = User(
        id=uuid.uuid4(),
        account_id=account.id,
        email=email,
        password_hash=hash_password("Str0ngTestPassw0rd!"),
        role=role,
        is_active=True,
    )
    db.add(user)
    db.commit()
    db.refresh(account)
    db.refresh(user)
    return AuthedActor(account=account, user=user, token=create_access_token(user.id))


def _client_for(actor: AuthedActor) -> TestClient:
    # A dedicated TestClient per actor — sharing one across actors would mean the later
    # header update clobbers the earlier one, since TestClient.headers is one shared dict.
    test_client = TestClient(app)
    test_client.headers.update({"Authorization": f"Bearer {actor.token}"})
    return test_client


@pytest.fixture()
def test_account(db_session) -> AuthedActor:
    """The default authenticated actor: an admin in their own account."""
    return _create_account_and_user(db_session, email="admin@example.com", role="admin")


@pytest.fixture()
def authed_client(test_account) -> TestClient:
    return _client_for(test_account)


@pytest.fixture()
def analyst_authed_client(db_session, test_account) -> TestClient:
    """An analyst-role user in the SAME account as `test_account` — for role-permission
    tests (an analyst hitting an admin-only endpoint should 403, not 401)."""
    analyst = _create_account_and_user(
        db_session,
        email="analyst@example.com",
        role="analyst",
        account_id=test_account.account.id,
    )
    return _client_for(analyst)


@pytest.fixture()
def other_account_authed_client(db_session) -> TestClient:
    """An admin in a wholly different account — for cross-account isolation tests."""
    other = _create_account_and_user(
        db_session,
        email="other-admin@example.com",
        role="admin",
        account_name="Other Account",
    )
    return _client_for(other)


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
