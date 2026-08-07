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


@pytest.fixture(autouse=True)
def _deterministic_llm_settings(monkeypatch):
    """Pin the shared settings singleton to the offline default for every test.

    config.py auto-loads a local .env, so a developer's own backend/.env (e.g. with
    ENABLE_LLM_REASONING=true for manual testing) must never change default test
    behavior. Tests that want the LLM path opt in explicitly via monkeypatch.
    """
    monkeypatch.setattr(settings, "enable_llm_reasoning", False)
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)


@pytest.fixture(autouse=True)
def _test_database(monkeypatch, tmp_path):
    """Give every test a fresh in-memory SQLite database, regardless of a developer's
    local DATABASE_URL — the suite must stay offline and isolated. Also redirects raw
    email storage to a per-test tmp_path so tests never touch the real data/ dir."""
    engine = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(bind=engine)
    TestingSessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False)

    def _override_get_db():
        db = TestingSessionLocal()
        try:
            yield db
        finally:
            db.close()

    app.dependency_overrides[get_db] = _override_get_db
    monkeypatch.setattr(settings, "raw_email_storage_dir", str(tmp_path / "raw_emails"))

    yield

    app.dependency_overrides.pop(get_db, None)
    Base.metadata.drop_all(bind=engine)
    engine.dispose()


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
