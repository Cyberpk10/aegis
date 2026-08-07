from __future__ import annotations

import json
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from app.core.config import settings
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
