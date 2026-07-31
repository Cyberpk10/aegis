from __future__ import annotations

import json
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from app.main import app
from app.parsing.eml_parser import ParsedEmail, parse_eml

FIXTURES_DIR = Path(__file__).parent / "fixtures" / "emails"


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
