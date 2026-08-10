"""The injection-focused test suite for the copilot. No LLM mocking needed here — these
tests exercise the whitelist-enforcement boundary (app.copilot.templates.execute_template)
directly, proving it holds regardless of what any caller (including a fully-compromised
LLM response) passes in.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest
from pydantic import ValidationError

import uuid

from app.copilot.templates import TEMPLATE_REGISTRY, execute_template

_ACCOUNT_ID = uuid.uuid4()


def test_unknown_template_name_is_rejected_not_executed(db_session):
    with pytest.raises(KeyError):
        execute_template("'; DROP TABLE cases; --", {}, db_session, _ACCOUNT_ID)


def test_plausible_sounding_but_unwhitelisted_template_name_is_rejected(db_session):
    with pytest.raises(KeyError):
        execute_template("run_raw_sql", {}, db_session, _ACCOUNT_ID)


def test_extra_params_are_rejected_not_silently_dropped(db_session):
    with pytest.raises(ValidationError):
        execute_template(
            "verdict_counts",
            {"date_from": None, "raw_sql": "DROP TABLE cases; --"},
            db_session, _ACCOUNT_ID,
        )


def test_extra_params_rejected_even_alongside_valid_required_fields(db_session):
    with pytest.raises(ValidationError):
        execute_template(
            "target_lookup",
            {"recipient": "alice@example.com", "injected_field": "anything"},
            db_session, _ACCOUNT_ID,
        )


def test_missing_required_param_is_rejected(db_session):
    with pytest.raises(ValidationError):
        execute_template("indicator_case_count", {}, db_session, _ACCOUNT_ID)  # indicator_id is required


def test_wrong_typed_param_is_rejected(db_session):
    with pytest.raises(ValidationError):
        execute_template("top_indicators", {"top_n": "'; DROP TABLE cases; --"}, db_session, _ACCOUNT_ID)


_FORBIDDEN_QUERY_CONSTRUCTION = re.compile(
    r"\.execute\(|\btext\(|f\"[^\"]*SELECT|f'[^']*SELECT", re.IGNORECASE
)


def test_copilot_source_contains_no_raw_sql_construction():
    """Static guardrail, not just a behavioral one — same technique as Stage 3's
    remediation guardrail test. Proves no file in app/copilot/ ever builds a query
    string; every executor is a plain SQLAlchemy ORM call."""
    copilot_dir = Path(__file__).resolve().parents[2] / "app" / "copilot"
    files = sorted(copilot_dir.glob("*.py"))
    assert len(files) >= 2  # sanity: we actually found the files we intend to check

    for path in files:
        source = path.read_text()
        match = _FORBIDDEN_QUERY_CONSTRUCTION.search(source)
        assert match is None, (
            f"{path} contains {match and match.group(0)!r} — no raw SQL construction allowed"
        )


def test_template_registry_only_contains_the_documented_whitelist():
    """Guards against silent scope creep — adding a new template should be a deliberate
    change that updates this test, not an accidental widening of what the LLM can reach."""
    assert set(TEMPLATE_REGISTRY.keys()) == {
        "verdict_counts",
        "top_indicators",
        "indicator_case_count",
        "target_lookup",
        "framework_coverage",
        "unsupported_question",
    }
