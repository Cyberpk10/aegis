from __future__ import annotations

import uuid
from datetime import datetime

from app.copilot.templates import (
    FrameworkCoverageParams,
    IndicatorCaseCountParams,
    TargetLookupParams,
    TopIndicatorsParams,
    UnsupportedQuestionParams,
    VerdictCountsParams,
    _execute_framework_coverage,
    _execute_indicator_case_count,
    _execute_target_lookup,
    _execute_top_indicators,
    _execute_unsupported_question,
    _execute_verdict_counts,
)
from app.db.models import Case

CRED = {
    "id": "CREDENTIAL_REQUEST",
    "category": "content",
    "title": "Cred req",
    "description": "d",
    "evidence": [],
    "severity": "high",
    "score": 30.0,
}
SPF = {
    "id": "AUTH_SPF_FAIL",
    "category": "authentication",
    "title": "SPF fail",
    "description": "d",
    "evidence": [],
    "severity": "high",
    "score": 15.0,
}
MITRE_MAPPING = {
    "mitre_attack": [
        {
            "indicator_id": "CREDENTIAL_REQUEST",
            "control_id": "T1598",
            "control_name": "Phishing for Information",
            "url": None,
        }
    ]
}


def _make_case(
    db_session,
    *,
    verdict,
    created_at,
    indicators=None,
    framework_mappings=None,
    to_addresses=None,
):
    case = Case(
        id=uuid.uuid4(),
        created_at=created_at,
        filename="t.eml",
        verdict=verdict,
        score=50,
        from_addr="s@example.com",
        subject="s",
        to_addresses=to_addresses or [],
        indicators=indicators or [],
        framework_mappings=framework_mappings or {},
    )
    db_session.add(case)
    db_session.commit()
    db_session.refresh(case)
    return case


def test_verdict_counts_executor(db_session):
    _make_case(db_session, verdict="malicious", created_at=datetime(2026, 1, 5))
    _make_case(db_session, verdict="malicious", created_at=datetime(2026, 1, 6))
    _make_case(db_session, verdict="safe", created_at=datetime(2026, 1, 7))

    result = _execute_verdict_counts(VerdictCountsParams(), db_session)

    assert result["counts"] == {"malicious": 2, "suspicious": 0, "safe": 1}
    assert result["total"] == 3


def test_verdict_counts_executor_respects_date_range(db_session):
    _make_case(db_session, verdict="malicious", created_at=datetime(2026, 1, 5))
    _make_case(db_session, verdict="malicious", created_at=datetime(2025, 1, 5))

    result = _execute_verdict_counts(
        VerdictCountsParams(date_from=datetime(2026, 1, 1), date_to=datetime(2026, 1, 31)),
        db_session,
    )

    assert result["total"] == 1


def test_top_indicators_executor(db_session):
    _make_case(db_session, verdict="malicious", created_at=datetime(2026, 1, 5), indicators=[CRED])
    _make_case(
        db_session, verdict="malicious", created_at=datetime(2026, 1, 6), indicators=[CRED, SPF]
    )

    result = _execute_top_indicators(TopIndicatorsParams(top_n=5), db_session)

    top = result["top_indicators"]
    assert top[0]["indicator_id"] == "CREDENTIAL_REQUEST"
    assert top[0]["count"] == 2


def test_indicator_case_count_executor(db_session):
    _make_case(db_session, verdict="malicious", created_at=datetime(2026, 1, 5), indicators=[CRED])
    _make_case(db_session, verdict="malicious", created_at=datetime(2026, 1, 6), indicators=[SPF])

    result = _execute_indicator_case_count(
        IndicatorCaseCountParams(indicator_id="CREDENTIAL_REQUEST"), db_session
    )

    assert result["count"] == 1
    assert len(result["sample_case_ids"]) == 1


def test_target_lookup_executor(db_session):
    for i in range(3):
        _make_case(
            db_session,
            verdict="malicious",
            created_at=datetime(2026, 1, i + 1),
            indicators=[CRED],
            to_addresses=["alice@example.com"],
        )

    result = _execute_target_lookup(TargetLookupParams(recipient="Alice@Example.com"), db_session)

    assert result["hit_count"] == 3
    assert result["flagged_for_training"] is True  # default threshold is 3


def test_target_lookup_executor_unknown_recipient(db_session):
    result = _execute_target_lookup(TargetLookupParams(recipient="nobody@example.com"), db_session)

    assert result["hit_count"] == 0
    assert result["flagged_for_training"] is False


def test_framework_coverage_executor(db_session):
    _make_case(
        db_session,
        verdict="malicious",
        created_at=datetime(2026, 1, 5),
        indicators=[CRED],
        framework_mappings=MITRE_MAPPING,
    )

    result = _execute_framework_coverage(FrameworkCoverageParams(framework="mitre"), db_session)

    assert result["framework"] == "mitre"
    assert result["operating_controls"] == 1
    assert result["total_controls"] == 7  # matches mitre_attack.yaml's control count


def test_unsupported_question_executor(db_session):
    result = _execute_unsupported_question(
        UnsupportedQuestionParams(reason="asks about the weather"), db_session
    )

    assert result == {"answerable": False, "reason": "asks about the weather"}
