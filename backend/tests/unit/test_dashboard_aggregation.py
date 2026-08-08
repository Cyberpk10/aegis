from __future__ import annotations

from datetime import datetime, timedelta, timezone

from app.dashboard.aggregation import (
    CaseRow,
    LabelRow,
    agreement_rate,
    framework_coverage,
    kris,
    monthly_threat_trend,
    top_indicators,
    verdict_counts,
)


def _case(id_, verdict, created_at=None, indicators=None, framework_mappings=None):
    return CaseRow(
        id=id_,
        created_at=created_at or datetime(2026, 1, 15, tzinfo=timezone.utc),
        verdict=verdict,
        indicators=indicators or [],
        framework_mappings=framework_mappings or {},
    )


def _label(case_id, analyst_verdict, created_at=None):
    return LabelRow(
        case_id=case_id,
        analyst_verdict=analyst_verdict,
        created_at=created_at or datetime(2026, 1, 16, tzinfo=timezone.utc),
    )


def test_verdict_counts_tallies_each_verdict():
    cases = [_case("1", "malicious"), _case("2", "malicious"), _case("3", "suspicious"), _case("4", "safe")]
    assert verdict_counts(cases) == {"malicious": 2, "suspicious": 1, "safe": 1}


def test_verdict_counts_zero_when_no_cases():
    assert verdict_counts([]) == {"malicious": 0, "suspicious": 0, "safe": 0}


def test_top_indicators_ranks_by_frequency_and_carries_metadata():
    ind_a = {"id": "URGENCY_LANGUAGE", "title": "Urgency", "category": "content", "severity": "high"}
    ind_b = {"id": "AUTH_SPF_FAIL", "title": "SPF fail", "category": "auth", "severity": "high"}
    cases = [
        _case("1", "malicious", indicators=[ind_a, ind_b]),
        _case("2", "malicious", indicators=[ind_a]),
        _case("3", "safe", indicators=[]),
    ]

    result = top_indicators(cases, top_n=10)

    assert result[0]["indicator_id"] == "URGENCY_LANGUAGE"
    assert result[0]["count"] == 2
    assert result[0]["title"] == "Urgency"
    assert result[1]["indicator_id"] == "AUTH_SPF_FAIL"
    assert result[1]["count"] == 1


def test_top_indicators_respects_top_n():
    indicators = [{"id": f"IND_{i}", "title": "t", "category": "c", "severity": "low"} for i in range(5)]
    cases = [_case("1", "malicious", indicators=indicators)]

    result = top_indicators(cases, top_n=2)

    assert len(result) == 2


def test_monthly_threat_trend_counts_non_safe_by_month_and_skips_safe():
    cases = [
        _case("1", "malicious", created_at=datetime(2026, 1, 5)),
        _case("2", "suspicious", created_at=datetime(2026, 1, 20)),
        _case("3", "safe", created_at=datetime(2026, 1, 10)),
        _case("4", "malicious", created_at=datetime(2026, 2, 1)),
    ]

    trend = monthly_threat_trend(cases)

    assert trend == [{"month": "2026-01", "count": 2}, {"month": "2026-02", "count": 1}]


def test_framework_coverage_computes_percentage_of_full_control_universe():
    cases = [
        _case(
            "1",
            "malicious",
            framework_mappings={"mitre_attack": [{"control_id": "T1566"}, {"control_id": "T1598"}]},
        ),
        # Duplicate control across cases must not double-count coverage.
        _case("2", "malicious", framework_mappings={"mitre_attack": [{"control_id": "T1566"}]}),
    ]

    result = framework_coverage(cases, {"mitre_attack": 4, "nist_csf": 10})
    by_key = {r["framework_key"]: r for r in result}

    assert by_key["mitre_attack"] == {
        "framework_key": "mitre_attack",
        "total_controls": 4,
        "covered_controls": 2,
        "coverage_pct": 50.0,
    }
    assert by_key["nist_csf"]["covered_controls"] == 0
    assert by_key["nist_csf"]["coverage_pct"] == 0.0


def test_agreement_rate_none_when_nothing_labeled():
    cases = [_case("1", "malicious")]

    result = agreement_rate(cases, {})

    assert result == {"rate_pct": None, "labeled_count": 0, "agreeing_count": 0}


def test_agreement_rate_computes_percentage_matching():
    cases = [_case("1", "malicious"), _case("2", "safe"), _case("3", "suspicious")]
    labels = {
        "1": _label("1", "malicious"),  # agrees
        "2": _label("2", "malicious"),  # disagrees
    }

    result = agreement_rate(cases, labels)

    assert result == {"rate_pct": 50.0, "labeled_count": 2, "agreeing_count": 1}


def test_kris_catch_rate_and_false_positive_rate():
    cases = [
        _case("1", "malicious"),  # TP
        _case("2", "safe"),  # FN: analyst says malicious, machine missed it
        _case("3", "malicious"),  # FP: analyst says it isn't malicious
        _case("4", "safe"),  # TN
    ]
    labels = {
        "1": _label("1", "malicious"),
        "2": _label("2", "malicious"),
        "3": _label("3", "suspicious"),
        "4": _label("4", "safe"),
    }

    result = kris(cases, labels, now=datetime(2026, 1, 20, tzinfo=timezone.utc))

    assert result["malicious_catch_rate_pct"] == 50.0  # TP=1, FN=1
    assert result["false_positive_rate_pct"] == 50.0  # FP=1, TN=1
    assert result["unlabeled_count"] == 0
    assert result["labeled_count"] == 4


def test_kris_rates_are_none_when_nothing_labeled():
    cases = [_case("1", "safe")]

    result = kris(cases, {}, now=datetime(2026, 1, 20, tzinfo=timezone.utc))

    assert result["malicious_catch_rate_pct"] is None
    assert result["false_positive_rate_pct"] is None
    assert result["unlabeled_count"] == 1
    assert result["labeled_count"] == 0


def test_kris_catch_rate_is_none_when_analyst_never_flags_malicious():
    # Every labeled case's analyst_verdict is non-malicious, so TP+FN == 0.
    cases = [_case("1", "safe"), _case("2", "suspicious")]
    labels = {"1": _label("1", "safe"), "2": _label("2", "suspicious")}

    result = kris(cases, labels, now=datetime(2026, 1, 20, tzinfo=timezone.utc))

    assert result["malicious_catch_rate_pct"] is None
    assert result["false_positive_rate_pct"] == 0.0  # FP=0, TN=2 — a real, defined 0%


def test_kris_false_positive_rate_is_none_when_analyst_always_flags_malicious():
    # Every labeled case's analyst_verdict is malicious, so FP+TN == 0.
    cases = [_case("1", "malicious")]
    labels = {"1": _label("1", "malicious")}

    result = kris(cases, labels, now=datetime(2026, 1, 20, tzinfo=timezone.utc))

    assert result["malicious_catch_rate_pct"] == 100.0  # TP=1, FN=0
    assert result["false_positive_rate_pct"] is None


def test_kris_mean_unlabeled_backlog_days():
    now = datetime(2026, 1, 20, tzinfo=timezone.utc)
    cases = [
        _case("1", "suspicious", created_at=now - timedelta(days=4)),
        _case("2", "suspicious", created_at=now - timedelta(days=2)),
    ]

    result = kris(cases, {}, now=now)

    assert result["unlabeled_count"] == 2
    assert result["labeled_count"] == 0
    assert result["mean_unlabeled_backlog_days"] == 3.0


def test_kris_mean_unlabeled_backlog_is_none_when_everything_labeled():
    cases = [_case("1", "safe")]
    labels = {"1": _label("1", "safe")}

    result = kris(cases, labels, now=datetime(2026, 1, 20, tzinfo=timezone.utc))

    assert result["mean_unlabeled_backlog_days"] is None
