from __future__ import annotations

from datetime import datetime, timezone

from app.remediation.targets import TargetCaseRow, aggregate_targets


def _case(id_, verdict, to_addresses, indicators, created_at=None):
    return TargetCaseRow(
        id=id_,
        created_at=created_at or datetime(2026, 1, 1, tzinfo=timezone.utc),
        verdict=verdict,
        to_addresses=to_addresses,
        indicators=indicators,
    )


def _ind(id_, title=None):
    return {"id": id_, "title": title or id_}


def test_only_non_safe_cases_count_as_hits():
    cases = [
        _case("1", "malicious", ["alice@x.com"], [_ind("CREDENTIAL_REQUEST")]),
        _case("2", "safe", ["alice@x.com"], []),
    ]
    result = aggregate_targets(cases, threshold=1)

    assert len(result) == 1
    assert result[0].recipient == "alice@x.com"
    assert result[0].hit_count == 1


def test_hit_counts_aggregate_per_recipient_across_cases():
    cases = [
        _case("1", "malicious", ["alice@x.com", "bob@x.com"], [_ind("CREDENTIAL_REQUEST")]),
        _case("2", "suspicious", ["alice@x.com"], [_ind("URGENCY_LANGUAGE")]),
    ]
    result = {s.recipient: s for s in aggregate_targets(cases, threshold=5)}

    assert result["alice@x.com"].hit_count == 2
    assert result["bob@x.com"].hit_count == 1


def test_recipient_is_normalized_case_insensitively():
    cases = [
        _case("1", "malicious", ["Alice@X.com"], [_ind("CREDENTIAL_REQUEST")]),
        _case("2", "malicious", ["alice@x.com"], [_ind("CREDENTIAL_REQUEST")]),
    ]
    result = aggregate_targets(cases, threshold=1)

    assert len(result) == 1
    assert result[0].hit_count == 2


def test_flagged_for_training_crosses_threshold_boundary():
    cases = [
        _case(str(i), "malicious", ["alice@x.com"], [_ind("CREDENTIAL_REQUEST")]) for i in range(3)
    ]

    below = aggregate_targets(cases, threshold=4)
    assert below[0].flagged_for_training is False
    assert below[0].recommendation is None

    at_threshold = aggregate_targets(cases, threshold=3)
    assert at_threshold[0].flagged_for_training is True
    assert at_threshold[0].recommendation is not None


def test_top_tactic_is_most_frequent_indicator_across_hits():
    cases = [
        _case("1", "malicious", ["alice@x.com"], [_ind("CREDENTIAL_REQUEST", "Cred req")]),
        _case("2", "malicious", ["alice@x.com"], [_ind("CREDENTIAL_REQUEST", "Cred req")]),
        _case("3", "malicious", ["alice@x.com"], [_ind("URGENCY_LANGUAGE", "Urgency")]),
    ]
    result = aggregate_targets(cases, threshold=3)[0]

    assert result.top_indicator_id == "CREDENTIAL_REQUEST"
    assert "Cred req" in result.recommendation


def test_results_sorted_by_hit_count_descending():
    cases = [
        _case("1", "malicious", ["low@x.com"], [_ind("URGENCY_LANGUAGE")]),
        _case("2", "malicious", ["high@x.com"], [_ind("CREDENTIAL_REQUEST")]),
        _case("3", "malicious", ["high@x.com"], [_ind("CREDENTIAL_REQUEST")]),
    ]
    result = aggregate_targets(cases, threshold=99)

    assert [s.recipient for s in result] == ["high@x.com", "low@x.com"]


def test_sample_case_ids_are_most_recent_first_and_capped_at_five():
    cases = [
        _case(
            str(i),
            "malicious",
            ["alice@x.com"],
            [_ind("CREDENTIAL_REQUEST")],
            created_at=datetime(2026, 1, i + 1, tzinfo=timezone.utc),
        )
        for i in range(7)
    ]
    result = aggregate_targets(cases, threshold=1)[0]

    assert len(result.sample_case_ids) == 5
    assert result.sample_case_ids[0] == "6"  # most recent (Jan 7) first
