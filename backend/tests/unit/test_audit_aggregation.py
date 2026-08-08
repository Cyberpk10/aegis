from __future__ import annotations

from datetime import datetime, timedelta, timezone

from app.audit.aggregation import evidence_for_framework
from app.dashboard.aggregation import CaseRow

# Real control ids/names from backend/app/mapping/frameworks/mitre_attack.yaml, same
# approach the dashboard tests took.
CONTROLS_BY_ID = {
    "T1598": {"name": "Phishing for Information", "url": None},
    "T1656": {"name": "Impersonation", "url": None},
    "T1566.002": {"name": "Phishing: Spearphishing Link", "url": None},
}


def _case(id_, verdict, control_ids, created_at=None):
    return CaseRow(
        id=id_,
        created_at=created_at or datetime(2026, 1, 15, tzinfo=timezone.utc),
        verdict=verdict,
        indicators=[],
        framework_mappings={
            "mitre_attack": [{"indicator_id": "X", "control_id": cid} for cid in control_ids]
        },
    )


def test_evidence_includes_every_control_even_with_zero_detections():
    result = evidence_for_framework([], CONTROLS_BY_ID, "mitre_attack")

    assert {e.control_id for e in result} == {"T1598", "T1656", "T1566.002"}
    for e in result:
        assert e.detection_count == 0
        assert e.operating is False
        assert e.sample_cases == []
        assert e.supporting_case_ids == []


def test_evidence_counts_supporting_cases_per_control():
    cases = [
        _case("1", "malicious", ["T1598"]),
        _case("2", "malicious", ["T1598", "T1656"]),
        _case("3", "safe", ["T1656"]),
    ]

    result = {e.control_id: e for e in evidence_for_framework(cases, CONTROLS_BY_ID, "mitre_attack")}

    assert result["T1598"].detection_count == 2
    assert result["T1598"].operating is True
    assert result["T1656"].detection_count == 2
    assert result["T1566.002"].detection_count == 0
    assert result["T1566.002"].operating is False


def test_case_counts_once_per_control_even_with_duplicate_indicator_mappings():
    # Two indicators on the same case both map to T1598 — must still count as 1.
    case = CaseRow(
        id="1",
        created_at=datetime(2026, 1, 15, tzinfo=timezone.utc),
        verdict="malicious",
        indicators=[],
        framework_mappings={
            "mitre_attack": [
                {"indicator_id": "URGENCY_LANGUAGE", "control_id": "T1598"},
                {"indicator_id": "CREDENTIAL_REQUEST", "control_id": "T1598"},
            ]
        },
    )

    result = {e.control_id: e for e in evidence_for_framework([case], CONTROLS_BY_ID, "mitre_attack")}

    assert result["T1598"].detection_count == 1
    assert result["T1598"].supporting_case_ids == ["1"]


def test_sample_cases_are_most_recent_first_and_capped_at_sample_size():
    now = datetime(2026, 1, 20, tzinfo=timezone.utc)
    cases = [
        _case(str(i), "malicious", ["T1598"], created_at=now - timedelta(days=i)) for i in range(8)
    ]

    result = {
        e.control_id: e
        for e in evidence_for_framework(cases, CONTROLS_BY_ID, "mitre_attack", sample_size=3)
    }
    evidence = result["T1598"]

    assert evidence.detection_count == 8  # full count unaffected by the sample cap
    assert len(evidence.sample_cases) == 3
    assert [s.id for s in evidence.sample_cases] == ["0", "1", "2"]  # most recent first
    assert len(evidence.supporting_case_ids) == 8  # full set, not capped


def test_cases_outside_the_framework_or_with_no_mappings_are_ignored():
    case_no_mappings = CaseRow(
        id="1",
        created_at=datetime(2026, 1, 15, tzinfo=timezone.utc),
        verdict="safe",
        indicators=[],
        framework_mappings={},
    )
    case_other_framework = CaseRow(
        id="2",
        created_at=datetime(2026, 1, 15, tzinfo=timezone.utc),
        verdict="malicious",
        indicators=[],
        framework_mappings={"nist_csf": [{"indicator_id": "X", "control_id": "PR.AT-01"}]},
    )

    result = evidence_for_framework(
        [case_no_mappings, case_other_framework], CONTROLS_BY_ID, "mitre_attack"
    )

    assert all(e.detection_count == 0 for e in result)
