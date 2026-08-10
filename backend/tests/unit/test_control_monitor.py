from __future__ import annotations

from datetime import datetime, timedelta, timezone

from app.mapping import framework_mapper
from app.monitoring.control_monitor import (
    STATUS_DEGRADED,
    STATUS_NO_EVIDENCE,
    STATUS_OPERATING,
    STATUS_STALE,
    CaseIndicatorRow,
    ControlHealth,
    EvidenceRow,
    auth_pass_rate_drift,
    control_health,
    coverage_drift,
    went_quiet_alerts,
)

_NOW = datetime(2026, 1, 30, tzinfo=timezone.utc)
_FRAMEWORK_KEY = "fw"
_CONTROLS = {
    "A1": {"id": "A1", "name": "Control A1", "url": None},
    "A2": {"id": "A2", "name": "Control A2", "url": None},
    "A3": {"id": "A3", "name": "Control A3", "url": None},
    "A4": {"id": "A4", "name": "Control A4", "url": None},
}
_DEFAULT_INTERVAL_DAYS = 14
_STALE_MULTIPLIER = 3.0  # stale boundary at 42 days


def _evidence(days_ago: int, control_ids: list[str]) -> EvidenceRow:
    return EvidenceRow(
        occurred_at=_NOW - timedelta(days=days_ago),
        framework_mappings={_FRAMEWORK_KEY: [{"control_id": cid} for cid in control_ids]},
    )


def _health(**kwargs) -> list[ControlHealth]:
    return control_health(
        list(kwargs.get("evidence", [])),
        _CONTROLS,
        _FRAMEWORK_KEY,
        _NOW,
        default_interval_days=_DEFAULT_INTERVAL_DAYS,
        stale_multiplier=_STALE_MULTIPLIER,
    )


def test_control_with_recent_evidence_is_operating():
    evidence = [_evidence(5, ["A1"])]
    health = _health(evidence=evidence)
    a1 = next(c for c in health if c.control_id == "A1")
    assert a1.status == STATUS_OPERATING
    assert a1.evidence_count == 1
    assert a1.last_evidence_at == _NOW - timedelta(days=5)


def test_control_with_aging_evidence_is_degraded():
    evidence = [_evidence(20, ["A2"])]  # 14 < 20 <= 42
    health = _health(evidence=evidence)
    a2 = next(c for c in health if c.control_id == "A2")
    assert a2.status == STATUS_DEGRADED


def test_control_with_very_old_evidence_is_stale():
    evidence = [_evidence(50, ["A3"])]  # 50 > 42
    health = _health(evidence=evidence)
    a3 = next(c for c in health if c.control_id == "A3")
    assert a3.status == STATUS_STALE


def test_control_with_no_evidence_ever_is_no_evidence():
    health = _health(evidence=[_evidence(5, ["A1"])])
    a4 = next(c for c in health if c.control_id == "A4")
    assert a4.status == STATUS_NO_EVIDENCE
    assert a4.evidence_count == 0
    assert a4.last_evidence_at is None


def test_went_quiet_flags_degraded_and_stale_controls_that_had_evidence():
    evidence = [_evidence(5, ["A1"]), _evidence(20, ["A2"]), _evidence(50, ["A3"])]
    health = _health(evidence=evidence)
    alerts = went_quiet_alerts(health)
    flagged = {a.control_id: a for a in alerts}

    assert set(flagged) == {"A2", "A3"}
    assert flagged["A2"].severity == "medium"
    assert flagged["A3"].severity == "high"
    assert flagged["A2"].since == _NOW - timedelta(days=20)


def test_went_quiet_never_flags_a_control_that_never_had_evidence():
    health = _health(evidence=[_evidence(5, ["A1"])])
    alerts = went_quiet_alerts(health)
    assert "A4" not in {a.control_id for a in alerts}


def _auth_cases(total: int, fail_count: int, indicator_id: str) -> list[CaseIndicatorRow]:
    rows = []
    for i in range(total):
        indicator_ids = [indicator_id] if i < fail_count else []
        rows.append(CaseIndicatorRow(created_at=_NOW, indicator_ids=indicator_ids))
    return rows


def test_auth_pass_rate_drift_fires_when_dmarc_fail_rate_rises():
    nist = framework_mapper.get_framework("nist_csf")
    assert nist is not None

    recent = _auth_cases(10, 6, "AUTH_DMARC_FAIL")  # 40% pass rate
    prior = _auth_cases(10, 1, "AUTH_DMARC_FAIL")  # 90% pass rate

    alerts = auth_pass_rate_drift(
        recent,
        prior,
        "nist_csf",
        nist.controls_by_id,
        _NOW,
        min_sample=5,
        drop_threshold=0.15,
    )

    assert alerts
    assert all(a.type == "auth_pass_rate_drop" for a in alerts)
    assert all(a.framework_key == "nist_csf" for a in alerts)
    assert all(a.since == _NOW for a in alerts)
    expected_controls = {
        ref.control_id
        for ref in framework_mapper.map_indicators(["AUTH_DMARC_FAIL"])["nist_csf"]
    }
    assert {a.control_id for a in alerts} == expected_controls


def test_auth_pass_rate_drift_skips_below_min_sample():
    nist = framework_mapper.get_framework("nist_csf")
    assert nist is not None

    recent = _auth_cases(3, 3, "AUTH_DMARC_FAIL")  # tiny sample, would otherwise look severe
    prior = _auth_cases(3, 0, "AUTH_DMARC_FAIL")

    alerts = auth_pass_rate_drift(
        recent, prior, "nist_csf", nist.controls_by_id, _NOW, min_sample=5, drop_threshold=0.15
    )
    assert alerts == []


def test_auth_pass_rate_drift_skips_below_drop_threshold():
    nist = framework_mapper.get_framework("nist_csf")
    assert nist is not None

    recent = _auth_cases(10, 1, "AUTH_DMARC_FAIL")  # 90% pass
    prior = _auth_cases(10, 0, "AUTH_DMARC_FAIL")  # 100% pass — only a 10pt drop

    alerts = auth_pass_rate_drift(
        recent, prior, "nist_csf", nist.controls_by_id, _NOW, min_sample=5, drop_threshold=0.15
    )
    assert alerts == []


def _coverage_health(statuses: list[str]) -> list[ControlHealth]:
    return [
        ControlHealth(
            framework_key=_FRAMEWORK_KEY,
            control_id=f"C{i}",
            control_name=f"Control {i}",
            status=status,
            last_evidence_at=None,
            evidence_count=0,
            expected_interval_days=_DEFAULT_INTERVAL_DAYS,
        )
        for i, status in enumerate(statuses)
    ]


def test_coverage_drift_fires_when_operating_share_drops():
    recent = _coverage_health([STATUS_OPERATING, STATUS_STALE, STATUS_STALE, STATUS_STALE])  # 25%
    prior = _coverage_health([STATUS_OPERATING, STATUS_OPERATING, STATUS_OPERATING, STATUS_STALE])  # 75%

    alert = coverage_drift(
        recent, prior, _FRAMEWORK_KEY, "Fake Framework", _NOW, comparison_days=30, drop_threshold=0.10
    )

    assert alert is not None
    assert alert.type == "coverage_drop"
    assert alert.framework_key == _FRAMEWORK_KEY


def test_coverage_drift_does_not_fire_when_coverage_is_stable():
    recent = _coverage_health([STATUS_OPERATING, STATUS_OPERATING, STATUS_OPERATING, STATUS_STALE])
    prior = _coverage_health([STATUS_OPERATING, STATUS_OPERATING, STATUS_OPERATING, STATUS_STALE])

    alert = coverage_drift(
        recent, prior, _FRAMEWORK_KEY, "Fake Framework", _NOW, comparison_days=30, drop_threshold=0.10
    )

    assert alert is None
