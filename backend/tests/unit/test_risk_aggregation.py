from __future__ import annotations

from datetime import datetime, timezone

from app.dashboard.aggregation import CaseRow, LabelRow
from app.risk_model.aggregation import classify_attack_type, exposure_avoided, residual_risk
from app.risk_model.assumptions import RiskModelAssumptions

PAYMENT_REQUEST = {"id": "PAYMENT_REQUEST", "title": "Payment", "category": "content", "severity": "high"}
CREDENTIAL_REQUEST = {"id": "CREDENTIAL_REQUEST", "title": "Credential", "category": "content", "severity": "high"}
URGENCY_LANGUAGE = {"id": "URGENCY_LANGUAGE", "title": "Urgency", "category": "content", "severity": "medium"}


def _case(id_, verdict, indicators=None, created_at=None):
    return CaseRow(
        id=id_,
        created_at=created_at or datetime(2026, 1, 15, tzinfo=timezone.utc),
        verdict=verdict,
        indicators=indicators or [],
        framework_mappings={},
    )


def _label(case_id, analyst_verdict, created_at=None):
    return LabelRow(
        case_id=case_id,
        analyst_verdict=analyst_verdict,
        created_at=created_at or datetime(2026, 1, 16, tzinfo=timezone.utc),
    )


def _assumptions(**overrides):
    return RiskModelAssumptions(
        bec_avg_loss_usd=overrides.get("bec_avg_loss_usd", 100000.0),
        credential_phishing_avg_loss_usd=overrides.get("credential_phishing_avg_loss_usd", 50000.0),
        generic_phishing_avg_loss_usd=overrides.get("generic_phishing_avg_loss_usd", 20000.0),
        verdict_prevention_weight_malicious=overrides.get("verdict_prevention_weight_malicious", 1.0),
        verdict_prevention_weight_suspicious=overrides.get("verdict_prevention_weight_suspicious", 0.0),
    )


def test_classify_attack_type_prioritizes_payment_over_credential():
    ids = frozenset({"PAYMENT_REQUEST", "CREDENTIAL_REQUEST"})
    assert classify_attack_type(ids) == "bec"


def test_classify_attack_type_credential_only():
    assert classify_attack_type(frozenset({"CREDENTIAL_REQUEST"})) == "credential_phishing"


def test_classify_attack_type_neither_is_generic():
    assert classify_attack_type(frozenset({"URGENCY_LANGUAGE"})) == "generic_phishing"
    assert classify_attack_type(frozenset()) == "generic_phishing"


def test_exposure_avoided_sums_malicious_cases_by_bucket():
    cases = [
        _case("1", "malicious", indicators=[PAYMENT_REQUEST]),
        _case("2", "malicious", indicators=[CREDENTIAL_REQUEST]),
        _case("3", "malicious", indicators=[URGENCY_LANGUAGE]),
        _case("4", "safe"),
    ]
    assumptions = _assumptions()

    result = exposure_avoided(cases, assumptions)

    by_type = {b["attack_type"]: b for b in result["by_attack_type"]}
    assert by_type["bec"]["count"] == 1
    assert by_type["bec"]["subtotal_usd"] == 100000.0
    assert by_type["credential_phishing"]["count"] == 1
    assert by_type["credential_phishing"]["subtotal_usd"] == 50000.0
    assert by_type["generic_phishing"]["count"] == 1
    assert by_type["generic_phishing"]["subtotal_usd"] == 20000.0
    assert result["total_usd"] == 170000.0


def test_exposure_avoided_excludes_suspicious_by_default():
    cases = [_case("1", "suspicious", indicators=[PAYMENT_REQUEST])]
    result = exposure_avoided(cases, _assumptions())
    assert result["total_usd"] == 0.0
    bec = next(b for b in result["by_attack_type"] if b["attack_type"] == "bec")
    assert bec["count"] == 0


def test_exposure_avoided_is_deterministic():
    cases = [_case("1", "malicious", indicators=[PAYMENT_REQUEST]), _case("2", "malicious", indicators=[CREDENTIAL_REQUEST])]
    assumptions = _assumptions()
    assert exposure_avoided(cases, assumptions) == exposure_avoided(cases, assumptions)


def test_changing_an_assumption_changes_only_that_buckets_output():
    cases = [
        _case("1", "malicious", indicators=[PAYMENT_REQUEST]),
        _case("2", "malicious", indicators=[CREDENTIAL_REQUEST]),
    ]
    baseline = exposure_avoided(cases, _assumptions())
    changed = exposure_avoided(cases, _assumptions(bec_avg_loss_usd=999999.0))

    baseline_by_type = {b["attack_type"]: b for b in baseline["by_attack_type"]}
    changed_by_type = {b["attack_type"]: b for b in changed["by_attack_type"]}

    assert changed_by_type["bec"]["subtotal_usd"] == 999999.0
    assert changed_by_type["bec"]["subtotal_usd"] != baseline_by_type["bec"]["subtotal_usd"]
    # Untouched bucket is unaffected.
    assert changed_by_type["credential_phishing"]["subtotal_usd"] == baseline_by_type["credential_phishing"]["subtotal_usd"]
    assert changed["total_usd"] != baseline["total_usd"]


def test_exposure_avoided_respects_configured_suspicious_weight():
    cases = [_case("1", "suspicious", indicators=[PAYMENT_REQUEST])]
    assumptions = _assumptions(verdict_prevention_weight_suspicious=0.5)

    result = exposure_avoided(cases, assumptions)

    bec = next(b for b in result["by_attack_type"] if b["attack_type"] == "bec")
    assert bec["count"] == 1
    assert bec["subtotal_usd"] == 50000.0  # 100000 * 0.5
    assert bec["prevention_weight"] == 0.5


def test_residual_risk_counts_only_analyst_confirmed_false_negatives():
    cases = [
        _case("1", "safe", indicators=[PAYMENT_REQUEST]),  # machine missed it, analyst caught it
        _case("2", "safe", indicators=[CREDENTIAL_REQUEST]),  # analyst agrees it's safe -> not counted
        _case("3", "malicious", indicators=[PAYMENT_REQUEST]),  # machine already caught it -> not a false negative
        _case("4", "suspicious", indicators=[URGENCY_LANGUAGE]),  # unlabeled -> not counted
    ]
    labels = {
        "1": _label("1", "malicious"),
        "2": _label("2", "safe"),
        "3": _label("3", "malicious"),
    }

    result = residual_risk(cases, labels, _assumptions())

    assert result["false_negative_count"] == 1
    bec = next(b for b in result["by_attack_type"] if b["attack_type"] == "bec")
    assert bec["count"] == 1
    assert bec["subtotal_usd"] == 100000.0
    assert result["total_usd"] == 100000.0
    assert "note" in result and result["note"]


def test_residual_risk_empty_when_no_false_negatives():
    cases = [_case("1", "malicious", indicators=[PAYMENT_REQUEST])]
    labels = {"1": _label("1", "malicious")}

    result = residual_risk(cases, labels, _assumptions())

    assert result["false_negative_count"] == 0
    assert result["total_usd"] == 0.0
