from __future__ import annotations

import pytest

from app.api.routes import analyze as analyze_module
from tests.conftest import FIXTURES_DIR


def _all_labeled_filenames(labeled_samples: dict[str, str]) -> list[str]:
    return sorted(labeled_samples.keys())


def test_health_check(client):
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


def test_rejects_non_eml_file(authed_client):
    response = authed_client.post(
        "/api/analyze", files={"file": ("note.txt", b"hello", "text/plain")}
    )
    assert response.status_code == 400


def test_rejects_empty_file(authed_client):
    response = authed_client.post("/api/analyze", files={"file": ("empty.eml", b"", "message/rfc822")})
    assert response.status_code == 400


@pytest.mark.parametrize(
    "filename",
    [
        "phishing_lookalike_paypal.eml",
        "phishing_bec_wire_transfer.eml",
        "phishing_shortener_credential_harvest.eml",
        "benign_newsletter.eml",
        "benign_internal_it_notice.eml",
        "benign_legit_password_reset.eml",
    ],
)
def test_labeled_samples_match_expected_verdict(authed_client, load_eml, labeled_samples, filename):
    expected_verdict = labeled_samples[filename]
    raw = load_eml(filename)

    response = authed_client.post(
        "/api/analyze", files={"file": (filename, raw, "message/rfc822")}
    )

    assert response.status_code == 200
    body = response.json()
    assert body["verdict"] == expected_verdict, (
        f"{filename}: expected {expected_verdict}, got {body['verdict']} "
        f"(score={body['score']}, indicators={[i['id'] for i in body['indicators']]})"
    )


def test_malicious_sample_has_populated_framework_mappings(authed_client, load_eml):
    raw = load_eml("phishing_lookalike_paypal.eml")
    response = authed_client.post(
        "/api/analyze", files={"file": ("phishing_lookalike_paypal.eml", raw, "message/rfc822")}
    )
    body = response.json()
    mappings = body["framework_mappings"]
    for framework_key in ("mitre_attack", "nist_csf", "iso_27001", "soc2"):
        assert len(mappings[framework_key]) > 0


def test_safe_sample_has_no_indicators(authed_client, load_eml):
    raw = load_eml("benign_newsletter.eml")
    response = authed_client.post(
        "/api/analyze", files={"file": ("benign_newsletter.eml", raw, "message/rfc822")}
    )
    body = response.json()
    assert body["indicators"] == []
    assert body["score"] == 0


def test_response_summary_reflects_auth_results(authed_client, load_eml):
    raw = load_eml("phishing_bec_wire_transfer.eml")
    response = authed_client.post(
        "/api/analyze", files={"file": ("phishing_bec_wire_transfer.eml", raw, "message/rfc822")}
    )
    body = response.json()
    assert body["summary"]["auth_results"]["spf"] == "fail"
    assert body["summary"]["from_address"] == "ceo@acmecorp-executives.com"


def test_llm_reasoning_disabled_by_default_omits_narrative(authed_client, load_eml):
    raw = load_eml("phishing_lookalike_paypal.eml")
    response = authed_client.post(
        "/api/analyze", files={"file": ("phishing_lookalike_paypal.eml", raw, "message/rfc822")}
    )
    body = response.json()
    assert body["analyst_narrative"] is None
    assert body["analyst_model"] is None


def test_llm_reasoning_enabled_populates_narrative(authed_client, load_eml, monkeypatch):
    monkeypatch.setattr(analyze_module.settings, "enable_llm_reasoning", True)

    def fake_narrative(parsed_email, indicators, score, verdict):
        return "Mocked analyst narrative describing the phishing risk.", "claude-haiku-4-5"

    monkeypatch.setattr(analyze_module, "generate_analyst_narrative", fake_narrative)

    raw = load_eml("phishing_lookalike_paypal.eml")
    response = authed_client.post(
        "/api/analyze", files={"file": ("phishing_lookalike_paypal.eml", raw, "message/rfc822")}
    )

    assert response.status_code == 200
    body = response.json()
    assert body["analyst_narrative"] == "Mocked analyst narrative describing the phishing risk."
    assert body["analyst_model"] == "claude-haiku-4-5"
    # The rule-based result is untouched by the LLM layer.
    assert body["verdict"] == "malicious"
    assert body["score"] == 100


def test_llm_reasoning_enabled_without_api_key_returns_null_narrative(authed_client, load_eml, monkeypatch):
    monkeypatch.setattr(analyze_module.settings, "enable_llm_reasoning", True)
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)

    raw = load_eml("benign_newsletter.eml")
    response = authed_client.post(
        "/api/analyze", files={"file": ("benign_newsletter.eml", raw, "message/rfc822")}
    )

    assert response.status_code == 200
    body = response.json()
    assert body["analyst_narrative"] is None
    assert body["analyst_model"] is None
    assert body["verdict"] == "safe"


def test_analyze_persists_a_retrievable_case(authed_client, load_eml):
    raw = load_eml("phishing_lookalike_paypal.eml")
    analyze_response = authed_client.post(
        "/api/analyze", files={"file": ("phishing_lookalike_paypal.eml", raw, "message/rfc822")}
    )
    assert analyze_response.status_code == 200
    analyze_body = analyze_response.json()
    assert analyze_body["id"]
    assert analyze_body["created_at"]

    case_response = authed_client.get(f"/api/cases/{analyze_body['id']}")
    assert case_response.status_code == 200
    case_body = case_response.json()

    assert case_body["id"] == analyze_body["id"]
    assert case_body["verdict"] == analyze_body["verdict"]
    assert case_body["score"] == analyze_body["score"]
    assert case_body["indicators"] == analyze_body["indicators"]
    assert case_body["framework_mappings"] == analyze_body["framework_mappings"]
    assert case_body["filename"] == "phishing_lookalike_paypal.eml"
    assert case_body["from_addr"] == analyze_body["summary"]["from_address"]
    assert case_body["subject"] == analyze_body["summary"]["subject"]
