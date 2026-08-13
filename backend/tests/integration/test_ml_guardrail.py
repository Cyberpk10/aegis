"""M3 guardrail: with the ML classifier live (ENABLE_ML_CLASSIFIER=true, real committed model
artifacts), every "safe"-labeled fixture must still verdict SAFE or SUSPICIOUS — never
MALICIOUS. False positives from the ML signal alone would destroy analyst trust, and
app.scoring.risk_engine's bounded blend (see test_risk_engine.py) makes this structurally
guaranteed rather than just empirically hoped for — this test exercises that guarantee
end-to-end against the real trained model rather than only the formula in isolation."""

from __future__ import annotations

import pytest

from app.ml import classifier as classifier_module
from app.models.schemas import Verdict

_ARTIFACTS_PRESENT = (
    (classifier_module._DEFAULT_ARTIFACTS_DIR / "classifier.joblib").exists()
    and (classifier_module._DEFAULT_ARTIFACTS_DIR / "vectorizer.joblib").exists()
    and (classifier_module._DEFAULT_ARTIFACTS_DIR / "metadata.json").exists()
)

_SAFE_FIXTURES = [
    "benign_newsletter.eml",
    "benign_internal_it_notice.eml",
    "benign_legit_password_reset.eml",
]


@pytest.mark.skipif(not _ARTIFACTS_PRESENT, reason="real trained model artifacts not present")
@pytest.mark.parametrize("filename", _SAFE_FIXTURES)
def test_ml_signal_never_flips_a_safe_fixture_to_malicious(
    monkeypatch, authed_client, load_eml, filename
):
    from app.core.config import settings

    monkeypatch.setattr(settings, "enable_ml_classifier", True)
    classifier_module._load_model.cache_clear()

    raw = load_eml(filename)
    response = authed_client.post(
        "/api/analyze", files={"file": (filename, raw, "message/rfc822")}
    )

    assert response.status_code == 200
    body = response.json()
    assert body["verdict"] != Verdict.MALICIOUS.value, (
        f"{filename} flipped to malicious with the ML signal live "
        f"(score={body['score']}, ml_probability={body.get('ml_probability')})"
    )
    # The ML signal is live and should populate on the response, confirming this test
    # actually exercised the real inference path rather than silently degrading.
    assert body["ml_probability"] is not None
    assert body["ml_model_version"] is not None

    classifier_module._load_model.cache_clear()
