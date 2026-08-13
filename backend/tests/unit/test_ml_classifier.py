from __future__ import annotations

import pytest

from app.core.config import settings
from app.ml import classifier
from app.parsing.eml_parser import ParsedEmail

_ARTIFACTS_PRESENT = (
    (classifier._DEFAULT_ARTIFACTS_DIR / "classifier.joblib").exists()
    and (classifier._DEFAULT_ARTIFACTS_DIR / "vectorizer.joblib").exists()
    and (classifier._DEFAULT_ARTIFACTS_DIR / "metadata.json").exists()
)


def test_flag_off_returns_none_without_loading_model(monkeypatch):
    monkeypatch.setattr(settings, "enable_ml_classifier", False)

    def fail_if_called():
        raise AssertionError("_load_model should never be called when the flag is off")

    monkeypatch.setattr(classifier, "_load_model", fail_if_called)

    probability, model_version = classifier.predict(ParsedEmail(body_text="hello"), [])
    assert (probability, model_version) == (None, None)


def test_missing_model_files_degrades_gracefully(monkeypatch, tmp_path):
    monkeypatch.setattr(settings, "enable_ml_classifier", True)
    monkeypatch.setattr(settings, "ml_artifacts_dir", str(tmp_path / "does-not-exist"))
    classifier._load_model.cache_clear()

    probability, model_version = classifier.predict(ParsedEmail(body_text="hello"), [])
    assert (probability, model_version) == (None, None)
    classifier._load_model.cache_clear()


def test_inference_failure_degrades_gracefully(monkeypatch):
    monkeypatch.setattr(settings, "enable_ml_classifier", True)

    class _ExplodingModel:
        def predict_proba(self, X):
            raise RuntimeError("simulated inference failure")

    fake_model = classifier.LoadedModel(
        classifier=_ExplodingModel(),
        vectorizer=None,
        model_version="test-version",
        feature_names=classifier.feature_names(),
    )
    monkeypatch.setattr(classifier, "_load_model", lambda: fake_model)

    probability, model_version = classifier.predict(ParsedEmail(body_text="hello"), [])
    assert (probability, model_version) == (None, None)


def test_feature_name_mismatch_degrades_gracefully(monkeypatch):
    """If backend/app/ml/features.py has changed since a model was trained, its pinned
    feature_names() list (recorded in metadata.json at train time) won't match the current
    live list — this must be caught, not silently misalign columns."""
    monkeypatch.setattr(settings, "enable_ml_classifier", True)

    fake_model = classifier.LoadedModel(
        classifier=object(),
        vectorizer=object(),
        model_version="stale-version",
        feature_names=["some", "outdated", "list"],
    )
    monkeypatch.setattr(classifier, "_load_model", lambda: fake_model)

    probability, model_version = classifier.predict(ParsedEmail(body_text="hello"), [])
    assert (probability, model_version) == (None, None)


@pytest.mark.skipif(not _ARTIFACTS_PRESENT, reason="real trained model artifacts not present")
def test_real_model_returns_a_probability_in_range(monkeypatch):
    monkeypatch.setattr(settings, "enable_ml_classifier", True)
    classifier._load_model.cache_clear()

    probability, model_version = classifier.predict(
        ParsedEmail(subject="Verify your account now", body_text="Click here to confirm."), []
    )

    assert probability is not None
    assert 0.0 <= probability <= 1.0
    assert model_version is not None
    classifier._load_model.cache_clear()
