"""Optional ML classifier signal (M3) — a secondary nudge on top of the primary rule-based
verdict, never a replacement for it. Mirrors app.reasoning.llm_analyst's shape exactly: gated
behind a settings flag, loads its model lazily and once, and never raises — any missing
artifact or inference failure degrades to (None, None) so callers fall back to the rule+LLM
result untouched. See app.scoring.risk_engine for the bounded blend that consumes the
probability this module returns, and ml/models/CARD.md for the model's data/metrics/limitations.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path

from app.core.config import settings
from app.ml.features import build_structured_features, feature_names
from app.models.schemas import Indicator
from app.parsing.eml_parser import ParsedEmail

_DEFAULT_ARTIFACTS_DIR = Path(__file__).parent / "artifacts"


@dataclass(frozen=True)
class LoadedModel:
    classifier: object
    vectorizer: object
    model_version: str
    feature_names: list[str]


@lru_cache(maxsize=1)
def _load_model() -> LoadedModel | None:
    """Loads the trained classifier + vectorizer + metadata once per process. Any missing file,
    unreadable JSON, or corrupt joblib is caught here (not retried per-request) and cached as
    "unavailable" — predict() then always returns (None, None) for the rest of the process
    lifetime, exactly like a missing ANTHROPIC_API_KEY degrades generate_analyst_narrative."""
    import joblib  # deferred: only import the ML runtime deps if the flag is actually on

    artifacts_dir = Path(settings.ml_artifacts_dir) if settings.ml_artifacts_dir else _DEFAULT_ARTIFACTS_DIR

    try:
        with (artifacts_dir / "metadata.json").open() as f:
            metadata = json.load(f)
        classifier = joblib.load(artifacts_dir / "classifier.joblib")
        vectorizer = joblib.load(artifacts_dir / "vectorizer.joblib")
    except Exception:  # noqa: BLE001 - missing/corrupt artifacts degrade gracefully, never crash startup
        return None

    return LoadedModel(
        classifier=classifier,
        vectorizer=vectorizer,
        model_version=metadata["model_version"],
        feature_names=metadata["feature_names"],
    )


def predict(parsed_email: ParsedEmail, indicators: list[Indicator]) -> tuple[float | None, str | None]:
    """Returns (probability, model_version), or (None, None) if the flag is off, the model
    isn't available, or inference fails for any reason. Never raises."""
    if not settings.enable_ml_classifier:
        return None, None

    model = _load_model()
    if model is None:
        return None, None

    try:
        from scipy import sparse

        structured = build_structured_features(parsed_email, indicators)
        # feature_names() must match the pinned order recorded in metadata.json at train time —
        # if backend/app/ml/features.py has changed since this model was trained, the column
        # order (and count) could silently mismatch, so this is checked rather than assumed.
        if feature_names() != model.feature_names:
            return None, None

        structured_row = [[structured[name] for name in feature_names()]]
        structured_matrix = sparse.csr_matrix(structured_row, dtype=float)

        text = f"{parsed_email.subject or ''} {parsed_email.body_text or ''}"
        tfidf_matrix = model.vectorizer.transform([text])

        X = sparse.hstack([structured_matrix, tfidf_matrix], format="csr")
        probability = float(model.classifier.predict_proba(X)[0, 1])
    except Exception:  # noqa: BLE001 - any inference failure degrades gracefully, never propagates
        return None, None

    return probability, model.model_version
