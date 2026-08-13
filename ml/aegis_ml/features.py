"""Training-side feature extraction (M3) — imports the REAL backend parsing/indicator code by
path (not a reimplementation), so features computed here are guaranteed identical in shape to
what backend.app.ml.classifier computes at real inference time. This is why every EmailRecord
carries raw_bytes (see aegis_ml.schema) — everything below is derived from re-parsing those
bytes through app.parsing.eml_parser.parse_eml(), never from this package's own corpus-assembly
fields (EmailRecord.subject/body_text exist only for dedupe/debugging, not for features).

Requires pydantic/pyyaml/python-dotenv installed in this environment (see pyproject.toml) even
though aegis_ml never imports them directly — they're transitive dependencies of the backend
modules imported below.
"""

from __future__ import annotations

import sys
from pathlib import Path

_BACKEND_DIR = Path(__file__).resolve().parents[2] / "backend"
if str(_BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(_BACKEND_DIR))

import pandas as pd  # noqa: E402
from scipy import sparse  # noqa: E402
from sklearn.feature_extraction.text import TfidfVectorizer  # noqa: E402

from app.indicators.engine import run_indicators  # noqa: E402
from app.ml.features import build_structured_features, feature_names  # noqa: E402
from app.parsing.eml_parser import parse_eml  # noqa: E402

TFIDF_MAX_FEATURES = 5000


def extract_structured_and_text(df: pd.DataFrame) -> tuple[pd.DataFrame, list[str], pd.Index]:
    """Re-parses every record's raw_bytes through the real backend pipeline. Returns
    (structured_features_df, text_for_tfidf, valid_index) — text_for_tfidf is `subject + " " +
    body_text` taken from the SAME parse_eml() call that produced the structured features, not
    the corpus's own separately-reconstructed columns, so nothing here can silently diverge
    from what a real inference-time request would see. valid_index is the subset of df.index
    that parsed successfully — a handful of real-world corpus messages can be malformed enough
    that even the lenient stdlib email parser chokes; those are skipped, not fatal, and the
    caller re-aligns labels via `df.loc[valid_index]` rather than assuming positional alignment."""
    structured_rows: list[dict[str, float]] = []
    texts: list[str] = []
    valid_positions: list[int] = []

    for position, raw_bytes in enumerate(df["raw_bytes"]):
        try:
            parsed = parse_eml(raw_bytes)
            indicators = run_indicators(parsed)
        except Exception:  # noqa: BLE001 - a handful of malformed corpus messages is expected
            continue
        structured_rows.append(build_structured_features(parsed, indicators))
        texts.append(f"{parsed.subject or ''} {parsed.body_text or ''}")
        valid_positions.append(position)

    valid_index = df.index[valid_positions]
    structured_df = pd.DataFrame(structured_rows, columns=feature_names(), index=valid_index)
    return structured_df, texts, valid_index


def fit_vectorizer(texts: list[str]) -> TfidfVectorizer:
    """Fit ONLY ever on the train split's text — see aegis_ml/split.py's leakage note. Val/test
    text is transformed with this same fitted vectorizer (see build_feature_matrix), never
    refit."""
    vectorizer = TfidfVectorizer(max_features=TFIDF_MAX_FEATURES, stop_words="english")
    vectorizer.fit(texts)
    return vectorizer


def build_feature_matrix(
    structured_df: pd.DataFrame, texts: list[str], vectorizer: TfidfVectorizer
) -> sparse.csr_matrix:
    """Combines the structured (dense-ish, ~23 cols) and TF-IDF (sparse, up to 5000 cols)
    halves into one matrix in a fixed column order: structured columns first (in
    app.ml.features.feature_names() order), then TF-IDF — app.ml.classifier must build
    vectors in this exact same order at inference time."""
    tfidf_matrix = vectorizer.transform(texts)
    structured_matrix = sparse.csr_matrix(structured_df.to_numpy(dtype=float))
    return sparse.hstack([structured_matrix, tfidf_matrix], format="csr")
