"""M3 Stage 2/3/4: train, calibrate, evaluate, and publish the phishing classifier.

`python -m aegis_ml.train` (or `python aegis_ml/train.py` from ml/) — loads the train/val/test
splits written by `aegis_ml.split`, extracts features via `aegis_ml.features` (which re-parses
every record through the real backend pipeline — see that module's docstring), trains a
calibrated logistic regression, evaluates on the held-out test split, tunes a high-precision
decision threshold on the val split, and publishes:
  - ml/models/metrics.json, ml/models/CARD.md — documentation, committed to git.
  - backend/app/ml/artifacts/{classifier,vectorizer}.joblib + metadata.json — the actual
    binary artifacts the running backend loads (see that module's docstring for why this is a
    separate location from ml/models/: Docker's build context is backend/ only).
"""

from __future__ import annotations

import json
import sys
from datetime import datetime, timezone
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from sklearn.calibration import CalibratedClassifierCV
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
    roc_auc_score,
)

from aegis_ml.features import build_feature_matrix, extract_structured_and_text, fit_vectorizer
from aegis_ml.paths import MODELS_DIR, PROCESSED_DIR

BACKEND_ARTIFACTS_DIR = Path(__file__).resolve().parents[2] / "backend" / "app" / "ml" / "artifacts"

TARGET_PRECISION = 0.95
MODEL_VERSION_PREFIX = "m3-logreg-v1"


def _load_split(name: str) -> pd.DataFrame:
    return pd.read_parquet(PROCESSED_DIR / f"{name}.parquet")


def _labels(df: pd.DataFrame, valid_index: pd.Index) -> np.ndarray:
    return (df.loc[valid_index, "label"] == "phishing").astype(int).to_numpy()


def _class_balance(y: np.ndarray) -> dict:
    return {"phishing": int(y.sum()), "benign": int((y == 0).sum()), "total": int(len(y))}


def _sweep_thresholds(y_true: np.ndarray, y_proba: np.ndarray) -> list[dict]:
    rows = []
    for threshold in np.linspace(0.05, 0.95, 181):
        y_pred = (y_proba >= threshold).astype(int)
        if y_pred.sum() == 0:
            continue
        rows.append(
            {
                "threshold": round(float(threshold), 4),
                "precision": float(precision_score(y_true, y_pred, zero_division=0)),
                "recall": float(recall_score(y_true, y_pred, zero_division=0)),
            }
        )
    return rows


def find_high_precision_threshold(y_true: np.ndarray, y_proba: np.ndarray) -> dict:
    """The lowest threshold that clears TARGET_PRECISION (maximizes recall among qualifying
    thresholds) — favoring precision over recall is deliberate: a false positive here means an
    analyst is told a benign email is phishing, which is exactly what erodes trust in the tool
    over time. If no threshold reaches TARGET_PRECISION on this split, falls back to whichever
    threshold achieved the highest precision found, clearly flagged as such."""
    swept = _sweep_thresholds(y_true, y_proba)
    qualifying = [row for row in swept if row["precision"] >= TARGET_PRECISION]
    if qualifying:
        best = min(qualifying, key=lambda row: row["threshold"])
        return {**best, "target_precision": TARGET_PRECISION, "target_met": True}
    best = max(swept, key=lambda row: row["precision"])
    return {**best, "target_precision": TARGET_PRECISION, "target_met": False}


def build_features_for_split(df: pd.DataFrame, vectorizer=None):
    structured_df, texts, valid_index = extract_structured_and_text(df)
    if vectorizer is None:
        vectorizer = fit_vectorizer(texts)
    X = build_feature_matrix(structured_df, texts, vectorizer)
    y = _labels(df, valid_index)
    return X, y, vectorizer


def train() -> dict:
    trained_at = datetime.now(timezone.utc)
    model_version = f"{MODEL_VERSION_PREFIX}-{trained_at:%Y%m%d}"

    print("[train] Loading splits...")
    train_df, val_df, test_df = _load_split("train"), _load_split("val"), _load_split("test")

    print("[train] Extracting features (re-parsing every record through the real backend "
          "pipeline — this is the slow step)...")
    X_train, y_train, vectorizer = build_features_for_split(train_df)
    X_val, y_val, _ = build_features_for_split(val_df, vectorizer=vectorizer)
    X_test, y_test, _ = build_features_for_split(test_df, vectorizer=vectorizer)
    print(f"[train] Feature matrix: {X_train.shape[1]} columns "
          f"(train={X_train.shape[0]}, val={X_val.shape[0]}, test={X_test.shape[0]})")

    print("[train] Fitting calibrated logistic regression...")
    base_model = LogisticRegression(
        class_weight="balanced", penalty="l2", max_iter=2000, random_state=42
    )
    model = CalibratedClassifierCV(base_model, method="sigmoid", cv=5)
    model.fit(X_train, y_train)

    print("[train] Evaluating on the held-out test split...")
    test_proba = model.predict_proba(X_test)[:, 1]
    test_pred_default = (test_proba >= 0.5).astype(int)
    tn, fp, fn, tp = confusion_matrix(y_test, test_pred_default).ravel()

    test_metrics = {
        "threshold": 0.5,
        "precision": float(precision_score(y_test, test_pred_default, zero_division=0)),
        "recall": float(recall_score(y_test, test_pred_default, zero_division=0)),
        "f1": float(f1_score(y_test, test_pred_default, zero_division=0)),
        "roc_auc": float(roc_auc_score(y_test, test_proba)),
        "confusion_matrix": {
            "true_negative": int(tn), "false_positive": int(fp),
            "false_negative": int(fn), "true_positive": int(tp),
        },
    }

    print("[train] Tuning a high-precision decision threshold on the val split...")
    val_proba = model.predict_proba(X_val)[:, 1]
    recommended = find_high_precision_threshold(y_val, val_proba)

    # Same threshold, re-reported against test — informational only, never used for tuning.
    test_pred_at_recommended = (test_proba >= recommended["threshold"]).astype(int)
    recommended_on_test = {
        "precision": float(precision_score(y_test, test_pred_at_recommended, zero_division=0)),
        "recall": float(recall_score(y_test, test_pred_at_recommended, zero_division=0)),
    }

    metrics = {
        "model_version": model_version,
        "trained_at": trained_at.isoformat(),
        "model_type": "LogisticRegression(class_weight=balanced, penalty=l2) "
                       "+ CalibratedClassifierCV(method=sigmoid, cv=5)",
        "feature_space": {
            "structured_features": X_train.shape[1] - 5000 if X_train.shape[1] > 5000 else None,
            "tfidf_max_features": 5000,
            "total_features": int(X_train.shape[1]),
        },
        "corpus": {
            "train": {"size": int(len(y_train)), "class_balance": _class_balance(y_train)},
            "val": {"size": int(len(y_val)), "class_balance": _class_balance(y_val)},
            "test": {"size": int(len(y_test)), "class_balance": _class_balance(y_test)},
        },
        "test_metrics_at_default_threshold": test_metrics,
        "high_precision_threshold": {
            "tuned_on": "val split",
            **recommended,
            "precision_recall_on_test_at_this_threshold": recommended_on_test,
        },
    }

    _write_outputs(model, vectorizer, metrics)
    return metrics


def _write_outputs(model, vectorizer, metrics: dict) -> None:
    MODELS_DIR.mkdir(parents=True, exist_ok=True)
    with (MODELS_DIR / "metrics.json").open("w") as f:
        json.dump(metrics, f, indent=2)
    print(f"[train] Wrote {MODELS_DIR / 'metrics.json'}")

    BACKEND_ARTIFACTS_DIR.mkdir(parents=True, exist_ok=True)
    joblib.dump(model, BACKEND_ARTIFACTS_DIR / "classifier.joblib")
    joblib.dump(vectorizer, BACKEND_ARTIFACTS_DIR / "vectorizer.joblib")

    from app.ml.features import INDICATOR_FEATURE_IDS, feature_names  # imported via sys.path, see aegis_ml.features

    artifact_metadata = {
        "model_version": metrics["model_version"],
        "trained_at": metrics["trained_at"],
        "feature_names": feature_names(),
        "indicator_feature_ids": list(INDICATOR_FEATURE_IDS),
        "recommended_threshold": metrics["high_precision_threshold"]["threshold"],
    }
    with (BACKEND_ARTIFACTS_DIR / "metadata.json").open("w") as f:
        json.dump(artifact_metadata, f, indent=2)
    print(f"[train] Published model artifacts to {BACKEND_ARTIFACTS_DIR}")


def main() -> None:
    metrics = train()
    print("\n=== Aegis ML Classifier — training summary ===\n")
    print(f"Model version: {metrics['model_version']}")
    print(f"Test metrics (threshold=0.5): {metrics['test_metrics_at_default_threshold']}")
    print(f"High-precision threshold (tuned on val): {metrics['high_precision_threshold']}")


if __name__ == "__main__":
    sys.exit(main())
