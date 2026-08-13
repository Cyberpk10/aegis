# Aegis phishing classifier — model card

**Version**: `m3-logreg-v1-20260812` · see `metrics.json` in this directory for the full
machine-readable evaluation. Published artifacts (`classifier.joblib`, `vectorizer.joblib`,
`metadata.json`) live in `backend/app/ml/artifacts/` — see that directory's note on why, and
`backend/app/ml/classifier.py` for how they're loaded at inference time.

## What this is

A secondary ML signal that nudges Aegis's rule-based phishing risk score, gated behind
`ENABLE_ML_CLASSIFIER` (default off). It is **not** a standalone verdict engine — the rule-based
indicator engine (`backend/app/indicators/`) remains the primary decision surface. See
`backend/app/scoring/risk_engine.py` for the bounded blend formula that makes this structurally
true (the ML signal alone can never push a case from `SAFE` to `MALICIOUS`).

## Data

Trained on the corpus assembled in `ml/aegis_ml/` — see `ml/corpus/sources.md` for full
provenance/licensing. Summary (post-dedupe, stratified 70/15/15 split, split before any feature
fitting to avoid leakage):

| split | total | phishing | benign |
|-------|------:|---------:|-------:|
| train | 8,130 |    1,068 |  7,062 |
| val   | 1,743 |      230 |  1,513 |
| test  | 1,744 |      230 |  1,514 |

Sources: Nazario phishing corpus (phishing), SpamAssassin public corpus ham subset + an Enron
`_sent_mail` sample (benign). Class imbalance (~13% phishing) reflects the real-world sources
rather than synthetic rebalancing; `class_weight="balanced"` is used at training time to
compensate.

## Features

Two halves, concatenated into one sparse matrix (`backend/app/ml/features.py` is the single
source of truth for the structured half — shared by training and real-time inference, so it
cannot drift):

- **Structured (23 columns)**: one feature per email-relevant rule-based indicator id (its score
  if it fired, else 0 — see `INDICATOR_FEATURE_IDS` in `backend/app/ml/features.py`), plus
  `total_rule_score`, `indicator_count`, `link_count`, `attachment_count`, `body_length_log`.
- **Text (up to 5,000 columns)**: TF-IDF over `subject + " " + body_text`, English stop words
  removed, fit **only on the train split** (`ml/aegis_ml/features.py::fit_vectorizer`) — val/test
  are only ever transformed with this fitted vectorizer, never refit, to avoid leakage.

Every record is re-parsed from its raw original bytes through the real backend parser
(`app.parsing.eml_parser.parse_eml`) and indicator engine (`app.indicators.engine.run_indicators`)
before feature extraction — not reconstructed from the corpus's own lightweight fields — so
training-time features are guaranteed identical in shape and derivation to what a live request
produces.

## Model

`LogisticRegression(class_weight="balanced", penalty="l2")` wrapped in
`CalibratedClassifierCV(method="sigmoid", cv=5)` for well-calibrated probabilities (chosen over
gradient boosting: the feature space is TF-IDF-dominated — thousands of sparse dimensions — which
a linear model fits and calibrates more predictably than a tree ensemble, without adding a new
third-party boosting dependency).

## Evaluation (held-out test split, never touched during training or threshold tuning)

At the default 0.5 probability threshold:

| metric | value |
|---|---|
| precision (phishing) | 0.991 |
| recall (phishing)    | 0.952 |
| F1 (phishing)         | 0.971 |
| ROC-AUC                | 0.995 |

Confusion matrix: TN=1512, FP=2, FN=11, TP=219.

### High-precision decision threshold

Tuned on the **val** split (not test, to avoid tuning-on-test leakage) as the lowest probability
cutoff that clears a phishing-class precision target of ≥0.95 — chosen because a false positive
here means telling an analyst a benign email is phishing, which is what erodes trust in the tool
fastest, so precision is favored over recall when trading off.

- **Threshold: 0.16** — val precision 0.954, recall 0.987 (target met).
- Re-reported on test (informational only, not used for tuning): precision 0.941, recall 0.978.

This threshold is for anyone wanting to use the model as a standalone high-precision gate — it is
**not** the mechanism used by the backend integration, which blends the raw probability directly
into the risk score via a bounded, symmetric nudge (see `risk_engine.py`) rather than a hard
cutoff.

## Limitations

- Trained on public corpora from the 2000s–2015 era (Nazario, SpamAssassin, Enron); phishing
  tactics have evolved since (e.g. QR-code phishing, AI-generated lures) and this model has not
  seen those patterns directly — the structured indicator features (lookalike domains, auth
  failures, urgency language, etc.) generalize better than the TF-IDF text half, which is more
  tied to this specific corpus's vocabulary and era.
- Binary label only (`phishing` / `benign`) — no public source provides a `suspicious` middle
  class, so this model cannot itself distinguish "borderline" from "clearly benign."
- English-language text bias — TF-IDF stop words and the source corpora are English-only;
  non-English phishing emails will get little signal from the text half.
- Small positive class in absolute terms (1,068 train / 230 val / 230 test phishing examples) —
  precision/recall estimates on rare sub-patterns within phishing (e.g. a specific brand
  impersonation) carry more uncertainty than the aggregate numbers above suggest.
- `from_addr` may be unreliable for a small fraction of Enron messages per a documented header-
  spoofing caveat in `ml/corpus/sources.md` — this affects a benign-class feature only, not the
  phishing class.

## Intended use

A secondary, bounded signal inside Aegis's existing rule-based email risk scoring — never a
replacement for the indicator engine, and never exposed as a standalone verdict. Retrain (and
re-publish this card) whenever `backend/app/indicators/` gains or changes rules that the
structured feature list depends on, or when the corpus is meaningfully refreshed with more recent
phishing samples.
