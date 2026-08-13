"""The single source of truth for turning a parsed email + its rule-based indicators into a
structured (non-text) ML feature vector (M3). Both the training pipeline (ml/aegis_ml/
features.py, imported by path — see that module's docstring) and the real-time inference path
(app.ml.classifier) call this exact function, so the structured half of the feature vector can
never drift between train and serve.

Pure and dependency-light (pydantic only, already a core backend dependency) — deliberately has
no scikit-learn/numpy import, so importing this module never requires the ML runtime deps to be
installed just to build a feature dict.
"""

from __future__ import annotations

import math

from app.channels.message import Message
from app.models.schemas import Indicator

# Pinned list of indicator ids that become structured feature columns — the 18 rule-based
# indicator ids that can actually fire on an email (app.indicators.chat_context's 3 ids are
# Slack/Teams-only and never fire for Channel.EMAIL, so they're deliberately excluded here).
# This list is versioned alongside the trained model (see app.ml.classifier's metadata check)
# — adding a new indicator rule later doesn't require an immediate retrain (the feature
# builder below defaults anything not in this list to simply not being a column at all, and
# anything in this list that didn't fire defaults to 0), it just means the model won't see the
# new signal until this list and the model are updated together.
INDICATOR_FEATURE_IDS: tuple[str, ...] = (
    "SENDER_REPLYTO_MISMATCH",
    "DISPLAY_NAME_EMAIL_MISMATCH",
    "PUNYCODE_IDN_DOMAIN",
    "LOOKALIKE_DOMAIN",
    "URGENCY_LANGUAGE",
    "CREDENTIAL_REQUEST",
    "PAYMENT_REQUEST",
    "LINK_DISPLAY_HREF_MISMATCH",
    "LINK_SHORTENER",
    "LINK_SUSPICIOUS_TLD",
    "LINK_IP_LITERAL",
    "ATTACHMENT_RISKY_EXTENSION",
    "ATTACHMENT_DOUBLE_EXTENSION",
    "ATTACHMENT_MACRO_ENABLED",
    "AUTH_SPF_FAIL",
    "AUTH_DKIM_FAIL",
    "AUTH_DMARC_FAIL",
    "AI_AUTHORED_SUSPECTED",
)


def feature_names() -> list[str]:
    """The full, ordered structured-feature column list — used to build training matrices in
    a stable column order, and persisted in the model's metadata so a mismatch between what a
    loaded model expects and what this function currently produces is detectable rather than
    silently misaligning columns (see app.ml.classifier)."""
    return [
        f"indicator_{indicator_id}" for indicator_id in INDICATOR_FEATURE_IDS
    ] + ["total_rule_score", "indicator_count", "link_count", "attachment_count", "body_length_log"]


def build_structured_features(parsed: Message, indicators: list[Indicator]) -> dict[str, float]:
    """One feature per pinned indicator id (its score if it fired, summed if it somehow fired
    more than once — no current rule does, but nothing guarantees that stays true forever —
    else 0), plus a handful of cheap aggregate signals that capture information no single
    indicator id does on its own (e.g. an email with fifteen links is more suspicious than one
    with one, even when only a single LINK_SHORTENER indicator fired)."""
    scores_by_id: dict[str, float] = {}
    for indicator in indicators:
        scores_by_id[indicator.id] = scores_by_id.get(indicator.id, 0.0) + indicator.score

    features = {
        f"indicator_{indicator_id}": scores_by_id.get(indicator_id, 0.0)
        for indicator_id in INDICATOR_FEATURE_IDS
    }
    features["total_rule_score"] = sum(indicator.score for indicator in indicators)
    features["indicator_count"] = float(len(indicators))
    features["link_count"] = float(len(parsed.links))
    features["attachment_count"] = float(len(parsed.attachments))
    # log1p rather than a raw character count — keeps magnitude comparable to the other
    # roughly-0-100-scaled features above instead of a plain body length swamping them.
    features["body_length_log"] = math.log1p(len(parsed.body_text))
    return features
