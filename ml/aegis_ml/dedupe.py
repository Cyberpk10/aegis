"""Cross-source dedupe by a normalized subject+body hash."""

from __future__ import annotations

import hashlib
import re

import pandas as pd

from aegis_ml.paths import INTERIM_DIR, ensure_dirs
from aegis_ml.schema import EMAIL_RECORD_COLUMNS

# First-seen-wins order when the same normalized subject+body appears in multiple sources.
SOURCE_PRIORITY = ["nazario", "spamassassin", "enron"]

_WHITESPACE_RE = re.compile(r"\s+")


def dedupe_hash(subject: str, body_text: str) -> str:
    combined = f"{subject or ''}\n{body_text or ''}".lower()
    normalized = _WHITESPACE_RE.sub(" ", combined).strip()
    return hashlib.sha256(normalized.encode("utf-8")).hexdigest()


def dedupe(frames: dict[str, pd.DataFrame]) -> tuple[pd.DataFrame, dict]:
    """Returns (deduped_df, stats). Keeps the first occurrence of each duplicate hash,
    processing sources in SOURCE_PRIORITY order."""
    ordered = [frames[name] for name in SOURCE_PRIORITY if name in frames and len(frames[name])]
    if ordered:
        combined = pd.concat(ordered, ignore_index=True)
    else:
        combined = pd.DataFrame(columns=EMAIL_RECORD_COLUMNS)

    raw_counts_by_source = {k: int(v) for k, v in combined["source"].value_counts().items()}

    if len(combined):
        combined = combined.copy()
        combined["_dedupe_hash"] = [
            dedupe_hash(subject, body_text)
            for subject, body_text in zip(combined["subject"], combined["body_text"])
        ]
        is_duplicate = combined.duplicated(subset="_dedupe_hash", keep="first")
        dropped = combined[is_duplicate]
        deduped = combined[~is_duplicate].drop(columns="_dedupe_hash")
        dropped_by_source = {k: int(v) for k, v in dropped["source"].value_counts().items()}
    else:
        deduped = combined
        dropped_by_source = {}

    stats = {
        "raw_counts_by_source": raw_counts_by_source,
        "total_raw": int(len(combined)),
        "total_duplicates_dropped": int(len(combined) - len(deduped)),
        "duplicates_dropped_by_source": dropped_by_source,
        "total_deduped": int(len(deduped)),
    }

    ensure_dirs()
    deduped.to_parquet(INTERIM_DIR / "deduped.parquet", index=False)
    return deduped, stats
