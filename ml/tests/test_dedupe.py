from __future__ import annotations

import pandas as pd

from aegis_ml.dedupe import dedupe, dedupe_hash


def _row(id_, subject, body_text, source, label="phishing"):
    return {
        "id": id_,
        "raw_headers": "",
        "subject": subject,
        "body_text": body_text,
        "from_addr": None,
        "label": label,
        "source": source,
    }


def test_dedupe_hash_ignores_case_and_whitespace_differences():
    a = dedupe_hash("Hello World", "Please   verify   now")
    b = dedupe_hash("  hello world  ", "please verify now")
    assert a == b


def test_dedupe_drops_cross_source_duplicate_keeping_source_priority():
    frames = {
        "nazario": pd.DataFrame(
            [_row("a", "Hello World", "Body text here", "nazario")]
        ),
        "spamassassin": pd.DataFrame(
            [
                _row("b", "hello   world", "BODY TEXT HERE", "spamassassin", label="benign"),
                _row("c", "Totally different", "Not a duplicate", "spamassassin", label="benign"),
            ]
        ),
    }

    deduped, stats = dedupe(frames)

    assert set(deduped["id"]) == {"a", "c"}
    assert stats["total_raw"] == 3
    assert stats["total_duplicates_dropped"] == 1
    assert stats["duplicates_dropped_by_source"] == {"spamassassin": 1}
    assert stats["total_deduped"] == 2


def test_dedupe_handles_empty_frames():
    deduped, stats = dedupe({"nazario": pd.DataFrame(columns=["id", "subject", "body_text", "source", "label"])})
    assert len(deduped) == 0
    assert stats["total_deduped"] == 0
