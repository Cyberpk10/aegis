from __future__ import annotations

import pandas as pd

from aegis_ml.split import stratified_split


def _synthetic_df(n_phishing=80, n_benign=20):
    rows = [{"id": f"phish-{i}", "label": "phishing"} for i in range(n_phishing)]
    rows += [{"id": f"benign-{i}", "label": "benign"} for i in range(n_benign)]
    return pd.DataFrame(rows)


def test_stratified_split_has_no_id_overlap_and_covers_all_rows():
    df = _synthetic_df()
    splits = stratified_split(df, seed=42)

    assert set(splits.keys()) == {"train", "val", "test"}
    total = sum(len(s) for s in splits.values())
    assert total == len(df)

    ids = {name: set(s["id"]) for name, s in splits.items()}
    assert ids["train"].isdisjoint(ids["val"])
    assert ids["train"].isdisjoint(ids["test"])
    assert ids["val"].isdisjoint(ids["test"])
    assert ids["train"] | ids["val"] | ids["test"] == set(df["id"])


def test_stratified_split_preserves_label_ratio_in_each_split():
    df = _synthetic_df(n_phishing=80, n_benign=20)  # 80/20 split
    splits = stratified_split(df, seed=42)

    for split_df in splits.values():
        ratio = (split_df["label"] == "phishing").mean()
        assert 0.7 <= ratio <= 0.9


def test_stratified_split_is_deterministic_given_same_seed():
    df = _synthetic_df()
    splits_a = stratified_split(df, seed=7)
    splits_b = stratified_split(df, seed=7)

    for name in splits_a:
        assert list(splits_a[name]["id"]) == list(splits_b[name]["id"])
