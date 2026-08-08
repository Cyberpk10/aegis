"""Stratified train/val/test split, run AFTER dedupe and before any feature fitting — no
vectorizer or corpus-wide statistic is computed anywhere in this pipeline. Whatever fits
features in a later M3 stage must fit only on the train split written here."""

from __future__ import annotations

import pandas as pd
from sklearn.model_selection import train_test_split

from aegis_ml.paths import PROCESSED_DIR, ensure_dirs

DEFAULT_SEED = 42
TRAIN_FRAC = 0.7
VAL_FRAC = 0.15
TEST_FRAC = 0.15


def stratified_split(df: pd.DataFrame, seed: int = DEFAULT_SEED) -> dict[str, pd.DataFrame]:
    train_df, temp_df = train_test_split(
        df, test_size=(VAL_FRAC + TEST_FRAC), stratify=df["label"], random_state=seed
    )
    val_df, test_df = train_test_split(
        temp_df,
        test_size=TEST_FRAC / (VAL_FRAC + TEST_FRAC),
        stratify=temp_df["label"],
        random_state=seed,
    )
    return {
        "train": train_df.reset_index(drop=True),
        "val": val_df.reset_index(drop=True),
        "test": test_df.reset_index(drop=True),
    }


def write_splits(splits: dict[str, pd.DataFrame]) -> None:
    ensure_dirs()
    for name, split_df in splits.items():
        split_df.to_parquet(PROCESSED_DIR / f"{name}.parquet", index=False)
