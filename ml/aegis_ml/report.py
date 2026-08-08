"""Class balance, per-source/per-split counts, and dedupe stats — the required Stage 1
report."""

from __future__ import annotations

import json

import pandas as pd

from aegis_ml.paths import PROCESSED_DIR


def _class_balance(df: pd.DataFrame) -> dict:
    total = len(df)
    counts = {k: int(v) for k, v in df["label"].value_counts().items()} if total else {}
    pct = {k: round(100 * v / total, 2) for k, v in counts.items()} if total else {}
    return {"total": int(total), "counts": counts, "pct": pct}


def build_report(dedupe_stats: dict, splits: dict[str, pd.DataFrame]) -> dict:
    all_rows = pd.concat(splits.values(), ignore_index=True) if splits else pd.DataFrame()
    return {
        "dedupe": dedupe_stats,
        "overall_class_balance": _class_balance(all_rows),
        "splits": {
            name: {"size": len(df), "class_balance": _class_balance(df)}
            for name, df in splits.items()
        },
    }


def write_and_print_report(report: dict) -> None:
    PROCESSED_DIR.mkdir(parents=True, exist_ok=True)
    with (PROCESSED_DIR / "corpus_report.json").open("w") as f:
        json.dump(report, f, indent=2)

    dedupe = report["dedupe"]
    print("\n=== Aegis ML Corpus Report ===\n")
    print(f"Raw counts by source:            {dedupe['raw_counts_by_source']}")
    print(f"Total raw records:                {dedupe['total_raw']}")
    print(
        f"Duplicates dropped:               {dedupe['total_duplicates_dropped']} "
        f"(by source: {dedupe['duplicates_dropped_by_source']})"
    )
    print(f"Deduped total:                     {dedupe['total_deduped']}")

    balance = report["overall_class_balance"]
    print(f"\nOverall class balance: {balance['counts']} ({balance['pct']}%)\n")

    for split_name, info in report["splits"].items():
        cb = info["class_balance"]
        print(f"  {split_name:>5}: {info['size']:>6} records — {cb['counts']} ({cb['pct']}%)")
    print()
