"""`python -m aegis_ml.cli build` — orchestrates download -> normalize -> dedupe -> split ->
report for the M3 Stage 1 training corpus."""

from __future__ import annotations

import argparse

from aegis_ml.dedupe import dedupe
from aegis_ml.download.enron import DEFAULT_SAMPLE_SIZE as ENRON_DEFAULT_SAMPLE_SIZE
from aegis_ml.download.enron import download_and_sample_enron
from aegis_ml.download.nazario import download_nazario
from aegis_ml.download.phishtank import download_phishtank_reference
from aegis_ml.download.spamassassin import download_spamassassin_ham
from aegis_ml.normalize import normalize_all
from aegis_ml.report import build_report, write_and_print_report
from aegis_ml.split import DEFAULT_SEED, stratified_split, write_splits

ALL_SOURCES = ["nazario", "spamassassin", "enron", "phishtank"]


def _download(sources: list[str], enron_sample_size: int, seed: int) -> None:
    if "nazario" in sources:
        print("[cli] Downloading Nazario phishing corpus...")
        download_nazario()
    if "spamassassin" in sources:
        print("[cli] Downloading SpamAssassin ham corpus...")
        download_spamassassin_ham()
    if "enron" in sources:
        print(f"[cli] Streaming + sampling Enron corpus (n={enron_sample_size})...")
        download_and_sample_enron(sample_size=enron_sample_size, seed=seed)
    if "phishtank" in sources:
        print("[cli] Downloading PhishTank reference feed (not part of the email corpus)...")
        download_phishtank_reference()


def build(
    skip_download: bool = False,
    sources: list[str] | None = None,
    enron_sample_size: int = ENRON_DEFAULT_SAMPLE_SIZE,
    seed: int = DEFAULT_SEED,
) -> dict:
    sources = sources or ALL_SOURCES

    if not skip_download:
        _download(sources, enron_sample_size, seed)
    else:
        print("[cli] --skip-download: using whatever is already in ml/data/raw/.")

    print("[cli] Normalizing sources into the common schema...")
    frames = normalize_all()

    print("[cli] Deduping across sources...")
    deduped, dedupe_stats = dedupe(frames)

    print("[cli] Splitting train/val/test (stratified by label)...")
    splits = stratified_split(deduped, seed=seed)
    write_splits(splits)

    report = build_report(dedupe_stats, splits)
    write_and_print_report(report)
    return report


def main() -> None:
    parser = argparse.ArgumentParser(prog="aegis_ml", description="Aegis ML training corpus pipeline")
    subparsers = parser.add_subparsers(dest="command", required=True)

    build_parser = subparsers.add_parser(
        "build", help="Download, normalize, dedupe, split, and report."
    )
    build_parser.add_argument("--skip-download", action="store_true")
    build_parser.add_argument(
        "--sources",
        type=str,
        default=",".join(ALL_SOURCES),
        help="Comma-separated subset of: " + ",".join(ALL_SOURCES),
    )
    build_parser.add_argument("--enron-sample-size", type=int, default=ENRON_DEFAULT_SAMPLE_SIZE)
    build_parser.add_argument("--seed", type=int, default=DEFAULT_SEED)

    args = parser.parse_args()

    if args.command == "build":
        sources = [s.strip() for s in args.sources.split(",") if s.strip()]
        build(
            skip_download=args.skip_download,
            sources=sources,
            enron_sample_size=args.enron_sample_size,
            seed=args.seed,
        )


if __name__ == "__main__":
    main()
