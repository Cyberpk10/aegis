"""Central paths for the ML pipeline. Everything under DATA_DIR/MODELS_DIR is gitignored —
never commit raw corpus data or trained artifacts."""

from __future__ import annotations

from pathlib import Path

ML_ROOT = Path(__file__).resolve().parent.parent

DATA_DIR = ML_ROOT / "data"
RAW_DIR = DATA_DIR / "raw"
INTERIM_DIR = DATA_DIR / "interim"
PROCESSED_DIR = DATA_DIR / "processed"
MODELS_DIR = ML_ROOT / "models"

RAW_NAZARIO_DIR = RAW_DIR / "nazario"
RAW_SPAMASSASSIN_DIR = RAW_DIR / "spamassassin"
RAW_ENRON_DIR = RAW_DIR / "enron"
RAW_PHISHTANK_DIR = RAW_DIR / "phishtank"


def ensure_dirs() -> None:
    for path in (
        RAW_NAZARIO_DIR,
        RAW_SPAMASSASSIN_DIR,
        RAW_ENRON_DIR,
        RAW_PHISHTANK_DIR,
        INTERIM_DIR,
        PROCESSED_DIR,
        MODELS_DIR,
    ):
        path.mkdir(parents=True, exist_ok=True)
