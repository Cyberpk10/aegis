"""Downloads the benign ("ham") subset of the Apache SpamAssassin public corpus.

Verified live 2026-08-07 at https://spamassassin.apache.org/old/publiccorpus/ — file listing
scraped directly. Only the ham archives are fetched; the spam ones aren't needed here.
"""

from __future__ import annotations

import io
import tarfile
from pathlib import Path

import requests

from aegis_ml.paths import RAW_SPAMASSASSIN_DIR, ensure_dirs

BASE_URL = "https://spamassassin.apache.org/old/publiccorpus/"
HAM_ARCHIVES = [
    "20030228_easy_ham.tar.bz2",
    "20030228_hard_ham.tar.bz2",
    "20030228_easy_ham_2.tar.bz2",
]

USER_AGENT = "aegis-ml-corpus-builder/0.1 (defensive-security research; contact via GitHub)"


def download_spamassassin_ham() -> list[Path]:
    """Downloads + extracts each ham archive (skipping ones already extracted). Returns
    the list of extracted folder paths (e.g. RAW_SPAMASSASSIN_DIR/easy_ham)."""
    ensure_dirs()
    folders: list[Path] = []

    for archive_name in HAM_ARCHIVES:
        folder_name = archive_name.split("_", 1)[1].removesuffix(".tar.bz2")
        dest_folder = RAW_SPAMASSASSIN_DIR / folder_name
        if dest_folder.exists() and any(dest_folder.iterdir()):
            folders.append(dest_folder)
            continue

        resp = requests.get(
            BASE_URL + archive_name, timeout=60, headers={"User-Agent": USER_AGENT}
        )
        resp.raise_for_status()

        with tarfile.open(fileobj=io.BytesIO(resp.content), mode="r:bz2") as tar:
            tar.extractall(RAW_SPAMASSASSIN_DIR, filter="data")

        folders.append(dest_folder)

    return folders
