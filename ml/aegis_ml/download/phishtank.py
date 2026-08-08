"""Downloads PhishTank's verified-phishing URL feed as a reference file — NOT part of the
unified email corpus.

Verified live 2026-08-07: PhishTank's API/feed provides URLs only (phish_id, url,
phish_detail_url, submission_time, verified, verification_time, online, target) — never raw
headers/subject/body/from-address, so it structurally cannot fill the common email schema.
Per an explicit product decision, it's fetched here as a standalone CSV for possible future
URL-reputation feature work (e.g. cross-referencing links found inside other emails), and is
never merged into ml/data/interim or the train/val/test parquet files.

The unauthenticated bulk feed (data.phishtank.com/data/online-valid.csv, redirects to a
signed CDN URL) worked without registration at verification time; an API key only raises
rate limits, it isn't required for this one-shot bulk fetch. Data is operated by Cisco Talos
under Cisco's general Terms of Use — see ml/corpus/sources.md.
"""

from __future__ import annotations

from pathlib import Path

import requests

from aegis_ml.paths import RAW_PHISHTANK_DIR, ensure_dirs

URL = "https://data.phishtank.com/data/online-valid.csv"
USER_AGENT = "aegis-ml-corpus-builder/0.1 (defensive-security research; contact via GitHub)"


def download_phishtank_reference() -> Path:
    ensure_dirs()
    dest = RAW_PHISHTANK_DIR / "online-valid.csv"

    resp = requests.get(URL, timeout=60, headers={"User-Agent": USER_AGENT})
    resp.raise_for_status()
    dest.write_bytes(resp.content)
    return dest
