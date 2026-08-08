"""Downloads Jose Nazario's phishing corpus.

Verified 2026-08-07: the primary host (monkey.org) was unreachable from the environment
this was written in, but general internet access was fine from that same shell — likely a
sandbox-specific network policy, not the site being down. A recent (2026-06-07) Wayback
Machine snapshot of the corpus index confirmed the classic files below are still listed, so
this downloader tries monkey.org directly first and falls back to the Wayback Machine's
`/wayback/available` API (plain HTTP, no extra dependency) to resolve a snapshot per file.

Only the well-known, unambiguously-a-file classic corpus is fetched here (phishing0-3.mbox,
20051114.mbox). The index also listed yearly `phishing-2015` .. `phishing-2025` entries with
no file extension — their directory-vs-file shape wasn't confirmed, so they're intentionally
not ingested in Stage 1 (see ml/corpus/sources.md) rather than risk silently saving an HTML
directory listing as if it were mbox content.
"""

from __future__ import annotations

import time
from pathlib import Path

import requests

from aegis_ml.paths import RAW_NAZARIO_DIR, ensure_dirs

BASE_URL = "https://monkey.org/~jose/phishing/"
CORE_FILES = ["phishing0.mbox", "phishing1.mbox", "phishing2.mbox", "phishing3.mbox", "20051114.mbox"]

USER_AGENT = "aegis-ml-corpus-builder/0.1 (defensive-security research; contact via GitHub)"
_HEADERS = {"User-Agent": USER_AGENT}


def _looks_like_html(content: bytes) -> bool:
    head = content[:512].lstrip().lower()
    return head.startswith(b"<!doctype") or head.startswith(b"<html")


def _try_direct(filename: str, timeout: int = 15) -> bytes | None:
    try:
        resp = requests.get(BASE_URL + filename, timeout=timeout, headers=_HEADERS)
    except requests.RequestException:
        return None
    if resp.status_code == 200 and resp.content and not _looks_like_html(resp.content):
        return resp.content
    return None


def _try_wayback(filename: str, timeout: int = 20, retries: int = 3) -> bytes | None:
    target_url = f"monkey.org/~jose/phishing/{filename}"
    for attempt in range(retries):
        try:
            avail = requests.get(
                "https://archive.org/wayback/available",
                params={"url": target_url},
                timeout=timeout,
            )
        except requests.RequestException:
            return None
        if avail.status_code == 429:
            time.sleep(2 * (attempt + 1))
            continue
        break
    else:
        return None

    try:
        snapshot = avail.json().get("archived_snapshots", {}).get("closest")
    except ValueError:
        return None
    if not snapshot or not snapshot.get("available"):
        return None

    timestamp = snapshot["timestamp"]
    # "id_" = unmodified original bytes, no Wayback Machine HTML rewriting.
    raw_url = f"https://web.archive.org/web/{timestamp}id_/https://monkey.org/~jose/phishing/{filename}"
    try:
        resp = requests.get(raw_url, timeout=timeout, headers=_HEADERS)
    except requests.RequestException:
        return None
    if resp.status_code == 200 and resp.content and not _looks_like_html(resp.content):
        return resp.content
    return None


def download_nazario() -> list[Path]:
    """Fetches each core corpus file (skipping ones already on disk), monkey.org first,
    Wayback Machine second. Returns the list of local file paths actually available
    (partial results are fine — the pipeline works with whatever came through)."""
    ensure_dirs()
    saved: list[Path] = []

    for filename in CORE_FILES:
        dest = RAW_NAZARIO_DIR / filename
        if dest.exists():
            saved.append(dest)
            continue

        content = _try_direct(filename) or _try_wayback(filename)
        if content is None:
            print(f"[nazario] WARNING: could not fetch {filename} from monkey.org or the Wayback Machine — skipping.")
            continue

        dest.write_bytes(content)
        saved.append(dest)

    if not saved:
        print(
            "[nazario] WARNING: no Nazario corpus files were downloaded. The phishing class "
            "will have zero records from this source."
        )
    return saved
