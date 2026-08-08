"""Streams the Enron corpus tar.gz and reservoir-samples a benign email subset — never
extracts the full ~500k-message archive to disk.

Verified live 2026-08-07: https://www.cs.cmu.edu/~enron/enron_mail_20150507.tar.gz,
423,254,787 bytes, no auth required. Released into the public record via the FERC
litigation; no explicit license. The page asks users to "be sensitive to the privacy of
the people involved" — see ml/corpus/sources.md.

Only messages under each custodian's `_sent_mail/` folder are sampled (mail the custodian
personally wrote, not inbox/received mail) — a cleaner "legitimate business email" signal.
The ~423MB still has to come over the wire once; CMU doesn't offer partial/range downloads
of a subset, so this is the minimum bandwidth cost for any subset of this corpus.
"""

from __future__ import annotations

import random
import tarfile
from pathlib import Path

import requests

from aegis_ml.paths import RAW_ENRON_DIR, ensure_dirs

URL = "https://www.cs.cmu.edu/~enron/enron_mail_20150507.tar.gz"
USER_AGENT = "aegis-ml-corpus-builder/0.1 (defensive-security research; contact via GitHub)"

DEFAULT_SAMPLE_SIZE = 6000
DEFAULT_SEED = 42


def download_and_sample_enron(
    sample_size: int = DEFAULT_SAMPLE_SIZE, seed: int = DEFAULT_SEED
) -> list[Path]:
    ensure_dirs()
    existing = sorted(RAW_ENRON_DIR.glob("*.eml"))
    if len(existing) >= sample_size:
        return existing[:sample_size]

    rng = random.Random(seed)
    reservoir: list[tuple[str, bytes]] = []
    seen = 0

    resp = requests.get(URL, stream=True, timeout=120, headers={"User-Agent": USER_AGENT})
    resp.raise_for_status()
    resp.raw.decode_content = True

    with tarfile.open(fileobj=resp.raw, mode="r|gz") as tar:
        for member in tar:
            if not member.isfile() or "_sent_mail/" not in member.name:
                continue
            extracted = tar.extractfile(member)
            if extracted is None:
                continue
            content = extracted.read()

            if len(reservoir) < sample_size:
                reservoir.append((member.name, content))
            else:
                j = rng.randint(0, seen)
                if j < sample_size:
                    reservoir[j] = (member.name, content)
            seen += 1

    saved: list[Path] = []
    for member_name, content in reservoir:
        safe_name = member_name.replace("/", "__")
        dest = RAW_ENRON_DIR / f"{safe_name}.eml"
        dest.write_bytes(content)
        saved.append(dest)

    return saved
