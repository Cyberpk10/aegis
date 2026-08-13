"""Parses the Enron corpus subset: individual raw RFC822 message files (one per file,
Maildir-style) sampled out of the source tar.gz by aegis_ml.download.enron."""

from __future__ import annotations

import email
from collections.abc import Iterator
from pathlib import Path

from aegis_ml.parsers._common import record_from_message
from aegis_ml.schema import EmailRecord, Label, Source


def iter_maildir_records(directory: Path, *, source: Source, label: Label) -> Iterator[EmailRecord]:
    for path in sorted(directory.iterdir()):
        if not path.is_file():
            continue
        raw_bytes = path.read_bytes()
        msg = email.message_from_bytes(raw_bytes)
        yield record_from_message(
            msg, source=source, label=label, original_id=path.name, raw_bytes=raw_bytes
        )
