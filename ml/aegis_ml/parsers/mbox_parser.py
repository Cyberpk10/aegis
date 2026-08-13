"""Parses mbox-format archives (Nazario phishing corpus, SpamAssassin ham corpus)."""

from __future__ import annotations

import mailbox
from collections.abc import Iterator
from pathlib import Path

from aegis_ml.parsers._common import record_from_message
from aegis_ml.schema import EmailRecord, Label, Source


def iter_mbox_records(path: Path, *, source: Source, label: Label) -> Iterator[EmailRecord]:
    """Yields one EmailRecord per message in an mbox file. `mailbox.mbox` hands back fully
    parsed `email.message.Message` objects, not a clean byte-exact single-message slice of
    the archive — `.as_bytes()` is a faithful re-serialization (preserves MIME structure,
    headers, attachments) and is what gets stored as raw_bytes, since that's what actually
    matters for a later re-parse through the real indicator engine to work correctly."""
    box = mailbox.mbox(str(path), create=False)
    try:
        for index, msg in enumerate(box):
            original_id = msg.get("Message-ID") or f"{path.name}:{index}"
            yield record_from_message(
                msg, source=source, label=label, original_id=original_id, raw_bytes=msg.as_bytes()
            )
    finally:
        box.close()


def iter_single_message_dir_records(
    directory: Path, *, source: Source, label: Label
) -> Iterator[EmailRecord]:
    """SpamAssassin's public corpus ships one raw RFC822 message per file (not an mbox
    archive) — this reads a directory of those files."""
    import email

    for path in sorted(directory.iterdir()):
        if not path.is_file() or path.name == "cmds":
            # "cmds" is a SpamAssassin public-corpus artifact (a shell-command log for
            # corpus maintainers), not an email message.
            continue
        raw_bytes = path.read_bytes()
        msg = email.message_from_bytes(raw_bytes)
        yield record_from_message(
            msg,
            source=source,
            label=label,
            original_id=f"{directory.name}/{path.name}",
            raw_bytes=raw_bytes,
        )
