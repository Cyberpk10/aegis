"""Parses mbox-format archives (Nazario phishing corpus, SpamAssassin ham corpus)."""

from __future__ import annotations

import mailbox
from collections.abc import Iterator
from pathlib import Path

from aegis_ml.parsers._common import record_from_message
from aegis_ml.schema import EmailRecord, Label, Source


def iter_mbox_records(path: Path, *, source: Source, label: Label) -> Iterator[EmailRecord]:
    """Yields one EmailRecord per message in an mbox file."""
    box = mailbox.mbox(str(path), create=False)
    try:
        for index, msg in enumerate(box):
            original_id = msg.get("Message-ID") or f"{path.name}:{index}"
            yield record_from_message(msg, source=source, label=label, original_id=original_id)
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
            msg, source=source, label=label, original_id=f"{directory.name}/{path.name}"
        )
