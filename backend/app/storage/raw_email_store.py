"""On-disk storage for raw .eml uploads.

Data minimization: the `cases` table never stores the raw email body/headers, only a path
pointer into this store. Files are named by case UUID (never user-controlled input, so this
is not susceptible to path traversal) and are purged after `settings.raw_email_retention_days`.
"""

from __future__ import annotations

import time
import uuid
from pathlib import Path

from app.core.config import settings


def _storage_dir() -> Path:
    path = Path(settings.raw_email_storage_dir)
    path.mkdir(parents=True, exist_ok=True)
    return path


def save_raw_email(case_id: uuid.UUID, raw_bytes: bytes) -> str:
    path = _storage_dir() / f"{case_id}.eml"
    path.write_bytes(raw_bytes)
    return str(path)


def load_raw_email(path: str) -> bytes | None:
    """Read-side counterpart to save_raw_email (M6 Stage 2 — the real Graph connector needs
    the original Message-ID header to locate a message in the mailbox). Returns None rather
    than raising if the file is missing (already purged by retention, or never saved) — the
    caller treats that the same as "no Message-ID available" and degrades gracefully."""
    try:
        return Path(path).read_bytes()
    except OSError:
        return None


def delete_raw_email(case_id: uuid.UUID) -> None:
    path = _storage_dir() / f"{case_id}.eml"
    path.unlink(missing_ok=True)


def purge_expired(now: float | None = None) -> int:
    """Delete stored .eml files older than the configured retention window. Returns the
    number of files deleted. Best-effort: run at app startup, and optionally on a schedule
    (cron/systemd timer) since this app has no background job runner."""
    cutoff = (now if now is not None else time.time()) - settings.raw_email_retention_days * 86400
    deleted = 0
    for path in _storage_dir().glob("*.eml"):
        if path.stat().st_mtime < cutoff:
            path.unlink(missing_ok=True)
            deleted += 1
    return deleted
