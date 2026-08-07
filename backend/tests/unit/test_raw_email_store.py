from __future__ import annotations

import os
import time
import uuid
from pathlib import Path

from app.core.config import settings
from app.storage import raw_email_store


def test_save_and_delete_raw_email(monkeypatch, tmp_path):
    monkeypatch.setattr(settings, "raw_email_storage_dir", str(tmp_path))
    case_id = uuid.uuid4()

    path = raw_email_store.save_raw_email(case_id, b"raw email bytes")
    assert Path(path).read_bytes() == b"raw email bytes"

    raw_email_store.delete_raw_email(case_id)
    assert not Path(path).exists()


def test_delete_raw_email_is_a_noop_when_missing(monkeypatch, tmp_path):
    monkeypatch.setattr(settings, "raw_email_storage_dir", str(tmp_path))
    raw_email_store.delete_raw_email(uuid.uuid4())  # must not raise


def test_purge_expired_deletes_only_files_past_the_retention_window(monkeypatch, tmp_path):
    monkeypatch.setattr(settings, "raw_email_storage_dir", str(tmp_path))
    monkeypatch.setattr(settings, "raw_email_retention_days", 7)

    old_file = tmp_path / "old.eml"
    old_file.write_bytes(b"old")
    new_file = tmp_path / "new.eml"
    new_file.write_bytes(b"new")

    now = time.time()
    old_mtime = now - 10 * 86400  # 10 days old, past the 7-day retention window
    os.utime(old_file, (old_mtime, old_mtime))

    deleted = raw_email_store.purge_expired(now=now)

    assert deleted == 1
    assert not old_file.exists()
    assert new_file.exists()
