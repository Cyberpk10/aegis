"""On-disk storage for generated Audit Mode evidence packs (PDF + JSON).

Mirrors app.storage.raw_email_store's pattern: files are named by report UUID (never
user-controlled input, so no path-traversal surface), and the DB (AuditReport) stores only
the path pointers, not the file contents.
"""

from __future__ import annotations

import uuid
from pathlib import Path

from app.core.config import settings


def _storage_dir() -> Path:
    path = Path(settings.audit_report_storage_dir)
    path.mkdir(parents=True, exist_ok=True)
    return path


def save_report_files(report_id: uuid.UUID, pdf_bytes: bytes, json_bytes: bytes) -> tuple[str, str]:
    """Writes both formats, returns (pdf_path, json_path) as strings for the DB row."""
    pdf_path = _storage_dir() / f"{report_id}.pdf"
    json_path = _storage_dir() / f"{report_id}.json"
    pdf_path.write_bytes(pdf_bytes)
    json_path.write_bytes(json_bytes)
    return str(pdf_path), str(json_path)
