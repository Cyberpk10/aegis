"""Application configuration."""

from __future__ import annotations

import os
from dataclasses import dataclass, field

from dotenv import load_dotenv

# Loads variables from a local .env file (if present) into os.environ. Real
# environment variables already set (shell, CI) always take precedence —
# load_dotenv() defaults to override=False. .env itself is gitignored; see
# .env.example for the documented set of variables.
load_dotenv()

_TRUTHY = {"1", "true", "yes", "on"}


def _env_bool(name: str, default: bool) -> bool:
    raw = os.environ.get(name)
    if raw is None:
        return default
    return raw.strip().lower() in _TRUTHY


@dataclass
class Settings:
    cors_origins: list[str] = field(
        default_factory=lambda: ["http://localhost:5173", "http://127.0.0.1:5173"]
    )
    max_upload_bytes: int = 10 * 1024 * 1024  # 10 MiB

    # LLM reasoning layer (M2): off by default so the app and test suite stay
    # fully offline and deterministic unless explicitly opted in.
    enable_llm_reasoning: bool = field(
        default_factory=lambda: _env_bool("ENABLE_LLM_REASONING", False)
    )
    llm_model: str = field(
        default_factory=lambda: os.environ.get("ANTHROPIC_MODEL", "claude-haiku-4-5")
    )

    # Persistence (M3/Stage 2). SQLite by default so the app and test suite run with zero
    # setup; point DATABASE_URL at the docker-compose Postgres for a real deployment.
    database_url: str = field(
        default_factory=lambda: os.environ.get("DATABASE_URL", "sqlite:///./aegis.db")
    )
    # Raw .eml files are stored on disk (never in the DB) and purged after this many days —
    # only a path pointer lives in the `cases` table.
    raw_email_storage_dir: str = field(
        default_factory=lambda: os.environ.get("RAW_EMAIL_STORAGE_DIR", "./data/raw_emails")
    )
    raw_email_retention_days: int = field(
        default_factory=lambda: int(os.environ.get("RAW_EMAIL_RETENTION_DAYS", "30"))
    )


settings = Settings()
