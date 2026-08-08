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

    # Analyst feedback loop (M4/Stage 3). Stub identity for "who labeled this" — an
    # X-Analyst-Id request header overrides this per-request. Not real auth.
    default_analyst_id: str = field(
        default_factory=lambda: os.environ.get("DEFAULT_ANALYST_ID", "anonymous-analyst")
    )

    # Audit Mode (M4 Stage 1). Generated evidence-pack PDF/JSON files live here — under
    # backend/data/ by default, already covered by .gitignore.
    audit_report_storage_dir: str = field(
        default_factory=lambda: os.environ.get("AUDIT_REPORT_STORAGE_DIR", "./data/audit_reports")
    )

    # Closed-loop remediation + targeted training (M4 Stage 3). A recipient hit by this
    # many non-safe cases gets flagged for a stored micro-training recommendation.
    target_training_threshold: int = field(
        default_factory=lambda: int(os.environ.get("TARGET_TRAINING_THRESHOLD", "3"))
    )

    # Natural-language threat copilot (M4 Stage 4). Off by default — separate from
    # enable_llm_reasoning since this is a broader, cross-case data-access surface than
    # the single-email analyst narrative, and a deployer should opt into it independently.
    enable_copilot: bool = field(default_factory=lambda: _env_bool("ENABLE_COPILOT", False))

    # Intrusion & data-exfiltration detection (M5 Stage 1). How far back from an actor's
    # latest event in an ingest batch the detection engine looks for correlated activity
    # (brute force, mass access, etc). Anchored to event timestamps, not wall-clock.
    intrusion_lookback_hours: int = field(
        default_factory=lambda: int(os.environ.get("INTRUSION_LOOKBACK_HOURS", "24"))
    )
    # Static business-hours window (UTC, 24h clock) for the off-hours-access detector.
    business_hours_start: int = field(
        default_factory=lambda: int(os.environ.get("BUSINESS_HOURS_START", "8"))
    )
    business_hours_end: int = field(
        default_factory=lambda: int(os.environ.get("BUSINESS_HOURS_END", "18"))
    )
    # Data-exfiltration thresholds: a single transfer/download over this many bytes to a
    # non-allowlisted destination, or a single db_query export over this many bytes, fires.
    exfil_large_transfer_bytes: int = field(
        default_factory=lambda: int(os.environ.get("EXFIL_LARGE_TRANSFER_BYTES", str(500_000_000)))
    )
    exfil_large_db_export_bytes: int = field(
        default_factory=lambda: int(
            os.environ.get("EXFIL_LARGE_DB_EXPORT_BYTES", str(200_000_000))
        )
    )
    # Comma-separated list of transfer/download targets considered "known" destinations
    # (never flagged as exfiltration regardless of size). Empty by default — everything is
    # "unfamiliar" until a deployer allowlists their own known-good destinations.
    exfil_allowlisted_destinations: list[str] = field(
        default_factory=lambda: [
            d.strip()
            for d in os.environ.get("EXFIL_ALLOWLISTED_DESTINATIONS", "").split(",")
            if d.strip()
        ]
    )

    # Behavioral baselines / UEBA (M5 Stage 2). Cold-start gates: an actor's baseline isn't
    # trusted over the Stage 1 static thresholds until it has this much history.
    baseline_min_events_for_hours: int = field(
        default_factory=lambda: int(os.environ.get("BASELINE_MIN_EVENTS_FOR_HOURS", "5"))
    )
    # An hour-of-day must have been seen at least this many times to count as "typical".
    baseline_min_hour_occurrences: int = field(
        default_factory=lambda: int(os.environ.get("BASELINE_MIN_HOUR_OCCURRENCES", "2"))
    )
    baseline_min_events_for_location: int = field(
        default_factory=lambda: int(os.environ.get("BASELINE_MIN_EVENTS_FOR_LOCATION", "5"))
    )
    # Minimum days of daily_volume history before the volume baseline is trusted over the
    # Stage 1 static count/distinct-target thresholds.
    baseline_min_days_for_volume: int = field(
        default_factory=lambda: int(os.environ.get("BASELINE_MIN_DAYS_FOR_VOLUME", "5"))
    )
    # A day's file-access volume fires if it exceeds mean + this-many-stddevs of the actor's
    # rolling daily_volume history.
    baseline_volume_stddev_multiplier: float = field(
        default_factory=lambda: float(os.environ.get("BASELINE_VOLUME_STDDEV_MULTIPLIER", "3.0"))
    )
    # Rolling window size (days) for daily_volume — oldest days are dropped as new ones are
    # added, so the baseline can adapt if an actor's normal workload genuinely changes.
    baseline_daily_volume_window_days: int = field(
        default_factory=lambda: int(os.environ.get("BASELINE_DAILY_VOLUME_WINDOW_DAYS", "30"))
    )


settings = Settings()
