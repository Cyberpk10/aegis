"""Application configuration."""

from __future__ import annotations

import os
import secrets
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


def _normalize_database_url(url: str) -> str:
    """Managed Postgres providers (Render, Heroku, ...) hand back a bare `postgres://` or
    `postgresql://` connection string, which implies SQLAlchemy's legacy default driver
    (psycopg2). This app depends on psycopg (v3, via `psycopg[binary]`) instead — without
    this rewrite, `create_engine()` tries to import psycopg2 (not installed) and crashes
    immediately at process startup, before the app or Alembic ever run."""
    if url.startswith("postgres://"):
        return "postgresql+psycopg://" + url[len("postgres://") :]
    if url.startswith("postgresql://"):
        return "postgresql+psycopg://" + url[len("postgresql://") :]
    return url


@dataclass
class Settings:
    # M8 Stage 1 (production hosting). "development" locally by default; Render sets this to
    # "production", which gates HTTPS enforcement in app.main.
    environment: str = field(default_factory=lambda: os.environ.get("ENVIRONMENT", "development"))
    log_level: str = field(default_factory=lambda: os.environ.get("LOG_LEVEL", "INFO"))

    # Comma-separated allowed CORS origins, e.g. the deployed Vercel URL in production. Falls
    # back to the local Vite dev server origins when unset, so local dev is unaffected.
    cors_origins: list[str] = field(
        default_factory=lambda: [
            o.strip() for o in os.environ.get("CORS_ALLOWED_ORIGINS", "").split(",") if o.strip()
        ]
        or ["http://localhost:5173", "http://127.0.0.1:5173"]
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
        default_factory=lambda: _normalize_database_url(
            os.environ.get("DATABASE_URL", "sqlite:///./aegis.db")
        )
    )
    # Raw .eml files are stored on disk (never in the DB) and purged after this many days —
    # only a path pointer lives in the `cases` table.
    raw_email_storage_dir: str = field(
        default_factory=lambda: os.environ.get("RAW_EMAIL_STORAGE_DIR", "./data/raw_emails")
    )
    raw_email_retention_days: int = field(
        default_factory=lambda: int(os.environ.get("RAW_EMAIL_RETENTION_DAYS", "30"))
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

    # Continuous Control Monitoring (M7 Stage A). How far back evidence queries look when
    # computing per-control freshness and drift.
    monitoring_lookback_days: int = field(
        default_factory=lambda: int(os.environ.get("MONITORING_LOOKBACK_DAYS", "180"))
    )
    # A control is "operating" if its most recent evidence is within this many days,
    # unless overridden per-control (see control_monitor.CONTROL_INTERVAL_OVERRIDES_DAYS).
    monitoring_default_interval_days: int = field(
        default_factory=lambda: int(os.environ.get("MONITORING_DEFAULT_INTERVAL_DAYS", "14"))
    )
    # Multiplied against a control's expected interval to get the degraded/stale boundary.
    monitoring_stale_multiplier: float = field(
        default_factory=lambda: float(os.environ.get("MONITORING_STALE_MULTIPLIER", "3.0"))
    )
    # Window size (days) for the two adjacent SPF/DKIM/DMARC pass-rate comparison periods.
    monitoring_auth_window_days: int = field(
        default_factory=lambda: int(os.environ.get("MONITORING_AUTH_WINDOW_DAYS", "14"))
    )
    # Minimum cases required in BOTH windows before an auth-pass-rate-drop alert can fire —
    # guards against a handful of emails manufacturing a false drift signal.
    monitoring_auth_min_sample: int = field(
        default_factory=lambda: int(os.environ.get("MONITORING_AUTH_MIN_SAMPLE", "5"))
    )
    # Minimum pass-rate drop (fraction, e.g. 0.15 = 15 points) between windows to alert.
    monitoring_auth_drop_threshold: float = field(
        default_factory=lambda: float(os.environ.get("MONITORING_AUTH_DROP_THRESHOLD", "0.15"))
    )
    # How far back the "prior" framework-coverage snapshot is taken from, for comparison
    # against the current one.
    monitoring_coverage_comparison_days: int = field(
        default_factory=lambda: int(os.environ.get("MONITORING_COVERAGE_COMPARISON_DAYS", "30"))
    )
    # Minimum operating-coverage drop (fraction) between snapshots to alert.
    monitoring_coverage_drop_threshold: float = field(
        default_factory=lambda: float(os.environ.get("MONITORING_COVERAGE_DROP_THRESHOLD", "0.10"))
    )

    # Multi-channel detection (M7 Stage B). Display names considered protected against
    # impersonation by an external chat sender — comma-separated, empty by default (same
    # sensible-default-list pattern as exfil_allowlisted_destinations/autonomy exclusions).
    chat_protected_display_names: list[str] = field(
        default_factory=lambda: [
            n.strip()
            for n in os.environ.get("CHAT_PROTECTED_DISPLAY_NAMES", "").split(",")
            if n.strip()
        ]
    )
    # Live Slack/Teams ingestion is not implemented yet (see app.channels.slack_client /
    # teams_client) — these flags exist as the seam for when it is, off by default.
    enable_live_slack_ingestion: bool = field(
        default_factory=lambda: _env_bool("ENABLE_LIVE_SLACK_INGESTION", False)
    )
    enable_live_teams_ingestion: bool = field(
        default_factory=lambda: _env_bool("ENABLE_LIVE_TEAMS_INGESTION", False)
    )

    # Authentication (M8 Stage 2). No safe default for production — if JWT_SECRET_KEY isn't
    # set, a random value is generated per-process so local dev still works, but every
    # restart invalidates every existing session. Render MUST have this set explicitly.
    jwt_secret_key: str = field(
        default_factory=lambda: os.environ.get("JWT_SECRET_KEY") or secrets.token_urlsafe(64)
    )
    jwt_access_token_ttl_minutes: int = field(
        default_factory=lambda: int(os.environ.get("JWT_ACCESS_TOKEN_TTL_MINUTES", "15"))
    )
    jwt_refresh_token_ttl_days: int = field(
        default_factory=lambda: int(os.environ.get("JWT_REFRESH_TOKEN_TTL_DAYS", "7"))
    )

    # Email forwarding intake (M8 Stage 3). No safe default for the signing key — an unset
    # value means the webhook hard-rejects everything (see app.api.routes.inbound) rather
    # than silently accepting unsigned requests. Get this from Mailgun's Sending -> Webhooks
    # page (a different value from the API key).
    #
    # TODO(deploy): the code path is fully built and tested, but inert in production until a
    # real domain is registered and pointed at Mailgun. Once you have one:
    #   1. Mailgun -> Sending -> Domains -> add a receiving subdomain (e.g. in.yourdomain.com),
    #      add the MX records it gives you at your DNS provider.
    #   2. Mailgun -> Receiving -> Routes -> create one route:
    #      match_recipient("^pilot-[a-z0-9]+@in\.yourdomain\.com$")
    #      -> forward("https://<backend>.onrender.com/api/inbound/email/mime")
    #   3. Set MAILGUN_WEBHOOK_SIGNING_KEY (Sending -> Webhooks) and INBOUND_EMAIL_DOMAIN on
    #      Render, redeploy. Full walkthrough: DEPLOYMENT.md section 8.
    mailgun_webhook_signing_key: str = field(
        default_factory=lambda: os.environ.get("MAILGUN_WEBHOOK_SIGNING_KEY", "")
    )
    # The domain forwarding addresses are shown as (pilot-<token>@<this>) — must match the
    # domain the Mailgun receiving route is actually configured on. See DEPLOYMENT.md.
    inbound_email_domain: str = field(
        default_factory=lambda: os.environ.get("INBOUND_EMAIL_DOMAIN", "in.aegis.example.com")
    )
    # Replay-attack defense in depth — Mailgun's own HMAC signature never expires on its own,
    # so a captured payload could otherwise be replayed indefinitely.
    inbound_email_signature_max_age_seconds: int = field(
        default_factory=lambda: int(os.environ.get("INBOUND_EMAIL_SIGNATURE_MAX_AGE_SECONDS", "900"))
    )
    # Per-account cap on inbound-forwarded emails per hour — a provider's webhook traffic all
    # comes from a small set of source IPs, so per-IP rate limiting (as used on /api/auth/*)
    # doesn't actually throttle per-tenant abuse here; this does.
    inbound_email_rate_limit_per_account_per_hour: int = field(
        default_factory=lambda: int(
            os.environ.get("INBOUND_EMAIL_RATE_LIMIT_PER_ACCOUNT_PER_HOUR", "30")
        )
    )

    # Real Microsoft Graph autonomous-response connector (M6 Stage 2). A single Azure AD app
    # registration shared across every account (multi-tenant; each customer's admin consents
    # it into their own tenant) — these two are the only Graph secrets that exist, and there's
    # exactly one of each, not one per account. Either unset means every account falls back to
    # MockConnector (see app.autonomy.connector_factory) — no real action ever fires
    # unconfigured. See DEPLOYMENT.md for the full Azure app registration walkthrough.
    microsoft_graph_client_id: str = field(
        default_factory=lambda: os.environ.get("MICROSOFT_GRAPH_CLIENT_ID", "")
    )
    microsoft_graph_client_secret: str = field(
        default_factory=lambda: os.environ.get("MICROSOFT_GRAPH_CLIENT_SECRET", "")
    )


settings = Settings()
