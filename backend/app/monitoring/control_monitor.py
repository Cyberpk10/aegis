"""Pure evidence-freshness math for Continuous Control Monitoring (M7 Stage A) — no DB
here, plain dataclasses in, plain dataclasses out, an explicit `now` parameter (never
wall-clock). Mirrors app/audit/aggregation.py's separation from route/DB wiring. Drift
alerts are derived live from the same `framework_mappings`/indicator data every
Case/Incident already carries, not from a new persisted alert table — this stage is
reporting-only and adds no mutable state.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta

from app.mapping import framework_mapper

STATUS_OPERATING = "operating"
STATUS_DEGRADED = "degraded"
STATUS_STALE = "stale"
STATUS_NO_EVIDENCE = "no_evidence"

# Controls needing more frequent evidence than the global default belong here (e.g. a
# control tied to something that should produce evidence daily). Empty for now — every
# control falls back to `default_interval_days`; extend as specific controls warrant it.
CONTROL_INTERVAL_OVERRIDES_DAYS: dict[str, int] = {}

_AUTH_INDICATOR_IDS = ("AUTH_SPF_FAIL", "AUTH_DKIM_FAIL", "AUTH_DMARC_FAIL")


@dataclass(frozen=True)
class EvidenceRow:
    """One Case or Incident's already-persisted framework_mappings, reduced to what
    freshness math needs — the route builds these directly from `row.created_at` /
    `row.framework_mappings`, no re-running of `map_indicators`."""

    occurred_at: datetime
    framework_mappings: dict[str, list[dict]]


@dataclass(frozen=True)
class CaseIndicatorRow:
    """A Case's indicator ids, reduced for the auth-pass-rate-drift check."""

    created_at: datetime
    indicator_ids: list[str]


@dataclass(frozen=True)
class ControlHealth:
    framework_key: str
    control_id: str
    control_name: str
    status: str
    last_evidence_at: datetime | None
    evidence_count: int
    expected_interval_days: int


@dataclass(frozen=True)
class DriftAlert:
    framework_key: str
    control_id: str
    control_name: str
    type: str
    since: datetime
    severity: str
    detail: str


def control_health(
    evidence: list[EvidenceRow],
    controls_by_id: dict[str, dict],
    framework_key: str,
    now: datetime,
    *,
    default_interval_days: int,
    stale_multiplier: float,
    interval_overrides: dict[str, int] | None = None,
) -> list[ControlHealth]:
    """For every control in `controls_by_id` (the framework's full control universe — a
    control with zero evidence still appears, as `no_evidence`, rather than being
    silently omitted, same pattern as app.audit.aggregation.evidence_for_framework),
    finds the most recent supporting evidence and classifies freshness against that
    control's expected interval."""
    overrides = interval_overrides or {}
    last_seen: dict[str, datetime] = {}
    counts: dict[str, int] = dict.fromkeys(controls_by_id, 0)

    for row in evidence:
        refs = row.framework_mappings.get(framework_key, [])
        seen_controls: set[str] = set()
        for ref in refs:
            control_id = ref["control_id"]
            if control_id not in controls_by_id or control_id in seen_controls:
                continue
            seen_controls.add(control_id)
            counts[control_id] += 1
            if control_id not in last_seen or row.occurred_at > last_seen[control_id]:
                last_seen[control_id] = row.occurred_at

    result: list[ControlHealth] = []
    for control_id, control in controls_by_id.items():
        expected_interval = overrides.get(control_id, default_interval_days)
        last_at = last_seen.get(control_id)
        if last_at is None:
            status = STATUS_NO_EVIDENCE
        else:
            age_days = (now - last_at).total_seconds() / 86400
            if age_days <= expected_interval:
                status = STATUS_OPERATING
            elif age_days <= expected_interval * stale_multiplier:
                status = STATUS_DEGRADED
            else:
                status = STATUS_STALE
        result.append(
            ControlHealth(
                framework_key=framework_key,
                control_id=control_id,
                control_name=control["name"],
                status=status,
                last_evidence_at=last_at,
                evidence_count=counts[control_id],
                expected_interval_days=expected_interval,
            )
        )
    return result


def went_quiet_alerts(controls: list[ControlHealth]) -> list[DriftAlert]:
    """A control that HAS prior evidence but is currently degraded/stale is "went
    quiet." A control that never had any evidence is just `no_evidence` — not drift,
    since there's no established pattern to have broken."""
    alerts: list[DriftAlert] = []
    for c in controls:
        if c.evidence_count == 0 or c.status not in (STATUS_DEGRADED, STATUS_STALE):
            continue
        severity = "high" if c.status == STATUS_STALE else "medium"
        assert c.last_evidence_at is not None
        alerts.append(
            DriftAlert(
                framework_key=c.framework_key,
                control_id=c.control_id,
                control_name=c.control_name,
                type="went_quiet",
                since=c.last_evidence_at,
                severity=severity,
                detail=(
                    f"No supporting evidence since {c.last_evidence_at:%Y-%m-%d} "
                    f"(expected every {c.expected_interval_days}d)."
                ),
            )
        )
    return alerts


def auth_pass_rate_drift(
    recent_cases: list[CaseIndicatorRow],
    prior_cases: list[CaseIndicatorRow],
    framework_key: str,
    controls_by_id: dict[str, dict],
    recent_window_start: datetime,
    *,
    min_sample: int,
    drop_threshold: float,
) -> list[DriftAlert]:
    """Compares SPF/DKIM/DMARC pass rates (proxied as 1 - fail-indicator rate, since
    only failures are ever recorded as indicators) between two adjacent windows. Small
    windows are skipped via `min_sample` so a handful of emails can't manufacture a
    drift alert."""
    alerts: list[DriftAlert] = []
    if len(recent_cases) < min_sample or len(prior_cases) < min_sample:
        return alerts

    for indicator_id in _AUTH_INDICATOR_IDS:
        recent_fail = sum(1 for c in recent_cases if indicator_id in c.indicator_ids)
        prior_fail = sum(1 for c in prior_cases if indicator_id in c.indicator_ids)
        recent_pass_rate = 1 - recent_fail / len(recent_cases)
        prior_pass_rate = 1 - prior_fail / len(prior_cases)
        drop = prior_pass_rate - recent_pass_rate
        if drop < drop_threshold:
            continue

        refs = framework_mapper.map_indicators([indicator_id]).get(framework_key, [])
        matched_control_ids = {ref.control_id for ref in refs if ref.control_id in controls_by_id}
        for control_id in sorted(matched_control_ids):
            control = controls_by_id[control_id]
            alerts.append(
                DriftAlert(
                    framework_key=framework_key,
                    control_id=control_id,
                    control_name=control["name"],
                    type="auth_pass_rate_drop",
                    since=recent_window_start,
                    severity="high" if drop >= drop_threshold * 2 else "medium",
                    detail=(
                        f"{indicator_id} pass rate dropped from {prior_pass_rate:.0%} to "
                        f"{recent_pass_rate:.0%} over the last window."
                    ),
                )
            )
    return alerts


def coverage_drift(
    recent_health: list[ControlHealth],
    prior_health: list[ControlHealth],
    framework_key: str,
    framework_name: str,
    since: datetime,
    *,
    comparison_days: int,
    drop_threshold: float,
) -> DriftAlert | None:
    """Framework-level (not per-control) alert: the share of controls currently
    `operating` has dropped materially versus a snapshot `comparison_days` ago."""

    def _coverage_pct(controls: list[ControlHealth]) -> float:
        if not controls:
            return 0.0
        operating = sum(1 for c in controls if c.status == STATUS_OPERATING)
        return operating / len(controls)

    recent_pct = _coverage_pct(recent_health)
    prior_pct = _coverage_pct(prior_health)
    drop = prior_pct - recent_pct
    if drop < drop_threshold:
        return None

    return DriftAlert(
        framework_key=framework_key,
        control_id="",
        control_name=framework_name,
        type="coverage_drop",
        since=since,
        severity="critical" if drop >= drop_threshold * 2 else "high",
        detail=(
            f"{framework_name} operating-control coverage dropped from {prior_pct:.0%} to "
            f"{recent_pct:.0%} over the last {comparison_days}d."
        ),
    )


def compute_drift_alerts(
    evidence: list[EvidenceRow],
    case_indicator_rows: list[CaseIndicatorRow],
    now: datetime,
    *,
    default_interval_days: int,
    stale_multiplier: float,
    auth_window_days: int,
    auth_min_sample: int,
    auth_drop_threshold: float,
    coverage_comparison_days: int,
    coverage_drop_threshold: float,
    interval_overrides: dict[str, int] | None = None,
) -> list[DriftAlert]:
    """Orchestrates all three drift rules across every loaded framework — the only
    function the route needs to call for GET /api/monitoring/drift."""
    alerts: list[DriftAlert] = []

    auth_recent_start = now - timedelta(days=auth_window_days)
    auth_prior_start = now - timedelta(days=auth_window_days * 2)
    recent_cases = [c for c in case_indicator_rows if c.created_at > auth_recent_start]
    prior_cases = [
        c for c in case_indicator_rows if auth_prior_start < c.created_at <= auth_recent_start
    ]

    coverage_cutoff = now - timedelta(days=coverage_comparison_days)
    prior_evidence = [row for row in evidence if row.occurred_at <= coverage_cutoff]

    for framework_key in framework_mapper.loaded_framework_keys():
        framework = framework_mapper.get_framework(framework_key)
        if framework is None:
            continue

        recent_health = control_health(
            evidence,
            framework.controls_by_id,
            framework_key,
            now,
            default_interval_days=default_interval_days,
            stale_multiplier=stale_multiplier,
            interval_overrides=interval_overrides,
        )
        alerts.extend(went_quiet_alerts(recent_health))

        alerts.extend(
            auth_pass_rate_drift(
                recent_cases,
                prior_cases,
                framework_key,
                framework.controls_by_id,
                auth_recent_start,
                min_sample=auth_min_sample,
                drop_threshold=auth_drop_threshold,
            )
        )

        prior_health = control_health(
            prior_evidence,
            framework.controls_by_id,
            framework_key,
            coverage_cutoff,
            default_interval_days=default_interval_days,
            stale_multiplier=stale_multiplier,
            interval_overrides=interval_overrides,
        )
        coverage_alert = coverage_drift(
            recent_health,
            prior_health,
            framework_key,
            framework.name,
            coverage_cutoff,
            comparison_days=coverage_comparison_days,
            drop_threshold=coverage_drop_threshold,
        )
        if coverage_alert is not None:
            alerts.append(coverage_alert)

    return alerts
