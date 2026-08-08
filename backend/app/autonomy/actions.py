"""The autonomy action catalog (M6 Stage 1) — deliberately small and reversible-first.
Every action here has a working reverse() path through app.autonomy.executor.ActionConnector;
there is no fifth, destructive action defined anywhere in this module. "Destructive actions
are never auto-eligible" is therefore a structural property, not a policy setting that could
be misconfigured — there is simply no connector method to delete or destroy anything.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass

from app.models.schemas import Finding

QUARANTINE_EMAIL = "QUARANTINE_EMAIL"
DISABLE_SESSION = "DISABLE_SESSION"
BLOCK_SENDER_DOMAIN = "BLOCK_SENDER_DOMAIN"
FLAG_ACCOUNT_FOR_REVIEW = "FLAG_ACCOUNT_FOR_REVIEW"


@dataclass(frozen=True)
class ActionDefinition:
    type: str
    title: str
    reversible: bool
    # Fixed, not configurable — this is what gives L1 vs L2 real meaning rather than being
    # an arbitrary policy label. See app.autonomy.policy.evaluate.
    containment: bool
    # A hard floor regardless of any customer policy rule — a rule can raise the bar for
    # auto-execution, never lower it below this. See app.autonomy.policy.evaluate.
    min_confidence_floor: float


ACTIONS: dict[str, ActionDefinition] = {
    QUARANTINE_EMAIL: ActionDefinition(
        type=QUARANTINE_EMAIL,
        title="Quarantine email",
        reversible=True,  # reverse = restore from quarantine — never delete
        containment=False,
        min_confidence_floor=0.5,
    ),
    FLAG_ACCOUNT_FOR_REVIEW: ActionDefinition(
        type=FLAG_ACCOUNT_FOR_REVIEW,
        title="Flag account for review",
        reversible=True,  # reverse = clear the flag
        containment=False,
        min_confidence_floor=0.4,
    ),
    DISABLE_SESSION: ActionDefinition(
        type=DISABLE_SESSION,
        title="Disable session",
        reversible=True,  # reverse = re-enable session — never delete the account
        containment=True,
        min_confidence_floor=0.6,
    ),
    BLOCK_SENDER_DOMAIN: ActionDefinition(
        type=BLOCK_SENDER_DOMAIN,
        title="Block sender domain",
        reversible=True,  # reverse = unblock the domain
        containment=True,
        min_confidence_floor=0.6,
    ),
}

# Maps existing M1-M5 finding/indicator ids to one of the four action types above. A finding
# with no entry here (e.g. anything only ever driving NOTIFY_SOC- or
# VERIFY_PAYMENT_OUT_OF_BAND-style human recommendations) simply has no autonomy path — it
# stays human-recommend-only forever, which is a safety property, not a gap.
FINDING_ACTION_MAP: dict[str, str] = {
    # Email indicators (M1-M4) — sender/domain-authenticity signals -> block the domain.
    "SENDER_REPLYTO_MISMATCH": BLOCK_SENDER_DOMAIN,
    "DISPLAY_NAME_EMAIL_MISMATCH": BLOCK_SENDER_DOMAIN,
    "LOOKALIKE_DOMAIN": BLOCK_SENDER_DOMAIN,
    "PUNYCODE_IDN_DOMAIN": BLOCK_SENDER_DOMAIN,
    "AUTH_SPF_FAIL": BLOCK_SENDER_DOMAIN,
    "AUTH_DKIM_FAIL": BLOCK_SENDER_DOMAIN,
    "AUTH_DMARC_FAIL": BLOCK_SENDER_DOMAIN,
    # Email indicators — message-content signals -> quarantine the message itself.
    "CREDENTIAL_REQUEST": QUARANTINE_EMAIL,
    "PAYMENT_REQUEST": QUARANTINE_EMAIL,
    "URGENCY_LANGUAGE": QUARANTINE_EMAIL,
    "LINK_DISPLAY_HREF_MISMATCH": QUARANTINE_EMAIL,
    "LINK_SHORTENER": QUARANTINE_EMAIL,
    "LINK_SUSPICIOUS_TLD": QUARANTINE_EMAIL,
    "LINK_IP_LITERAL": QUARANTINE_EMAIL,
    "ATTACHMENT_RISKY_EXTENSION": QUARANTINE_EMAIL,
    "ATTACHMENT_DOUBLE_EXTENSION": QUARANTINE_EMAIL,
    "ATTACHMENT_MACRO_ENABLED": QUARANTINE_EMAIL,
    "AI_AUTHORED_SUSPECTED": QUARANTINE_EMAIL,
    # Intrusion findings (M5) — account/session-compromise signals -> disable the session.
    "BRUTE_FORCE_PASSWORD_SPRAY": DISABLE_SESSION,
    "IMPOSSIBLE_TRAVEL": DISABLE_SESSION,
    "ANOMALOUS_LOCATION": DISABLE_SESSION,
    # Intrusion findings — activity/escalation signals with no clean single reversible
    # action -> the conservative fallback, flag for human review.
    "OFF_HOURS_ACCESS": FLAG_ACCOUNT_FOR_REVIEW,
    "MASS_FILE_ACCESS": FLAG_ACCOUNT_FOR_REVIEW,
    "DATA_EXFIL_LARGE_TRANSFER": FLAG_ACCOUNT_FOR_REVIEW,
    "DATA_EXFIL_LARGE_DB_EXPORT": FLAG_ACCOUNT_FOR_REVIEW,
    "PRIVILEGE_ESCALATION": FLAG_ACCOUNT_FOR_REVIEW,
}


def confidence_for_findings(findings: list[Finding]) -> float:
    """Deterministic confidence derived from the existing 0-100 points scale (points/100,
    clamped to 1.0) — a separate ML-calibrated confidence model is out of scope for Stage 1.
    When several findings contribute, the MINIMUM is used: this is a safety gate, so the
    weakest contributing signal governs, not the strongest."""
    return confidence_from_scores(f.points for f in findings)


def confidence_from_scores(scores: Iterable[float]) -> float:
    """Same derivation as confidence_for_findings, but schema-agnostic (a plain iterable
    of 0-100 numbers) — needed because Case.indicators are stored as `Indicator` dicts
    (field `score`) while Incident.findings are stored as `Finding` dicts (field `points`);
    the caller extracts whichever field applies before calling this."""
    values = [max(0.0, min(1.0, s / 100.0)) for s in scores]
    return min(values) if values else 0.0
