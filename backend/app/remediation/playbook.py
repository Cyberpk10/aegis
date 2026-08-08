"""Deterministic, rule-based response-playbook generation.

Aegis only *recommends* here — nothing in this module (or the route that calls it) makes
a network call, blocks anything, resets any credential, or quarantines anything. It maps a
case's already-computed indicator ids to a fixed set of suggested operator actions; a human
approves/marks each step done via app.api.routes.remediation, which only ever records that
decision as state (see app.db.models.RemediationAction).
"""

from __future__ import annotations

from dataclasses import dataclass

_TRIGGERS_BLOCK_SENDER_DOMAIN = frozenset(
    {
        "LOOKALIKE_DOMAIN",
        "PUNYCODE_IDN_DOMAIN",
        "SENDER_REPLYTO_MISMATCH",
        "AUTH_SPF_FAIL",
        "AUTH_DKIM_FAIL",
        "AUTH_DMARC_FAIL",
    }
)
_TRIGGERS_RESET_CREDENTIALS = frozenset({"CREDENTIAL_REQUEST"})
_TRIGGERS_QUARANTINE_COPIES = frozenset(
    {
        "LINK_DISPLAY_HREF_MISMATCH",
        "LINK_SHORTENER",
        "LINK_SUSPICIOUS_TLD",
        "LINK_IP_LITERAL",
        "ATTACHMENT_RISKY_EXTENSION",
        "ATTACHMENT_DOUBLE_EXTENSION",
        "ATTACHMENT_MACRO_ENABLED",
    }
)
_TRIGGERS_VERIFY_PAYMENT = frozenset({"PAYMENT_REQUEST"})
_TRIGGERS_NOTIFY_TARGETED_USER = frozenset(
    {"URGENCY_LANGUAGE", "CREDENTIAL_REQUEST", "PAYMENT_REQUEST", "LOOKALIKE_DOMAIN"}
)

# Fixed order: iteration order determines output order, which is part of what makes
# generate_playbook() deterministic for a given indicator set.
_STEP_RULES: tuple[tuple[str, str, str, str, frozenset[str]], ...] = (
    (
        "BLOCK_SENDER_DOMAIN",
        "Block sender domain",
        "Block the sending address/domain at the mail gateway to stop further delivery "
        "from this source.",
        "block_sender",
        _TRIGGERS_BLOCK_SENDER_DOMAIN,
    ),
    (
        "RESET_CREDENTIALS",
        "Reset credentials for any user who may have entered them",
        "This message solicited login credentials. Reset the password (and revoke active "
        "sessions/tokens) for any recipient who may have submitted them.",
        "reset_credentials",
        _TRIGGERS_RESET_CREDENTIALS,
    ),
    (
        "VERIFY_PAYMENT_OUT_OF_BAND",
        "Verify payment/wire request out-of-band",
        "This message requested a payment, wire transfer, or change to banking details. "
        "Verify the request directly with the purported sender through a separate, "
        "known-good channel before any funds move.",
        "verify_payment",
        _TRIGGERS_VERIFY_PAYMENT,
    ),
    (
        "QUARANTINE_COPIES",
        "Quarantine copies of this message across mailboxes",
        "Search for and quarantine copies of this message (by sender/subject/link) that "
        "may have reached other mailboxes in the organization.",
        "quarantine_copies",
        _TRIGGERS_QUARANTINE_COPIES,
    ),
    (
        "NOTIFY_TARGETED_USER",
        "Notify the targeted recipient(s)",
        "Notify the recipient(s) that they were targeted, with brief awareness guidance "
        "on the specific tactic used in this message.",
        "notify_user",
        _TRIGGERS_NOTIFY_TARGETED_USER,
    ),
)


@dataclass(frozen=True)
class PlaybookStep:
    step_id: str
    title: str
    description: str
    category: str
    related_indicator_ids: list[str]


def generate_playbook(indicator_ids: list[str]) -> list[PlaybookStep]:
    """Pure function: the same indicator id set always produces the same steps in the
    same order, with the same related_indicator_ids (sorted) — this determinism is by
    design, not incidental."""
    present = set(indicator_ids)
    steps: list[PlaybookStep] = []

    for step_id, title, description, category, triggers in _STEP_RULES:
        matched = sorted(present & triggers)
        if not matched:
            continue
        steps.append(
            PlaybookStep(
                step_id=step_id,
                title=title,
                description=description,
                category=category,
                related_indicator_ids=matched,
            )
        )

    return steps
