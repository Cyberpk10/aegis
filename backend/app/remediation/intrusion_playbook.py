"""Deterministic, rule-based response-playbook generation for intrusion/data-exfiltration
incidents (M5 Stage 1) — mirrors app.remediation.playbook's email playbook exactly, reusing
its shared generate_from_rules engine and PlaybookStep shape with a different rule table.

Aegis only *recommends* here — nothing in this module (or the route that calls it) isolates
a host, blocks an IP, resets a credential, or revokes a session. It maps an incident's
already-computed finding ids to a fixed set of suggested operator actions; a human
approves/marks each step done via app.api.routes.remediation, which only ever records that
decision as state (see app.db.models.RemediationAction).
"""

from __future__ import annotations

from app.remediation.playbook import PlaybookStep, generate_from_rules

_TRIGGERS_ISOLATE_HOST = frozenset(
    {"MASS_FILE_ACCESS", "DATA_EXFIL_LARGE_TRANSFER", "DATA_EXFIL_LARGE_DB_EXPORT"}
)
_TRIGGERS_FORCE_PASSWORD_RESET = frozenset({"BRUTE_FORCE_PASSWORD_SPRAY", "IMPOSSIBLE_TRAVEL"})
_TRIGGERS_BLOCK_SOURCE_IP = frozenset({"BRUTE_FORCE_PASSWORD_SPRAY", "IMPOSSIBLE_TRAVEL"})
_TRIGGERS_ROTATE_CREDENTIALS = frozenset(
    {"DATA_EXFIL_LARGE_DB_EXPORT", "PRIVILEGE_ESCALATION"}
)
_TRIGGERS_REVIEW_PRIVILEGE_GRANT = frozenset({"PRIVILEGE_ESCALATION"})
_TRIGGERS_NOTIFY_SOC = frozenset(
    {
        "BRUTE_FORCE_PASSWORD_SPRAY",
        "IMPOSSIBLE_TRAVEL",
        "OFF_HOURS_ACCESS",
        "MASS_FILE_ACCESS",
        "DATA_EXFIL_LARGE_TRANSFER",
        "DATA_EXFIL_LARGE_DB_EXPORT",
        "PRIVILEGE_ESCALATION",
    }
)

# Fixed order: iteration order determines output order (same determinism guarantee as
# the email _STEP_RULES).
_INTRUSION_STEP_RULES: tuple[tuple[str, str, str, str, frozenset[str]], ...] = (
    (
        "FORCE_PASSWORD_RESET",
        "Force password reset and revoke active sessions",
        "The account may be compromised. Force a password reset and revoke active "
        "sessions/tokens for the affected account before any further activity.",
        "reset_credentials",
        _TRIGGERS_FORCE_PASSWORD_RESET,
    ),
    (
        "BLOCK_SOURCE_IP",
        "Block source IP at egress",
        "Block the offending source IP address at the firewall/egress point to stop "
        "further access attempts from this source.",
        "block_network",
        _TRIGGERS_BLOCK_SOURCE_IP,
    ),
    (
        "ISOLATE_HOST",
        "Isolate the affected host from the network",
        "Isolate the host/endpoint involved in this activity from the network pending "
        "investigation, to contain any potential data loss.",
        "isolate_host",
        _TRIGGERS_ISOLATE_HOST,
    ),
    (
        "ROTATE_CREDENTIALS_KEYS",
        "Rotate credentials and API keys",
        "Rotate any credentials, API keys, or service account secrets accessible to this "
        "actor, in case they were exposed or misused.",
        "rotate_credentials",
        _TRIGGERS_ROTATE_CREDENTIALS,
    ),
    (
        "REVIEW_PRIVILEGE_GRANT",
        "Review and, if unauthorized, revoke the privilege grant",
        "Review the privilege/permission change for legitimacy against change-management "
        "records; revoke it if it wasn't properly authorized.",
        "review_access",
        _TRIGGERS_REVIEW_PRIVILEGE_GRANT,
    ),
    (
        "NOTIFY_SOC",
        "Notify the security operations team",
        "Notify SOC/security personnel of this incident with a brief summary of the "
        "detected activity for awareness and further investigation.",
        "notify_soc",
        _TRIGGERS_NOTIFY_SOC,
    ),
)


def generate_intrusion_playbook(finding_ids: list[str]) -> list[PlaybookStep]:
    return generate_from_rules(finding_ids, _INTRUSION_STEP_RULES)
