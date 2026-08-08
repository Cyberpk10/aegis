"""Editable, cited assumptions for the financial risk model (M4 Stage 5).

Every numeric default here is sourced — see sources.md in this package for the full
citation write-up (exact quotes, URLs, verification dates). Nothing in this file is a
made-up figure: where a precisely-scoped public figure could not be verified, the
comment says so explicitly and names the conservative proxy used instead.

All fields are env-var overridable, same pattern as app.core.config.Settings, so a
deployer can plug in better internal/actuarial numbers without touching code.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field


def _env_float(name: str, default: float) -> float:
    raw = os.environ.get(name)
    if raw is None:
        return default
    return float(raw)


@dataclass
class RiskModelAssumptions:
    # Average loss per successful Business Email Compromise incident.
    # Source: FBI IC3 "2024 Internet Crime Report" — $2.77 billion in BEC losses across
    # 21,442 reported complaints ($2,770,000,000 / 21,442 ~= $129,242/incident).
    # https://www.ic3.gov/AnnualReport/Reports/2024_IC3Report.pdf (figure verified via
    # direct citation on certifid.com and abnormal.ai, 2026-08-07). Cross-reference: an
    # industry aggregation (IBM Cost of a Data Breach Report 2025 / DeepStrike / Hoxhunt,
    # via totalassure.com) independently cites ~$160,000 average BEC incident cost — same
    # order of magnitude.
    bec_avg_loss_usd: float = field(
        default_factory=lambda: _env_float("RISK_BEC_AVG_LOSS_USD", 129242.0)
    )

    # Average loss per successful credential-harvesting phishing compromise.
    # Mainstream reports (IBM) only publish credential-harvesting cost as part of a full
    # enterprise breach (~$4.88M average, 2024/2025 — investigation, containment,
    # notification, ~254 days to detect+contain), which is the wrong scope for "cost of
    # one detected/blocked phishing email." The best-scoped *per-incident* (not
    # per-breach) figure that could be directly verified is QR-code phishing's $97,000
    # average incident cost, from the same IBM/DeepStrike/Hoxhunt aggregation (via
    # totalassure.com/blog/average-cost-phishing-attack, verified 2026-08-07). Used here
    # as a deliberately conservative proxy since no more precisely-scoped
    # generic-credential-phishing figure could be verified — override if better internal
    # data is available.
    credential_phishing_avg_loss_usd: float = field(
        default_factory=lambda: _env_float("RISK_CREDENTIAL_PHISHING_AVG_LOSS_USD", 97000.0)
    )

    # Average loss for phishing that fires neither a payment nor a credential-harvesting
    # indicator (e.g. malware attachment, lookalike domain alone). No distinct verified
    # figure exists for this bucket; defaults to the same conservative proxy as
    # credential_phishing_avg_loss_usd above. Override independently if better data
    # becomes available for this bucket specifically.
    generic_phishing_avg_loss_usd: float = field(
        default_factory=lambda: _env_float("RISK_GENERIC_PHISHING_AVG_LOSS_USD", 97000.0)
    )

    # What fraction of a bucket's avg loss counts as "exposure avoided" per verdict.
    # Conservative default: only high-confidence "malicious" verdicts count in full;
    # "suspicious" (lower-confidence) verdicts count for nothing unless the operator
    # opts in. This is a judgment call, not a cited figure — override to taste.
    verdict_prevention_weight_malicious: float = field(
        default_factory=lambda: _env_float("RISK_WEIGHT_MALICIOUS", 1.0)
    )
    verdict_prevention_weight_suspicious: float = field(
        default_factory=lambda: _env_float("RISK_WEIGHT_SUSPICIOUS", 0.0)
    )

    def prevention_weight(self, verdict: str) -> float:
        if verdict == "malicious":
            return self.verdict_prevention_weight_malicious
        if verdict == "suspicious":
            return self.verdict_prevention_weight_suspicious
        return 0.0

    def avg_loss_for_attack_type(self, attack_type: str) -> float:
        return {
            "bec": self.bec_avg_loss_usd,
            "credential_phishing": self.credential_phishing_avg_loss_usd,
            "generic_phishing": self.generic_phishing_avg_loss_usd,
        }[attack_type]

    def to_response_dict(self) -> dict[str, dict[str, object]]:
        """Every assumption used by the risk model, value + a short source string —
        the structural guarantee that a dollar figure is never returned without its
        inputs (see sources.md for the full citation)."""
        return {
            "bec_avg_loss_usd": {
                "value": self.bec_avg_loss_usd,
                "source": "FBI IC3 2024 Internet Crime Report: $2.77B BEC losses / 21,442 "
                "complaints",
            },
            "credential_phishing_avg_loss_usd": {
                "value": self.credential_phishing_avg_loss_usd,
                "source": "IBM/DeepStrike/Hoxhunt (via totalassure.com) QR-code phishing "
                "avg incident cost, used as conservative proxy",
            },
            "generic_phishing_avg_loss_usd": {
                "value": self.generic_phishing_avg_loss_usd,
                "source": "Same proxy as credential_phishing_avg_loss_usd — no distinct "
                "verified figure for this bucket",
            },
            "verdict_prevention_weight_malicious": {
                "value": self.verdict_prevention_weight_malicious,
                "source": "Operator judgment call (default: full weight for high-confidence "
                "malicious verdicts)",
            },
            "verdict_prevention_weight_suspicious": {
                "value": self.verdict_prevention_weight_suspicious,
                "source": "Operator judgment call (default: 0 — suspicious verdicts are "
                "lower-confidence)",
            },
        }


risk_assumptions = RiskModelAssumptions()
