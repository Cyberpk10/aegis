"""SPF/DKIM/DMARC authentication-failure indicators, from the parsed Authentication-Results header."""

from __future__ import annotations

from app.indicators.base import make_indicator
from app.models.schemas import AuthResultValue, Indicator, Severity
from app.parsing.eml_parser import ParsedEmail

_FAILING_RESULTS = {AuthResultValue.FAIL, AuthResultValue.SOFTFAIL, AuthResultValue.PERMERROR}

_CHECKS = [
    ("spf", "AUTH_SPF_FAIL", "SPF authentication failed"),
    ("dkim", "AUTH_DKIM_FAIL", "DKIM authentication failed"),
    ("dmarc", "AUTH_DMARC_FAIL", "DMARC authentication failed"),
]


def evaluate(email: ParsedEmail) -> list[Indicator]:
    indicators: list[Indicator] = []
    auth = email.auth_results

    for attr, indicator_id, title in _CHECKS:
        result: AuthResultValue = getattr(auth, attr)
        if result not in _FAILING_RESULTS:
            continue
        severity = Severity.HIGH if result == AuthResultValue.FAIL else Severity.MEDIUM
        score = 15 if result == AuthResultValue.FAIL else 8
        indicators.append(
            make_indicator(
                id=indicator_id,
                category="authentication",
                title=title,
                description=(
                    f"The mail server's Authentication-Results header reports {attr.upper()}="
                    f"{result.value} for this message, indicating it may not genuinely originate "
                    "from the claimed sending domain."
                ),
                evidence=[f"{attr.upper()} result: {result.value}"]
                + ([f"Raw header: {auth.raw_header}"] if auth.raw_header else []),
                severity=severity,
                score=score,
            )
        )

    return indicators
