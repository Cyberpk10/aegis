"""Parses the `Authentication-Results` header(s) of an email into SPF/DKIM/DMARC verdicts.

This module only reads results that a receiving mail server already stamped onto the message.
Aegis does not perform its own SPF/DKIM/DMARC verification or any live DNS lookups.
"""

from __future__ import annotations

import re

from app.models.schemas import AuthResults, AuthResultValue

_VALID_RESULTS = {r.value for r in AuthResultValue if r is not AuthResultValue.UNKNOWN}

# Matches e.g. "spf=pass", "dkim = fail", "dmarc=softfail" anywhere in the header value.
_MECHANISM_RE = re.compile(
    r"\b(?P<mechanism>spf|dkim|dmarc)\s*=\s*(?P<result>[a-zA-Z]+)", re.IGNORECASE
)


def parse_authentication_results(header_values: list[str]) -> AuthResults:
    """Parse one or more raw `Authentication-Results` header strings into an AuthResults model.

    A message may carry multiple `Authentication-Results` headers (e.g. one per hop / one per
    trusted authserv-id). The first recognized result for each mechanism wins, mirroring how
    most mail clients surface the most recent (topmost) hop's verdict.
    """
    found: dict[str, str] = {}
    raw_parts: list[str] = []

    for header_value in header_values:
        if not header_value:
            continue
        raw_parts.append(header_value.strip())
        for match in _MECHANISM_RE.finditer(header_value):
            mechanism = match.group("mechanism").lower()
            result = match.group("result").lower()
            if mechanism in found:
                continue
            found[mechanism] = result if result in _VALID_RESULTS else AuthResultValue.UNKNOWN.value

    return AuthResults(
        spf=AuthResultValue(found.get("spf", AuthResultValue.UNKNOWN.value)),
        dkim=AuthResultValue(found.get("dkim", AuthResultValue.UNKNOWN.value)),
        dmarc=AuthResultValue(found.get("dmarc", AuthResultValue.UNKNOWN.value)),
        raw_header=" | ".join(raw_parts) if raw_parts else None,
    )
