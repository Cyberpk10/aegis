"""Deterministic credential-harvesting and payment/wire-transfer request detection."""

from __future__ import annotations

import re

from app.indicators.base import make_indicator
from app.models.schemas import Indicator, Severity
from app.parsing.eml_parser import ParsedEmail

_CREDENTIAL_PHRASES = [
    r"verify your (?:password|account|identity|login|credentials)",
    r"confirm your (?:account|password|identity|login|details)",
    r"(?:enter|update|re-?enter) your (?:password|login|credentials)",
    r"click here to (?:verify|confirm|log ?in|sign ?in)",
    r"log ?in to (?:confirm|verify|update)",
    r"your (?:password|account) (?:will expire|has expired)",
    r"unusual (?:sign-?in|login) activity",
    r"confirm your (?:credit card|billing) (?:information|details)",
    r"update your payment information",
    r"security alert.{0,20}(?:verify|confirm)",
]

_PAYMENT_PHRASES = [
    r"wire transfer",
    r"bank (?:account|routing) (?:number|details)",
    r"gift cards?",
    r"purchase (?:several |some )?gift cards",
    r"process(?:ing)? (?:an? )?(?:urgent )?payment",
    r"send (?:the )?funds",
    r"invoice (?:is )?attached.{0,20}pay",
    r"outstanding (?:invoice|balance|payment)",
    r"update your (?:direct deposit|banking) (?:information|details)",
    r"change of (?:bank|payment) (?:details|information)",
]

_CREDENTIAL_PATTERN = re.compile("|".join(f"(?:{p})" for p in _CREDENTIAL_PHRASES), re.IGNORECASE)
_PAYMENT_PATTERN = re.compile("|".join(f"(?:{p})" for p in _PAYMENT_PHRASES), re.IGNORECASE)


def _build_indicator(id_: str, title: str, description: str, matches: list[str]) -> Indicator:
    severity = Severity.HIGH if len(matches) >= 2 else Severity.MEDIUM
    score = min(30, 15 * len(matches))
    return make_indicator(
        id=id_,
        category="content",
        title=title,
        description=description,
        evidence=[f"Matched phrase: {m!r}" for m in matches],
        severity=severity,
        score=score,
    )


def evaluate(email: ParsedEmail) -> list[Indicator]:
    text = " ".join(filter(None, [email.subject, email.body_text]))
    indicators: list[Indicator] = []

    credential_matches = sorted({m.group(0).strip().lower() for m in _CREDENTIAL_PATTERN.finditer(text)})
    if credential_matches:
        indicators.append(
            _build_indicator(
                "CREDENTIAL_REQUEST",
                "Credential-harvesting language detected",
                "The message asks the recipient to verify, confirm, or re-enter login "
                "credentials or account details — a hallmark of credential-phishing.",
                credential_matches,
            )
        )

    payment_matches = sorted({m.group(0).strip().lower() for m in _PAYMENT_PATTERN.finditer(text)})
    if payment_matches:
        indicators.append(
            _build_indicator(
                "PAYMENT_REQUEST",
                "Payment / wire-transfer request language detected",
                "The message requests a payment, wire transfer, gift cards, or a change to "
                "banking/payment details — common in business-email-compromise (BEC) fraud.",
                payment_matches,
            )
        )

    return indicators
