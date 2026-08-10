"""Look-alike / homoglyph / typosquat domain detection against a curated brand list.

Purely offline and deterministic: compares sender and link domains against
`app/indicators/data/brands.yaml` using confusable-character normalization, edit distance, and
punycode (IDN) detection. No DNS or network calls are made.
"""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path

import yaml

from app.indicators.base import make_indicator
from app.indicators.domain_utils import levenshtein, registrable_domain
from app.models.schemas import Indicator, Severity
from app.channels.message import Message

_BRANDS_PATH = Path(__file__).parent / "data" / "brands.yaml"

# Maps visually-confusable characters (including common Cyrillic homoglyphs) to their Latin
# look-alike, so e.g. "micrоsoft.com" (Cyrillic о) normalizes to "microsoft.com".
_CONFUSABLE_MAP = {
    "0": "o", "1": "l", "3": "e", "5": "s", "7": "t",
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "х": "x", "у": "y", "і": "i", "ѕ": "s",
}

_MAX_TYPOSQUAT_DISTANCE = 2


@lru_cache(maxsize=1)
def _load_brands() -> list[tuple[str, str]]:
    """Returns list of (brand_name, canonical_domain) pairs."""
    with _BRANDS_PATH.open("r", encoding="utf-8") as f:
        data = yaml.safe_load(f)
    pairs: list[tuple[str, str]] = []
    for brand in data.get("brands", []):
        name = brand["name"]
        for domain in brand.get("domains", []):
            pairs.append((name, domain.lower()))
    return pairs


def _normalize_confusables(domain: str) -> str:
    return "".join(_CONFUSABLE_MAP.get(ch, ch) for ch in domain)


def _is_punycode(domain: str) -> bool:
    return any(label.startswith("xn--") for label in domain.split("."))


def _candidate_domains(email: Message) -> set[str]:
    domains: set[str] = set()
    if email.from_address and "@" in email.from_address:
        domains.add(email.from_address.rsplit("@", 1)[-1].lower())
    for link in email.links:
        if link.href_domain:
            domains.add(link.href_domain.lower())
    return domains


def evaluate(email: Message) -> list[Indicator]:
    indicators: list[Indicator] = []
    brands = _load_brands()
    brand_domains = {domain for _, domain in brands}

    flagged_domains: set[str] = set()

    for domain in sorted(_candidate_domains(email)):
        reg_domain = registrable_domain(domain)

        if reg_domain in brand_domains:
            continue  # exact match to a known-good brand domain — not a look-alike

        if _is_punycode(domain):
            indicators.append(
                make_indicator(
                    id="PUNYCODE_IDN_DOMAIN",
                    category="domain",
                    title="Internationalized (punycode) domain",
                    description=(
                        "A domain uses punycode (xn--) encoding, which is frequently used to "
                        "register visually-confusable internationalized look-alike domains."
                    ),
                    evidence=[f"Domain: {domain}"],
                    severity=Severity.MEDIUM,
                    score=15,
                )
            )
            flagged_domains.add(domain)

        normalized = _normalize_confusables(reg_domain)
        homoglyph_match = next((bd for bd in brand_domains if normalized == bd), None)
        if homoglyph_match and domain not in flagged_domains:
            indicators.append(
                make_indicator(
                    id="LOOKALIKE_DOMAIN",
                    category="domain",
                    title="Homoglyph look-alike of a known brand domain",
                    description=(
                        f"Domain '{domain}' visually mimics the trusted domain "
                        f"'{homoglyph_match}' using confusable characters."
                    ),
                    evidence=[f"Domain: {domain}", f"Mimics: {homoglyph_match}"],
                    severity=Severity.HIGH,
                    score=25,
                )
            )
            flagged_domains.add(domain)
            continue

        closest = min(
            ((bd, levenshtein(reg_domain, bd)) for bd in brand_domains),
            key=lambda pair: pair[1],
            default=None,
        )
        if (
            closest
            and 0 < closest[1] <= _MAX_TYPOSQUAT_DISTANCE
            and domain not in flagged_domains
        ):
            brand_domain, distance = closest
            indicators.append(
                make_indicator(
                    id="LOOKALIKE_DOMAIN",
                    category="domain",
                    title="Typosquat look-alike of a known brand domain",
                    description=(
                        f"Domain '{domain}' is a near-exact match (edit distance {distance}) of "
                        f"the trusted domain '{brand_domain}'."
                    ),
                    evidence=[f"Domain: {domain}", f"Mimics: {brand_domain}"],
                    severity=Severity.HIGH,
                    score=25,
                )
            )
            flagged_domains.add(domain)
            continue

        for brand_name, brand_domain in brands:
            slug = brand_name.lower().replace(" ", "")
            if slug in normalized and domain not in flagged_domains:
                indicators.append(
                    make_indicator(
                        id="LOOKALIKE_DOMAIN",
                        category="domain",
                        title="Brand name used in an unrelated domain",
                        description=(
                            f"Domain '{domain}' contains the brand name '{brand_name}' but is "
                            f"not the brand's real domain ('{brand_domain}')."
                        ),
                        evidence=[f"Domain: {domain}", f"Brand referenced: {brand_name}"],
                        severity=Severity.HIGH,
                        score=20,
                    )
                )
                flagged_domains.add(domain)
                break

    return indicators
