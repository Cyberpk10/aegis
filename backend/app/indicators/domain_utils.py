"""Shared, dependency-free domain helpers used by multiple indicator rules."""

from __future__ import annotations

# Common multi-label public suffixes. Not exhaustive (no full Public Suffix List bundled to
# keep the engine dependency-free and fully offline) — good enough for the common brand/TLD
# cases M1 targets. Extend as needed in later milestones.
_MULTI_LABEL_SUFFIXES = {
    "co.uk", "org.uk", "ac.uk", "gov.uk",
    "co.jp", "co.in", "co.kr", "co.nz", "co.za",
    "com.au", "com.br", "com.cn", "com.mx", "com.sg",
}


def registrable_domain(domain: str) -> str:
    """Best-effort extraction of the registrable ("brand") portion of a domain.

    e.g. "login.paypa1-secure.com" -> "paypa1-secure.com", "mail.example.co.uk" -> "example.co.uk"
    """
    domain = domain.lower().strip(".")
    labels = domain.split(".")
    if len(labels) <= 2:
        return domain
    last_two = ".".join(labels[-2:])
    if last_two in _MULTI_LABEL_SUFFIXES and len(labels) >= 3:
        return ".".join(labels[-3:])
    return last_two


def levenshtein(a: str, b: str) -> int:
    """Standard edit distance, O(len(a)*len(b)), fine for short domain strings."""
    if a == b:
        return 0
    if not a:
        return len(b)
    if not b:
        return len(a)

    previous_row = list(range(len(b) + 1))
    for i, char_a in enumerate(a, start=1):
        current_row = [i]
        for j, char_b in enumerate(b, start=1):
            insert_cost = current_row[j - 1] + 1
            delete_cost = previous_row[j] + 1
            substitute_cost = previous_row[j - 1] + (char_a != char_b)
            current_row.append(min(insert_cost, delete_cost, substitute_cost))
        previous_row = current_row
    return previous_row[-1]


def is_ip_literal_host(host: str) -> bool:
    parts = host.split(".")
    if len(parts) != 4:
        return False
    return all(part.isdigit() and 0 <= int(part) <= 255 for part in parts)
