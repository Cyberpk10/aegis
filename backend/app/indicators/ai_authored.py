"""Explainable, offline heuristics estimating whether a message was likely AI/LLM-authored.

This is a stylometric signal, not a content signal — it looks at *how* the text is
constructed (sentence/paragraph regularity, template structure, generic fluent phrasing)
rather than *what* it says. Deliberately scored low: AI-authorship alone is corroborating
evidence, not proof of malicious intent — plenty of legitimate business email is AI-drafted
today too.

Future extension point: an optional model-based secondary signal could be added here behind
a config flag (e.g. settings.enable_ai_authorship_model), falling back to this heuristic-only
path whenever the flag is off or a model call fails/is unavailable. Not implemented in this
stage — heuristics only, fully offline and deterministic, no network call.
"""

from __future__ import annotations

import re
import statistics

from app.indicators.base import make_indicator
from app.models.schemas import Indicator, Severity
from app.parsing.eml_parser import ParsedEmail

_MIN_SENTENCES_FOR_BURSTINESS = 3
_MIN_PARAGRAPHS_FOR_REGULARITY = 2
_MIN_WORDS_FOR_FLUENCY_CHECK = 40
_LOW_CV_THRESHOLD = 0.35
_MIN_FLUENT_PHRASE_MATCHES = 2
_MIN_SIGNALS_TO_FIRE = 3

_SENTENCE_SPLIT_RE = re.compile(r"[.!?]+(?:\s+|$)")
_PARAGRAPH_SPLIT_RE = re.compile(r"\n\s*\n")
_WORD_RE = re.compile(r"[A-Za-z'’]+")

_GREETING_RE = re.compile(
    r"^\s*(dear|hi|hello|good (morning|afternoon|evening))\b.{0,40}[,:]?\s*$",
    re.IGNORECASE | re.MULTILINE,
)
_SIGNOFF_RE = re.compile(
    r"^\s*(best regards|kind regards|warm regards|best wishes|sincerely|regards|best|thank you)[,.]?\s*$",
    re.IGNORECASE | re.MULTILINE,
)

_FLUENT_FILLER_PHRASES = [
    r"i hope this email finds you well",
    r"i hope this message finds you well",
    r"i wanted to reach out",
    r"please don.t hesitate to reach out",
    r"please do not hesitate to (?:reach out|contact)",
    r"feel free to (?:reach out|contact)",
    r"moving forward",
    r"at your earliest convenience",
    r"should you have any questions",
    r"i look forward to (?:hearing from you|your response)",
    r"thank you for your (?:understanding|time and attention|attention)",
    r"it.s (?:important|worth) (?:to )?not(?:e|ing) that",
    r"in today.s (?:fast-paced|digital|ever-changing) world",
    r"please let me know if you have any questions",
]
_FLUENT_PATTERN = re.compile("|".join(f"(?:{p})" for p in _FLUENT_FILLER_PHRASES), re.IGNORECASE)

_CONTRACTION_RE = re.compile(r"\b\w+'(?:t|re|ve|ll|d|s|m)\b", re.IGNORECASE)
_EMPHASIS_RE = re.compile(r"!{2,}")
_ELLIPSIS_RE = re.compile(r"\.\.\.|…")
_ALLCAPS_WORD_RE = re.compile(r"\b[A-Z]{4,}\b")
_EMOJI_RE = re.compile("[\U0001F300-\U0001FAFF\U00002600-\U000027BF]")


def _words(text: str) -> list[str]:
    return _WORD_RE.findall(text)


def _coefficient_of_variation(counts: list[int]) -> float | None:
    if len(counts) < 2:
        return None
    mean = statistics.mean(counts)
    if mean == 0:
        return None
    return statistics.pstdev(counts) / mean


def _check_stylometric_regularity(body_text: str) -> tuple[bool, str | None]:
    """Signal 1: unusually uniform paragraph lengths."""
    paragraphs = [p for p in _PARAGRAPH_SPLIT_RE.split(body_text) if p.strip()]
    if len(paragraphs) < _MIN_PARAGRAPHS_FOR_REGULARITY:
        return False, None
    cv = _coefficient_of_variation([len(_words(p)) for p in paragraphs])
    if cv is not None and cv < _LOW_CV_THRESHOLD:
        return True, f"Paragraph lengths are unusually uniform (coefficient of variation {cv:.2f})"
    return False, None


def _check_low_burstiness(body_text: str) -> tuple[bool, str | None]:
    """Signal 2: unusually uniform sentence lengths (low burstiness)."""
    sentences = [s for s in _SENTENCE_SPLIT_RE.split(body_text) if s.strip()]
    if len(sentences) < _MIN_SENTENCES_FOR_BURSTINESS:
        return False, None
    cv = _coefficient_of_variation([len(_words(s)) for s in sentences])
    if cv is not None and cv < _LOW_CV_THRESHOLD:
        return True, f"Sentence lengths are unusually uniform / low burstiness (coefficient of variation {cv:.2f})"
    return False, None


def _check_template_formatting(body_text: str) -> tuple[bool, str | None]:
    """Signal 3: a recognizable template greeting-and-sign-off skeleton."""
    if _GREETING_RE.search(body_text) and _SIGNOFF_RE.search(body_text):
        return True, "Contains a template greeting-and-sign-off structure typical of generated boilerplate"
    return False, None


def _check_generic_fluent_no_idiosyncrasy(text: str) -> tuple[bool, str | None]:
    """Signal 4: generic, fluent transitional phrasing with zero human idiosyncrasy
    markers (contractions, emphasis, ellipses, ALL-CAPS emphasis, emoji)."""
    if len(_words(text)) < _MIN_WORDS_FOR_FLUENCY_CHECK:
        return False, None

    fluent_matches = sorted({m.group(0).strip().lower() for m in _FLUENT_PATTERN.finditer(text)})
    if len(fluent_matches) < _MIN_FLUENT_PHRASE_MATCHES:
        return False, None

    has_idiosyncrasy = any(
        pattern.search(text)
        for pattern in (_CONTRACTION_RE, _EMPHASIS_RE, _ELLIPSIS_RE, _ALLCAPS_WORD_RE, _EMOJI_RE)
    )
    if has_idiosyncrasy:
        return False, None

    example = ", ".join(repr(p) for p in fluent_matches[:3])
    return True, (
        f"Generic, fluent transitional phrasing ({example}) with no contractions, emphasis, "
        "or other human idiosyncrasy"
    )


def evaluate(email: ParsedEmail) -> list[Indicator]:
    body_text = email.body_text or ""
    full_text = " ".join(filter(None, [email.subject, body_text]))

    checks = [
        _check_stylometric_regularity(body_text),
        _check_low_burstiness(body_text),
        _check_template_formatting(body_text),
        _check_generic_fluent_no_idiosyncrasy(full_text),
    ]
    fired_reasons = [reason for did_fire, reason in checks if did_fire]

    # Require co-occurrence of most signals, not any single one — any one signal alone is
    # too weak and would false-positive on plenty of genuinely human, well-edited formal
    # writing. This threshold is the guardrail protecting analyst trust in the flag.
    if len(fired_reasons) < _MIN_SIGNALS_TO_FIRE:
        return []

    score = 10 + 4 * (len(fired_reasons) - _MIN_SIGNALS_TO_FIRE)

    return [
        make_indicator(
            id="AI_AUTHORED_SUSPECTED",
            category="authorship",
            title="Likely AI-generated text",
            description=(
                "The message's writing style shows multiple markers consistent with "
                "machine/LLM-generated text (uniform sentence/paragraph structure, template "
                "formatting, and generic fluent phrasing with no human idiosyncrasy). This is "
                "a corroborating stylistic signal, not proof of malicious intent — legitimate "
                "AI-drafted business email is common."
            ),
            evidence=fired_reasons,
            severity=Severity.MEDIUM,
            score=score,
        )
    ]
