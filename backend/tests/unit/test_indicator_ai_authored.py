from __future__ import annotations

from app.indicators import ai_authored
from app.models.schemas import Severity
from app.parsing.eml_parser import ParsedEmail


def test_no_flag_for_empty_or_short_body():
    assert ai_authored.evaluate(ParsedEmail(subject="Hi", body_text="")) == []
    assert ai_authored.evaluate(ParsedEmail(subject="Hi", body_text="Quick note, see you soon.")) == []


def test_stylometric_regularity_signal_fires_on_uniform_paragraphs():
    body = (
        "Alpha bravo charlie delta echo foxtrot golf hotel.\n\n"
        "Kilo lima mike november oscar papa quebec romeo.\n\n"
        "Sierra tango uniform victor whiskey xray yankee zulu."
    )
    fired, reason = ai_authored._check_stylometric_regularity(body)
    assert fired is True
    assert "uniform" in reason


def test_stylometric_regularity_signal_does_not_fire_on_varied_paragraphs():
    body = (
        "Short one.\n\n"
        "This paragraph on the other hand is considerably longer and rambles on for quite a "
        "while about many different unrelated topics before finally wrapping up completely.\n\n"
        "Mid length paragraph with a handful of words in it here today."
    )
    fired, _ = ai_authored._check_stylometric_regularity(body)
    assert fired is False


def test_low_burstiness_signal_fires_on_uniform_sentence_lengths():
    body = "This is fine today. That is good news. Things look nice now. All seems well here."
    fired, reason = ai_authored._check_low_burstiness(body)
    assert fired is True
    assert "burstiness" in reason.lower()


def test_low_burstiness_signal_does_not_fire_on_varied_sentence_lengths():
    body = (
        "No. "
        "That is genuinely surprising to hear about given everything that happened last week. "
        "Okay then. "
        "I suppose we should probably talk about this more later when we both have time."
    )
    fired, _ = ai_authored._check_low_burstiness(body)
    assert fired is False


def test_template_formatting_signal_requires_both_greeting_and_signoff():
    with_both = "Dear Team,\n\nSome content here.\n\nBest regards,\nOps"
    fired, _ = ai_authored._check_template_formatting(with_both)
    assert fired is True

    greeting_only = "Dear Team,\n\nSome content here without a matching sign-off line.\n\nThanks a bunch,\nOps"
    fired2, _ = ai_authored._check_template_formatting(greeting_only)
    assert fired2 is False


def test_generic_fluent_signal_requires_enough_words_matches_and_no_idiosyncrasy():
    fluent_clean = (
        "I hope this email finds you well. I wanted to reach out regarding an update on our "
        "shared project timeline and next steps for the coming weeks ahead of the deadline "
        "that we discussed in our last meeting together as a team."
    )
    fired, _ = ai_authored._check_generic_fluent_no_idiosyncrasy(fluent_clean)
    assert fired is True

    fluent_but_casual = fluent_clean + " Can't wait to get started!!!"
    fired2, _ = ai_authored._check_generic_fluent_no_idiosyncrasy(fluent_but_casual)
    assert fired2 is False

    too_few_phrases = "I hope this email finds you well and that things are going alright for you lately."
    fired3, _ = ai_authored._check_generic_fluent_no_idiosyncrasy(too_few_phrases)
    assert fired3 is False


def test_evaluate_fires_only_when_at_least_three_signals_present():
    # Exactly 3 of 4 signals: low burstiness + template formatting + generic-fluent
    # (paragraph regularity is not engineered to fire in this example).
    body = (
        "Dear Team,\n\n"
        "I hope this email finds you well today. I wanted to reach out about our shared "
        "plan. Moving forward we will update the full project timeline soon. Please let us "
        "know about any questions you may have.\n\n"
        "Best regards,\nOperations"
    )
    indicators = ai_authored.evaluate(ParsedEmail(subject="Project Update", body_text=body))

    assert len(indicators) == 1
    indicator = indicators[0]
    assert indicator.id == "AI_AUTHORED_SUSPECTED"
    assert indicator.category == "authorship"
    assert indicator.severity == Severity.MEDIUM
    assert indicator.score == 10
    assert len(indicator.evidence) == 3


def test_evaluate_does_not_fire_with_only_two_signals():
    # Template formatting + generic-fluent fire; sentences are deliberately varied in
    # length so burstiness does not also fire, keeping this under the 3-signal floor.
    body = (
        "Dear Team,\n\n"
        "Hi. I hope this email finds you well today. Please let me know if you have any "
        "questions whenever you get a chance to look over the attached document at some "
        "point before our meeting next week if that works for your schedule.\n\n"
        "Best regards,\nOperations"
    )
    fired = [c for c, _ in [
        ai_authored._check_stylometric_regularity(body),
        ai_authored._check_low_burstiness(body),
        ai_authored._check_template_formatting(body),
        ai_authored._check_generic_fluent_no_idiosyncrasy(body),
    ] if c]
    assert len(fired) < 3  # sanity-check the fixture is actually under threshold

    assert ai_authored.evaluate(ParsedEmail(subject="", body_text=body)) == []


def test_evaluate_does_not_fire_on_natural_human_email():
    body = (
        "Hey Sarah,\n\n"
        "Quick update — I finally got the vendor contract sorted out! Took forever but "
        "we're good to go now.\n\n"
        "Can you take a look at the attached doc when you get a sec? No rush, just want to "
        "make sure I didn't miss anything before I send it over.\n\n"
        "Thanks!\nMike"
    )
    assert ai_authored.evaluate(ParsedEmail(subject="Vendor contract", body_text=body)) == []
