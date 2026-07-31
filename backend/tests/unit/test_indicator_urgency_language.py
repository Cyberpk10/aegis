from __future__ import annotations

from app.indicators import urgency_language
from app.parsing.eml_parser import ParsedEmail


def test_flags_urgency_phrases():
    email = ParsedEmail(
        subject="Final Notice",
        body_text="Act now, your account will be suspended within 24 hours.",
    )
    indicators = urgency_language.evaluate(email)
    assert len(indicators) == 1
    assert indicators[0].id == "URGENCY_LANGUAGE"
    assert indicators[0].score > 0


def test_no_flag_for_neutral_text():
    email = ParsedEmail(
        subject="Scheduled Maintenance This Weekend",
        body_text="Our team will be performing routine maintenance on Saturday evening.",
    )
    assert urgency_language.evaluate(email) == []


def test_score_scales_with_match_count_but_is_capped():
    light = ParsedEmail(subject="", body_text="This is urgent.")
    heavy = ParsedEmail(
        subject="",
        body_text=(
            "This is urgent, act now, final notice, your account will be suspended, "
            "verify your account immediately, within 24 hours, act immediately."
        ),
    )
    light_score = urgency_language.evaluate(light)[0].score
    heavy_score = urgency_language.evaluate(heavy)[0].score
    assert heavy_score > light_score
    assert heavy_score <= 16
