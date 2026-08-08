"""End-to-end wiring check for the AI_AUTHORED_SUSPECTED indicator: real .eml fixtures
parsed through app.parsing.eml_parser.parse_eml and run through the full indicator
engine (app.indicators.engine.run_indicators), not just the isolated evaluate() function.
This is the guardrail test protecting analyst trust in the flag — it must fire on
AI-styled content and must not false-positive on natural human business email.
"""

from __future__ import annotations

from app.indicators.engine import run_indicators


def test_ai_style_phishing_fixture_flags_ai_authored(parse_fixture):
    email = parse_fixture("ai_style_phishing_request.eml")
    indicators = run_indicators(email)

    ai_indicators = [i for i in indicators if i.id == "AI_AUTHORED_SUSPECTED"]
    assert len(ai_indicators) == 1
    assert ai_indicators[0].severity.value == "medium"
    assert len(ai_indicators[0].evidence) >= 3


def test_ai_style_corporate_update_fixture_flags_ai_authored(parse_fixture):
    email = parse_fixture("ai_style_corporate_update.eml")
    indicators = run_indicators(email)

    ai_indicators = [i for i in indicators if i.id == "AI_AUTHORED_SUSPECTED"]
    assert len(ai_indicators) == 1

    # This fixture has no malicious content — proves the detection is style-based,
    # not content-based, since it fires without any content-risk indicator alongside it.
    other_content_risk_ids = {"CREDENTIAL_REQUEST", "PAYMENT_REQUEST", "URGENCY_LANGUAGE"}
    assert not any(i.id in other_content_risk_ids for i in indicators)


def test_natural_human_email_fixture_does_not_flag_ai_authored(parse_fixture):
    email = parse_fixture("natural_human_business_email.eml")
    indicators = run_indicators(email)

    assert [i for i in indicators if i.id == "AI_AUTHORED_SUSPECTED"] == []
