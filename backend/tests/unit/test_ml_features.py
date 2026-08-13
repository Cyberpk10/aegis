from __future__ import annotations

from app.ml.features import INDICATOR_FEATURE_IDS, build_structured_features, feature_names
from app.models.schemas import Indicator, Severity
from app.parsing.eml_parser import ParsedEmail
from app.channels.message import Attachment, Link


def _indicator(indicator_id: str, score: float) -> Indicator:
    return Indicator(
        id=indicator_id,
        category="test",
        title="test",
        description="test",
        evidence=[],
        severity=Severity.LOW,
        score=score,
    )


def test_feature_names_matches_indicator_ids_plus_aggregates():
    names = feature_names()
    assert names[: len(INDICATOR_FEATURE_IDS)] == [
        f"indicator_{i}" for i in INDICATOR_FEATURE_IDS
    ]
    assert names[len(INDICATOR_FEATURE_IDS) :] == [
        "total_rule_score",
        "indicator_count",
        "link_count",
        "attachment_count",
        "body_length_log",
    ]


def test_fired_indicator_populates_its_column_others_default_to_zero():
    email = ParsedEmail(body_text="hello")
    features = build_structured_features(email, [_indicator("LOOKALIKE_DOMAIN", 25.0)])

    assert features["indicator_LOOKALIKE_DOMAIN"] == 25.0
    assert features["indicator_URGENCY_LANGUAGE"] == 0.0
    assert features["indicator_AI_AUTHORED_SUSPECTED"] == 0.0


def test_aggregate_features_reflect_the_email_and_indicator_list():
    email = ParsedEmail(
        body_text="x" * 10,
        links=[
            Link(display_text="a", href="http://a", href_domain="a"),
            Link(display_text="b", href="http://b", href_domain="b"),
        ],
        attachments=[
            Attachment(filename="f.exe", content_type="application/octet-stream", size_bytes=100)
        ],
    )
    indicators = [_indicator("LOOKALIKE_DOMAIN", 25.0), _indicator("URGENCY_LANGUAGE", 10.0)]

    features = build_structured_features(email, indicators)

    assert features["total_rule_score"] == 35.0
    assert features["indicator_count"] == 2.0
    assert features["link_count"] == 2.0
    assert features["attachment_count"] == 1.0
    assert features["body_length_log"] > 0.0


def test_no_indicators_is_all_zero_except_body_length():
    email = ParsedEmail(body_text="hello")
    features = build_structured_features(email, [])

    for indicator_id in INDICATOR_FEATURE_IDS:
        assert features[f"indicator_{indicator_id}"] == 0.0
    assert features["total_rule_score"] == 0.0
    assert features["indicator_count"] == 0.0
    assert features["link_count"] == 0.0
    assert features["attachment_count"] == 0.0


def test_repeated_indicator_id_sums_rather_than_overwrites():
    """No current rule fires the same id twice, but nothing structurally guarantees that —
    build_structured_features must sum, not silently drop, a repeat."""
    email = ParsedEmail(body_text="hello")
    features = build_structured_features(
        email, [_indicator("URGENCY_LANGUAGE", 10.0), _indicator("URGENCY_LANGUAGE", 5.0)]
    )
    assert features["indicator_URGENCY_LANGUAGE"] == 15.0
