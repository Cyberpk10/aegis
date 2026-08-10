from __future__ import annotations

import json
from pathlib import Path

from app.channels.message import Channel
from app.channels.slack_adapter import normalize_slack_message

FIXTURES_DIR = Path(__file__).parent.parent / "fixtures" / "channels"


def _load(filename: str) -> dict:
    return json.loads((FIXTURES_DIR / filename).read_text())


def test_normalizes_a_benign_public_channel_message():
    message = normalize_slack_message(_load("slack_benign.json"))

    assert message.channel == Channel.SLACK
    assert message.from_display == "alice"
    assert message.from_address == "alice@corp.com"
    assert message.body_text == "Good morning team! Standup in 10 minutes."
    assert message.links == []
    assert message.is_direct_message is False
    assert message.is_external_sender is False
    assert message.channel_name == "general"


def test_normalizes_an_external_dm_with_a_link():
    message = normalize_slack_message(_load("slack_external_dm_link.json"))

    assert message.channel == Channel.SLACK
    assert message.is_direct_message is True
    assert message.is_external_sender is True
    assert len(message.links) == 1
    assert message.links[0].href == "http://bit.ly/verify-now-123"
    assert message.links[0].href_domain == "bit.ly"


def test_extracts_mentions_and_strips_mention_markup():
    payload = _load("slack_benign.json")
    payload = {**payload, "text": "Hey <@U222>, can you review this?"}

    message = normalize_slack_message(payload)

    assert message.mentions == ["U222"]
    assert "<@U222>" not in message.body_text
    assert "@U222" in message.body_text
