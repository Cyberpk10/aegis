from __future__ import annotations

import json
from pathlib import Path

from app.channels.message import Channel
from app.channels.teams_adapter import normalize_teams_message

FIXTURES_DIR = Path(__file__).parent.parent / "fixtures" / "channels"


def _load(filename: str) -> dict:
    return json.loads((FIXTURES_DIR / filename).read_text())


def test_normalizes_a_benign_channel_message():
    message = normalize_teams_message(_load("teams_benign.json"))

    assert message.channel == Channel.TEAMS
    assert message.from_display == "Alice Smith"
    assert message.from_address == "alice@corp.com"
    assert message.body_text == "Good morning team! Standup in 10 minutes."
    assert message.links == []
    assert message.is_direct_message is False
    assert message.is_external_sender is False
    assert message.channel_name == "19:general@thread.tacv2"


def test_normalizes_an_external_guest_chat_with_a_link():
    message = normalize_teams_message(_load("teams_external_dm_link.json"))

    assert message.channel == Channel.TEAMS
    assert message.is_direct_message is True
    assert message.is_external_sender is True
    assert len(message.links) == 1
    assert message.links[0].href_domain == "bit.ly"


def test_extracts_mentions():
    payload = _load("teams_benign.json")
    payload = {
        **payload,
        "mentions": [{"mentioned": {"user": {"displayName": "Bob Jones"}}}],
    }

    message = normalize_teams_message(payload)

    assert message.mentions == ["Bob Jones"]


def test_strips_html_content_type():
    payload = _load("teams_benign.json")
    payload = {
        **payload,
        "body": {"contentType": "html", "content": "<p>Hello <b>team</b></p>"},
    }

    message = normalize_teams_message(payload)

    assert "Hello" in message.body_text
    assert "team" in message.body_text
    assert "<p>" not in message.body_text
