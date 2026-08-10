from __future__ import annotations

import json
from pathlib import Path

from app.channels.message import Message
from app.channels.slack_adapter import normalize_slack_message
from app.channels.teams_adapter import normalize_teams_message
from app.core.config import settings
from app.indicators import chat_context

FIXTURES_DIR = Path(__file__).parent.parent / "fixtures" / "channels"


def _slack(filename: str) -> Message:
    return normalize_slack_message(json.loads((FIXTURES_DIR / filename).read_text()))


def _teams(filename: str) -> Message:
    return normalize_teams_message(json.loads((FIXTURES_DIR / filename).read_text()))


def test_never_fires_for_an_email_message():
    assert chat_context.evaluate(Message()) == []


def test_benign_slack_message_has_no_chat_indicators():
    assert chat_context.evaluate(_slack("slack_benign.json")) == []


def test_benign_teams_message_has_no_chat_indicators():
    assert chat_context.evaluate(_teams("teams_benign.json")) == []


def test_external_dm_with_link_fires_on_slack():
    ids = {i.id for i in chat_context.evaluate(_slack("slack_external_dm_link.json"))}
    assert "EXTERNAL_DM_WITH_LINK" in ids


def test_external_dm_with_link_fires_on_teams():
    ids = {i.id for i in chat_context.evaluate(_teams("teams_external_dm_link.json"))}
    assert "EXTERNAL_DM_WITH_LINK" in ids


def test_suspicious_link_public_channel_fires_on_slack():
    ids = {i.id for i in chat_context.evaluate(_slack("slack_suspicious_public_link.json"))}
    assert "SUSPICIOUS_LINK_PUBLIC_CHANNEL" in ids
    assert "EXTERNAL_DM_WITH_LINK" not in ids  # not a DM


def test_suspicious_link_public_channel_fires_on_teams():
    ids = {i.id for i in chat_context.evaluate(_teams("teams_suspicious_public_link.json"))}
    assert "SUSPICIOUS_LINK_PUBLIC_CHANNEL" in ids


def test_impersonated_display_name_fires_when_protected_and_matched(monkeypatch):
    monkeypatch.setattr(settings, "chat_protected_display_names", ["Jane CEO"])

    ids = {i.id for i in chat_context.evaluate(_slack("slack_impersonation.json"))}
    assert "IMPERSONATED_DISPLAY_NAME" in ids


def test_impersonated_display_name_silent_without_a_protected_list_configured(monkeypatch):
    monkeypatch.setattr(settings, "chat_protected_display_names", [])

    ids = {i.id for i in chat_context.evaluate(_slack("slack_impersonation.json"))}
    assert "IMPERSONATED_DISPLAY_NAME" not in ids


def test_impersonated_display_name_silent_for_internal_senders(monkeypatch):
    monkeypatch.setattr(settings, "chat_protected_display_names", ["alice"])

    # slack_benign.json's sender is internal (is_external: false) — should never match
    # even though "alice" is on the protected list.
    ids = {i.id for i in chat_context.evaluate(_slack("slack_benign.json"))}
    assert "IMPERSONATED_DISPLAY_NAME" not in ids
