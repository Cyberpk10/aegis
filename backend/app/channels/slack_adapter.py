"""Normalizes a Slack message payload into the common `Message` shape (M7 Stage B).

The payload shape here is representative of Slack's Events API `message` event (the `event`
object) plus a resolved user profile — illustrative, since this stage builds the adapter and
mock sample payloads only; there is no live call to Slack's API (see slack_client.py). Pure,
offline, deterministic.
"""

from __future__ import annotations

import re

from app.channels.message import Channel, Message, extract_links_from_text

_MENTION_RE = re.compile(r"<@([A-Z0-9]+)>")


def _strip_mention_markup(text: str, mentions_by_id: dict[str, str]) -> str:
    def _sub(match: re.Match[str]) -> str:
        user_id = match.group(1)
        return f"@{mentions_by_id.get(user_id, user_id)}"

    return _MENTION_RE.sub(_sub, text)


def normalize_slack_message(payload: dict) -> Message:
    """`payload` is a single Slack `message` event, e.g.:

    {
      "channel_type": "im" | "channel" | "group",
      "channel_name": "general",
      "user": {"display_name": "...", "real_name": "...", "email": "...", "is_external": bool},
      "text": "message text, possibly containing <@U123> mentions and raw https:// links",
      "ts": "1735689600.000100"
    }
    """
    user = payload.get("user") or {}
    text = payload.get("text") or ""
    mentioned_ids = _MENTION_RE.findall(text)
    mentions_by_id = {uid: uid for uid in mentioned_ids}

    return Message(
        channel=Channel.SLACK,
        from_display=user.get("display_name") or user.get("real_name"),
        from_address=user.get("email"),
        body_text=_strip_mention_markup(text, mentions_by_id),
        links=extract_links_from_text(text),
        mentions=mentioned_ids,
        is_direct_message=payload.get("channel_type") == "im",
        is_external_sender=bool(user.get("is_external")),
        channel_name=payload.get("channel_name"),
        date=payload.get("ts"),
    )
