"""Normalizes a Microsoft Teams message payload into the common `Message` shape (M7 Stage B).

The payload shape here is representative of a Microsoft Graph `chatMessage` resource —
illustrative, since this stage builds the adapter and mock sample payloads only; there is no
live call to Microsoft Graph (see teams_client.py). Pure, offline, deterministic.
"""

from __future__ import annotations

import re

from app.channels.message import Channel, Message, extract_links_from_text

_TAG_RE = re.compile(r"<[^>]+>")


def _plain_text(body: dict) -> str:
    content = body.get("content") or ""
    if body.get("contentType") == "html":
        return _TAG_RE.sub(" ", content).strip()
    return content


def normalize_teams_message(payload: dict) -> Message:
    """`payload` is a single Microsoft Graph `chatMessage` resource, e.g.:

    {
      "from": {"user": {"displayName": "...", "userIdentityType": "aadUser" | "guest", "email": "..."}},
      "body": {"contentType": "text" | "html", "content": "message text, raw https:// links"},
      "mentions": [{"mentioned": {"user": {"displayName": "..."}}}],
      "chatId": "19:...@thread.v2",          # present for 1:1/group chat
      "channelIdentity": {"channelId": "..."},  # present for a channel post instead
      "createdDateTime": "2026-01-01T12:00:00Z"
    }
    """
    sender = (payload.get("from") or {}).get("user") or {}
    body = payload.get("body") or {}
    text = _plain_text(body)
    mentions = [
        m.get("mentioned", {}).get("user", {}).get("displayName")
        for m in payload.get("mentions") or []
        if m.get("mentioned", {}).get("user", {}).get("displayName")
    ]
    channel_identity = payload.get("channelIdentity")

    return Message(
        channel=Channel.TEAMS,
        from_display=sender.get("displayName"),
        from_address=sender.get("email"),
        body_text=text,
        links=extract_links_from_text(text),
        mentions=mentions,
        is_direct_message=bool(payload.get("chatId")) and not channel_identity,
        is_external_sender=sender.get("userIdentityType") == "guest",
        channel_name=(channel_identity or {}).get("channelId"),
        date=payload.get("createdDateTime"),
    )
