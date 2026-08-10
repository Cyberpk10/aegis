"""Live Slack ingestion — NOT implemented in M7 Stage B, this module is the seam for it.

Wiring this up for real requires:
- A Slack app subscribed to the Events API (`message.channels`, `message.im`, `message.groups`)
  or, for a pull model, `conversations.history`/`conversations.replies`.
- A bot token with read-only scopes only: `channels:history`, `groups:history`, `im:history`,
  `users:read`, `users:read.email` — never write/post scopes, this is analysis-only.
- Secrets (`SLACK_BOT_TOKEN`, `SLACK_SIGNING_SECRET` — to verify inbound Events API requests)
  supplied via environment/vault, same as every other secret in this app (see .env.example) —
  never hardcoded, never committed.
- Gated behind `settings.enable_live_slack_ingestion` (default False) before any of this is
  reachable from a route.

None of that is built yet. `app.channels.slack_adapter.normalize_slack_message` already defines
the target shape once a real payload is available.
"""

from __future__ import annotations


def fetch_recent_messages(*, channel_id: str, since: str | None = None) -> list[dict]:
    raise NotImplementedError(
        "Live Slack ingestion is not implemented yet — see this module's docstring for what's "
        "needed. Use app.channels.slack_adapter.normalize_slack_message on a payload you already "
        "have (e.g. a test fixture) in the meantime."
    )
