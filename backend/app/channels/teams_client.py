"""Live Microsoft Teams ingestion — NOT implemented in M7 Stage B, this module is the seam for it.

Wiring this up for real requires:
- A Microsoft Entra ID app registration with the Microsoft Graph **application** permission
  `ChannelMessage.Read.All` (read-only; admin-consented), or `Chat.Read.All` for 1:1/group chats.
- Secrets (`MS_GRAPH_CLIENT_ID`, `MS_GRAPH_CLIENT_SECRET`, `MS_GRAPH_TENANT_ID`) supplied via
  environment/vault, same as every other secret in this app (see .env.example) — never
  hardcoded, never committed.
- Gated behind `settings.enable_live_teams_ingestion` (default False) before any of this is
  reachable from a route.

None of that is built yet. `app.channels.teams_adapter.normalize_teams_message` already defines
the target shape once a real payload is available.
"""

from __future__ import annotations


def fetch_recent_messages(*, chat_or_channel_id: str, since: str | None = None) -> list[dict]:
    raise NotImplementedError(
        "Live Teams ingestion is not implemented yet — see this module's docstring for what's "
        "needed. Use app.channels.teams_adapter.normalize_teams_message on a payload you already "
        "have (e.g. a test fixture) in the meantime."
    )
