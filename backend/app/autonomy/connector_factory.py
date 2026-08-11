"""Per-account connector selection (M6 Stage 2) — the single seam that decides whether an
account's autonomy actions are simulated (MockConnector, the default) or real
(GraphConnector). A real connector is only ever returned when every piece is actually in
place: the shared Microsoft Graph app registration's credentials are configured (Render env),
this specific account has completed Microsoft 365 setup (a GraphIntegration row exists), and
that connection hasn't been paused. Missing any one of those silently and safely falls back to
MockConnector — no real action ever fires for an unconfigured or half-configured account.
"""

from __future__ import annotations

import uuid

from sqlalchemy.orm import Session

from app.autonomy.executor import ActionConnector, MockConnector
from app.autonomy.graph_connector import GraphConnector
from app.core.config import settings
from app.db.models import GraphIntegration


def get_connector_for_account(db: Session, account_id: uuid.UUID) -> ActionConnector:
    if not settings.microsoft_graph_client_id or not settings.microsoft_graph_client_secret:
        return MockConnector()

    integration = (
        db.query(GraphIntegration)
        .filter(GraphIntegration.account_id == account_id, GraphIntegration.is_enabled.is_(True))
        .first()
    )
    if integration is None:
        return MockConnector()

    return GraphConnector(
        tenant_id=integration.tenant_id,
        client_id=settings.microsoft_graph_client_id,
        client_secret=settings.microsoft_graph_client_secret,
    )
