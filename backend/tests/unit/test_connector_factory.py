from __future__ import annotations

import uuid

from app.autonomy.connector_factory import get_connector_for_account
from app.autonomy.executor import MockConnector
from app.autonomy.graph_connector import GraphConnector
from app.core.config import settings
from app.db.models import Account, GraphIntegration
from app.auth.security import generate_inbound_token


def _make_account(db_session) -> Account:
    account = Account(id=uuid.uuid4(), name="Test Account", inbound_token=generate_inbound_token())
    db_session.add(account)
    db_session.commit()
    db_session.refresh(account)
    return account


def test_falls_back_to_mock_when_client_credentials_are_unset(db_session, monkeypatch):
    monkeypatch.setattr(settings, "microsoft_graph_client_id", "")
    monkeypatch.setattr(settings, "microsoft_graph_client_secret", "")
    account = _make_account(db_session)
    db_session.add(GraphIntegration(account_id=account.id, tenant_id="some-tenant"))
    db_session.commit()

    connector = get_connector_for_account(db_session, account.id)

    assert isinstance(connector, MockConnector)


def test_falls_back_to_mock_when_no_integration_row_exists(db_session, monkeypatch):
    monkeypatch.setattr(settings, "microsoft_graph_client_id", "client-id")
    monkeypatch.setattr(settings, "microsoft_graph_client_secret", "client-secret")
    account = _make_account(db_session)

    connector = get_connector_for_account(db_session, account.id)

    assert isinstance(connector, MockConnector)


def test_falls_back_to_mock_when_integration_is_disabled(db_session, monkeypatch):
    monkeypatch.setattr(settings, "microsoft_graph_client_id", "client-id")
    monkeypatch.setattr(settings, "microsoft_graph_client_secret", "client-secret")
    account = _make_account(db_session)
    db_session.add(
        GraphIntegration(account_id=account.id, tenant_id="some-tenant", is_enabled=False)
    )
    db_session.commit()

    connector = get_connector_for_account(db_session, account.id)

    assert isinstance(connector, MockConnector)


def test_returns_graph_connector_when_fully_configured(db_session, monkeypatch):
    monkeypatch.setattr(settings, "microsoft_graph_client_id", "client-id")
    monkeypatch.setattr(settings, "microsoft_graph_client_secret", "client-secret")
    account = _make_account(db_session)
    db_session.add(
        GraphIntegration(account_id=account.id, tenant_id="the-real-tenant-id", is_enabled=True)
    )
    db_session.commit()

    connector = get_connector_for_account(db_session, account.id)

    assert isinstance(connector, GraphConnector)
    assert connector._tenant_id == "the-real-tenant-id"
    assert connector._client_id == "client-id"
    assert connector._client_secret == "client-secret"


def test_a_different_account_with_no_integration_still_gets_mock(db_session, monkeypatch):
    # Confirms the lookup is genuinely account-scoped, not "any GraphIntegration row exists
    # anywhere" — one account connecting Microsoft 365 must never silently activate it for
    # another account.
    monkeypatch.setattr(settings, "microsoft_graph_client_id", "client-id")
    monkeypatch.setattr(settings, "microsoft_graph_client_secret", "client-secret")
    connected_account = _make_account(db_session)
    other_account = _make_account(db_session)
    db_session.add(GraphIntegration(account_id=connected_account.id, tenant_id="tenant-a"))
    db_session.commit()

    connector = get_connector_for_account(db_session, other_account.id)

    assert isinstance(connector, MockConnector)
