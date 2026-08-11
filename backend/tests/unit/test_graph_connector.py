from __future__ import annotations

from unittest.mock import patch

import httpx
import pytest
import respx

from app.autonomy.graph_connector import GraphConnector

_BASE_URL = "https://graph.microsoft.com/v1.0"


@pytest.fixture()
def connector():
    return GraphConnector(tenant_id="test-tenant", client_id="test-client", client_secret="test-secret")


@pytest.fixture(autouse=True)
def _fake_token():
    """Every test in this file bypasses MSAL entirely — constructing a real
    ConfidentialClientApplication and calling acquire_token_for_client would trigger a live
    OIDC discovery HTTP call against login.microsoftonline.com (see GraphConnector's module
    docstring). Patching our own thin wrapper method is simpler and more robust than trying
    to mock MSAL's internals (which use `requests`, not httpx — respx can't see them)."""
    with patch.object(GraphConnector, "_acquire_token", return_value="fake-token"):
        yield


def test_connector_construction_makes_no_network_call():
    # No respx mock active at all here — this must not raise or hang.
    GraphConnector(tenant_id="t", client_id="c", client_secret="s")


# --- QUARANTINE_EMAIL --------------------------------------------------------------------


def test_quarantine_email_happy_path_moves_message_and_creates_folder(connector):
    with respx.mock(base_url=_BASE_URL) as mock:
        mock.get("/users/soc@corp.com/messages").mock(
            return_value=httpx.Response(
                200, json={"value": [{"id": "msg-1", "parentFolderId": "inbox-id"}]}
            )
        )
        mock.get("/users/soc@corp.com/mailFolders").mock(
            return_value=httpx.Response(200, json={"value": []})
        )
        mock.post("/users/soc@corp.com/mailFolders").mock(
            return_value=httpx.Response(201, json={"id": "quarantine-id"})
        )
        mock.post("/users/soc@corp.com/messages/msg-1/move").mock(
            return_value=httpx.Response(201, json={"id": "msg-1-moved"})
        )

        result = connector.execute(
            "QUARANTINE_EMAIL",
            "evil.com",
            {"recipient_mailbox": "soc@corp.com", "internet_message_id": "<abc@evil.com>"},
        )

    assert result == {
        "outcome": "success",
        "mailbox": "soc@corp.com",
        "message_id": "msg-1-moved",
        "original_folder_id": "inbox-id",
        "quarantine_folder_id": "quarantine-id",
    }


def test_quarantine_email_reuses_an_existing_quarantine_folder(connector):
    # assert_all_called=False: the create-folder POST route is registered defensively but
    # must NOT be hit here (that's the whole point of the test) — respx's default
    # assert-every-registered-route-was-called would otherwise fail this for the wrong reason.
    with respx.mock(base_url=_BASE_URL, assert_all_called=False) as mock:
        mock.get("/users/soc@corp.com/messages").mock(
            return_value=httpx.Response(
                200, json={"value": [{"id": "msg-1", "parentFolderId": "inbox-id"}]}
            )
        )
        mock.get("/users/soc@corp.com/mailFolders").mock(
            return_value=httpx.Response(200, json={"value": [{"id": "existing-quarantine-id"}]})
        )
        create_route = mock.post("/users/soc@corp.com/mailFolders").mock(
            return_value=httpx.Response(201, json={"id": "should-not-be-used"})
        )
        mock.post("/users/soc@corp.com/messages/msg-1/move").mock(
            return_value=httpx.Response(201, json={"id": "msg-1-moved"})
        )

        result = connector.execute(
            "QUARANTINE_EMAIL",
            "evil.com",
            {"recipient_mailbox": "soc@corp.com", "internet_message_id": "<abc@evil.com>"},
        )

    assert result["quarantine_folder_id"] == "existing-quarantine-id"
    assert not create_route.called


def test_quarantine_email_raises_when_message_not_found(connector):
    with respx.mock(base_url=_BASE_URL) as mock:
        mock.get("/users/soc@corp.com/messages").mock(
            return_value=httpx.Response(200, json={"value": []})
        )

        with pytest.raises(RuntimeError, match="No message"):
            connector.execute(
                "QUARANTINE_EMAIL",
                "evil.com",
                {"recipient_mailbox": "soc@corp.com", "internet_message_id": "<missing@evil.com>"},
            )


def test_quarantine_email_raises_on_missing_params(connector):
    with pytest.raises(ValueError, match="recipient_mailbox"):
        connector.execute("QUARANTINE_EMAIL", "evil.com", {})


def test_quarantine_email_raises_on_graph_error_response(connector):
    with respx.mock(base_url=_BASE_URL) as mock:
        mock.get("/users/soc@corp.com/messages").mock(
            return_value=httpx.Response(403, text="Forbidden")
        )
        with pytest.raises(RuntimeError, match="403"):
            connector.execute(
                "QUARANTINE_EMAIL",
                "evil.com",
                {"recipient_mailbox": "soc@corp.com", "internet_message_id": "<abc@evil.com>"},
            )


def test_reverse_quarantine_email_moves_message_back(connector):
    execute_result = {
        "outcome": "success",
        "mailbox": "soc@corp.com",
        "message_id": "msg-1-moved",
        "original_folder_id": "inbox-id",
        "quarantine_folder_id": "quarantine-id",
    }
    with respx.mock(base_url=_BASE_URL) as mock:
        mock.post("/users/soc@corp.com/messages/msg-1-moved/move").mock(
            return_value=httpx.Response(201, json={"id": "msg-1-restored"})
        )
        result = connector.reverse("QUARANTINE_EMAIL", "evil.com", execute_result)

    assert result == {"outcome": "reversed", "mailbox": "soc@corp.com", "message_id": "msg-1-restored"}


def test_reverse_quarantine_email_raises_when_original_result_is_missing_data(connector):
    with pytest.raises(ValueError, match="Cannot restore"):
        connector.reverse("QUARANTINE_EMAIL", "evil.com", {})


# --- DISABLE_SESSION ------------------------------------------------------------------------


def test_disable_session_happy_path(connector):
    with respx.mock(base_url=_BASE_URL) as mock:
        mock.post("/users/alice@corp.com/revokeSignInSessions").mock(
            return_value=httpx.Response(200, json={"value": True})
        )
        result = connector.execute("DISABLE_SESSION", "alice@corp.com", {})

    assert result == {"outcome": "success", "target": "alice@corp.com"}


def test_disable_session_raises_on_graph_failure(connector):
    with respx.mock(base_url=_BASE_URL) as mock:
        mock.post("/users/alice@corp.com/revokeSignInSessions").mock(
            return_value=httpx.Response(404, text="User not found")
        )
        with pytest.raises(RuntimeError, match="404"):
            connector.execute("DISABLE_SESSION", "alice@corp.com", {})


def test_disable_session_has_no_reverse(connector):
    # DISABLE_SESSION never reaches reverse() through the real executor (reversible=False
    # is checked before any connector is ever called) — this proves the connector itself
    # also refuses cleanly, as a defense-in-depth backstop.
    with pytest.raises(ValueError, match="no reverse"):
        connector.reverse("DISABLE_SESSION", "alice@corp.com", {})


# --- BLOCK_SENDER_DOMAIN --------------------------------------------------------------------


def test_block_sender_domain_creates_a_rule_per_mailbox(connector):
    with respx.mock(base_url=_BASE_URL) as mock:
        mock.post("/users/alice@corp.com/mailFolders/inbox/messageRules").mock(
            return_value=httpx.Response(201, json={"id": "rule-1"})
        )
        mock.post("/users/bob@corp.com/mailFolders/inbox/messageRules").mock(
            return_value=httpx.Response(201, json={"id": "rule-2"})
        )

        result = connector.execute(
            "BLOCK_SENDER_DOMAIN",
            "evil.com",
            {"recipient_mailboxes": ["alice@corp.com", "bob@corp.com"]},
        )

    assert result == {
        "outcome": "success",
        "rules_created": [
            {"mailbox": "alice@corp.com", "rule_id": "rule-1"},
            {"mailbox": "bob@corp.com", "rule_id": "rule-2"},
        ],
    }


def test_block_sender_domain_raises_on_missing_mailboxes(connector):
    with pytest.raises(ValueError, match="at least one recipient mailbox"):
        connector.execute("BLOCK_SENDER_DOMAIN", "evil.com", {})


def test_block_sender_domain_raises_if_any_mailbox_fails(connector):
    with respx.mock(base_url=_BASE_URL) as mock:
        mock.post("/users/alice@corp.com/mailFolders/inbox/messageRules").mock(
            return_value=httpx.Response(201, json={"id": "rule-1"})
        )
        mock.post("/users/bob@corp.com/mailFolders/inbox/messageRules").mock(
            return_value=httpx.Response(403, text="Forbidden")
        )
        with pytest.raises(RuntimeError, match="403"):
            connector.execute(
                "BLOCK_SENDER_DOMAIN",
                "evil.com",
                {"recipient_mailboxes": ["alice@corp.com", "bob@corp.com"]},
            )


def test_reverse_block_sender_domain_deletes_every_rule(connector):
    execute_result = {
        "outcome": "success",
        "rules_created": [
            {"mailbox": "alice@corp.com", "rule_id": "rule-1"},
            {"mailbox": "bob@corp.com", "rule_id": "rule-2"},
        ],
    }
    with respx.mock(base_url=_BASE_URL) as mock:
        delete_a = mock.delete("/users/alice@corp.com/mailFolders/inbox/messageRules/rule-1").mock(
            return_value=httpx.Response(204)
        )
        delete_b = mock.delete("/users/bob@corp.com/mailFolders/inbox/messageRules/rule-2").mock(
            return_value=httpx.Response(204)
        )
        result = connector.reverse("BLOCK_SENDER_DOMAIN", "evil.com", execute_result)

    assert delete_a.called
    assert delete_b.called
    assert result["outcome"] == "reversed"
    assert result["deleted"] == execute_result["rules_created"]


def test_reverse_block_sender_domain_raises_on_missing_rules(connector):
    with pytest.raises(ValueError, match="no rules_created"):
        connector.reverse("BLOCK_SENDER_DOMAIN", "evil.com", {})


# --- generic ------------------------------------------------------------------------------


def test_execute_raises_for_unsupported_action_type(connector):
    with pytest.raises(ValueError, match="no execute"):
        connector.execute("SOME_FUTURE_ACTION", "target", {})


def test_token_acquisition_failure_raises(connector):
    with patch.object(
        GraphConnector,
        "_acquire_token",
        side_effect=RuntimeError("Failed to acquire a Microsoft Graph token: invalid_client"),
    ):
        with pytest.raises(RuntimeError, match="Failed to acquire"):
            connector.execute("DISABLE_SESSION", "alice@corp.com", {})


def test_network_error_propagates_not_swallowed(connector):
    with respx.mock(base_url=_BASE_URL) as mock:
        mock.post("/users/alice@corp.com/revokeSignInSessions").mock(
            side_effect=httpx.ConnectError("simulated network outage")
        )
        with pytest.raises(httpx.ConnectError):
            connector.execute("DISABLE_SESSION", "alice@corp.com", {})
