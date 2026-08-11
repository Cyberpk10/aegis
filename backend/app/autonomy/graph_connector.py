"""The real Microsoft Graph connector (M6 Stage 2) — defensive containment inside a
customer's own Microsoft 365 tenant, nothing more. Implements the same ActionConnector
interface as MockConnector; app.autonomy.connector_factory decides which one a given account
actually gets.

Auth: app-only (client-credentials) Graph access via MSAL, scoped to one customer tenant at a
time — see app.autonomy.connector_factory for where tenant_id/client_id/client_secret come
from. `msal.ConfidentialClientApplication` handles token acquisition/caching; nothing here
talks to the token endpoint directly.

Failure contract, deliberately different from MockConnector: every method here either returns
a dict describing a genuine success, or raises. There is no third "returned normally but
actually failed" state — app.autonomy.executor's callers infer success/failure from whether an
exception was raised, not by inspecting the returned dict, so silently swallowing a failure
into a "soft" result here would get misrecorded as a real success. execute_if_authorized()
catches exceptions from execute() and records status="execution_failed"; reverse_action()
catches exceptions from reverse() and re-raises as ValueError (translated to an HTTP 400) —
both already exist in app.autonomy.executor and needed no connector-specific handling here.
"""

from __future__ import annotations

import httpx
import msal

from app.autonomy.actions import BLOCK_SENDER_DOMAIN, DISABLE_SESSION, QUARANTINE_EMAIL
from app.autonomy.executor import ActionConnector


class GraphConnector(ActionConnector):
    _GRAPH_BASE_URL = "https://graph.microsoft.com/v1.0"
    _GRAPH_SCOPE = ["https://graph.microsoft.com/.default"]
    # A dedicated folder per mailbox, created on first use — never Deleted Items or any
    # folder a user might empty without realizing it holds a quarantined message.
    _QUARANTINE_FOLDER_NAME = "Aegis Quarantine"

    def __init__(self, *, tenant_id: str, client_id: str, client_secret: str) -> None:
        self._tenant_id = tenant_id
        self._client_id = client_id
        self._client_secret = client_secret
        self._msal_app: msal.ConfidentialClientApplication | None = None

    # ---- auth + transport --------------------------------------------------------------

    def _get_msal_app(self) -> msal.ConfidentialClientApplication:
        # Built lazily, not in __init__ — constructing a ConfidentialClientApplication
        # triggers an immediate OIDC discovery HTTP call against the tenant's authority
        # endpoint, before any token is even requested. Deferring it means simply
        # *instantiating* a GraphConnector (e.g. app.autonomy.connector_factory picking a
        # connector for an account) never makes a network call — only actually calling
        # execute()/reverse() does.
        if self._msal_app is None:
            self._msal_app = msal.ConfidentialClientApplication(
                self._client_id,
                authority=f"https://login.microsoftonline.com/{self._tenant_id}",
                client_credential=self._client_secret,
            )
        return self._msal_app

    def _acquire_token(self) -> str:
        result = self._get_msal_app().acquire_token_for_client(scopes=self._GRAPH_SCOPE)
        if "access_token" not in result:
            raise RuntimeError(
                "Failed to acquire a Microsoft Graph token: "
                f"{result.get('error_description') or result.get('error') or result}"
            )
        return result["access_token"]

    def _request(self, method: str, path: str, **kwargs) -> httpx.Response:
        token = self._acquire_token()
        headers = kwargs.pop("headers", {})
        headers["Authorization"] = f"Bearer {token}"
        with httpx.Client(base_url=self._GRAPH_BASE_URL, timeout=30.0) as client:
            return client.request(method, path, headers=headers, **kwargs)

    @staticmethod
    def _require_ok(response: httpx.Response, message: str) -> None:
        if response.status_code >= 300:
            raise RuntimeError(f"{message}: HTTP {response.status_code} — {response.text}")

    # ---- ActionConnector interface ------------------------------------------------------

    def execute(self, action_type: str, target: str, params: dict) -> dict:
        if action_type == QUARANTINE_EMAIL:
            return self._quarantine_email(target, params)
        if action_type == DISABLE_SESSION:
            return self._disable_session(target)
        if action_type == BLOCK_SENDER_DOMAIN:
            return self._block_sender_domain(target, params)
        raise ValueError(f"GraphConnector has no execute() implementation for {action_type!r}")

    def reverse(self, action_type: str, target: str, params: dict) -> dict:
        if action_type == QUARANTINE_EMAIL:
            return self._restore_email(target, params)
        if action_type == BLOCK_SENDER_DOMAIN:
            return self._unblock_sender_domain(target, params)
        # DISABLE_SESSION never reaches here in practice — it's reversible=False (no API to
        # un-revoke a session exists), and executor.reverse_action() refuses to call a
        # connector's reverse() for a non-reversible row before this method is ever invoked.
        raise ValueError(f"GraphConnector has no reverse() implementation for {action_type!r}")

    # ---- QUARANTINE_EMAIL ----------------------------------------------------------------

    def _get_or_create_quarantine_folder(self, mailbox: str) -> str:
        search = self._request(
            "GET",
            f"/users/{mailbox}/mailFolders",
            params={"$filter": f"displayName eq '{self._QUARANTINE_FOLDER_NAME}'"},
        )
        self._require_ok(search, "Failed to search for the quarantine folder")
        existing = search.json().get("value", [])
        if existing:
            return existing[0]["id"]

        create = self._request(
            "POST",
            f"/users/{mailbox}/mailFolders",
            json={"displayName": self._QUARANTINE_FOLDER_NAME},
        )
        self._require_ok(create, "Failed to create the quarantine folder")
        return create.json()["id"]

    def _quarantine_email(self, target: str, params: dict) -> dict:
        mailbox = params.get("recipient_mailbox")
        message_id = params.get("internet_message_id")
        if not mailbox or not message_id:
            raise ValueError(
                "QUARANTINE_EMAIL requires recipient_mailbox and internet_message_id in params"
            )

        search = self._request(
            "GET",
            f"/users/{mailbox}/messages",
            params={"$filter": f"internetMessageId eq '{message_id}'"},
        )
        self._require_ok(search, "Failed to search the mailbox for the message")
        found = search.json().get("value", [])
        if not found:
            raise RuntimeError(
                f"No message with Internet-Message-Id {message_id!r} found in {mailbox}"
            )
        message = found[0]
        original_folder_id = message["parentFolderId"]

        quarantine_folder_id = self._get_or_create_quarantine_folder(mailbox)

        move = self._request(
            "POST",
            f"/users/{mailbox}/messages/{message['id']}/move",
            json={"destinationId": quarantine_folder_id},
        )
        self._require_ok(move, "Failed to move the message to quarantine")
        moved = move.json()

        return {
            "outcome": "success",
            "mailbox": mailbox,
            # The moved message is a *new* copy with a new id (Graph's move semantics) —
            # this is what reverse() needs, not the original (now-deleted) message id.
            "message_id": moved["id"],
            "original_folder_id": original_folder_id,
            "quarantine_folder_id": quarantine_folder_id,
        }

    def _restore_email(self, target: str, params: dict) -> dict:
        mailbox = params.get("mailbox")
        message_id = params.get("message_id")
        original_folder_id = params.get("original_folder_id")
        if not mailbox or not message_id or not original_folder_id:
            raise ValueError(
                "Cannot restore — the original execute() result is missing mailbox/"
                "message_id/original_folder_id"
            )

        move = self._request(
            "POST",
            f"/users/{mailbox}/messages/{message_id}/move",
            json={"destinationId": original_folder_id},
        )
        self._require_ok(move, "Failed to restore the message from quarantine")
        return {"outcome": "reversed", "mailbox": mailbox, "message_id": move.json()["id"]}

    # ---- DISABLE_SESSION ------------------------------------------------------------------

    def _disable_session(self, target: str) -> dict:
        response = self._request("POST", f"/users/{target}/revokeSignInSessions")
        self._require_ok(response, f"Failed to revoke sign-in sessions for {target}")
        return {"outcome": "success", "target": target}

    # ---- BLOCK_SENDER_DOMAIN ----------------------------------------------------------------

    def _block_sender_domain(self, target: str, params: dict) -> dict:
        mailboxes = params.get("recipient_mailboxes") or []
        if not mailboxes:
            raise ValueError("BLOCK_SENDER_DOMAIN requires at least one recipient mailbox")

        # All-or-nothing: the first mailbox that fails aborts the rest rather than leaving an
        # unrecorded, orphaned rule behind in an already-processed mailbox — see module
        # docstring on why every failure here raises rather than degrading silently.
        rules_created = []
        for mailbox in mailboxes:
            response = self._request(
                "POST",
                f"/users/{mailbox}/mailFolders/inbox/messageRules",
                json={
                    "displayName": f"Aegis: block {target}",
                    "sequence": 1,
                    "isEnabled": True,
                    "conditions": {"senderContains": [f"@{target}"]},
                    "actions": {"delete": True, "stopProcessingRules": True},
                },
            )
            self._require_ok(response, f"Failed to create a block rule in {mailbox}")
            rules_created.append({"mailbox": mailbox, "rule_id": response.json()["id"]})

        return {"outcome": "success", "rules_created": rules_created}

    def _unblock_sender_domain(self, target: str, params: dict) -> dict:
        rules_created = params.get("rules_created") or []
        if not rules_created:
            raise ValueError("Cannot unblock — the original execute() result has no rules_created")

        for entry in rules_created:
            response = self._request(
                "DELETE",
                f"/users/{entry['mailbox']}/mailFolders/inbox/messageRules/{entry['rule_id']}",
            )
            self._require_ok(response, f"Failed to delete the block rule in {entry['mailbox']}")

        return {"outcome": "reversed", "deleted": rules_created}
