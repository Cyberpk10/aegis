"""Injection and malformed/oversized-input adversarial tests.

Injection: every DB query in this codebase goes through the SQLAlchemy ORM with bound
parameters (confirmed by recon: no `.execute(text(f"..."))`, no f-string/`.format()`-built
SQL, no `eval`/`exec`/`subprocess`/`pickle`/unsafe `yaml.load` anywhere in app/). So classic
SQL injection isn't reachable — these tests prove that empirically (payloads are treated as
inert literal strings, never cause a 500, never corrupt other rows) and add a static guard so
a future change that introduces raw SQL construction anywhere in the app fails CI, the same
way tests/unit/test_copilot_security.py already guards app/copilot specifically.

Input abuse: oversized uploads/bodies and malformed/adversarial .eml/MIME structures.
"""

from __future__ import annotations

import re
import uuid
from pathlib import Path

from app.core.config import settings
from app.db.models import Case

SQLI_PAYLOADS = [
    "'; DROP TABLE cases; --",
    "' OR '1'='1",
    "1; SELECT * FROM users",
    "admin'--",
    "' UNION SELECT password_hash, email FROM users --",
    "Robert'); DROP TABLE cases;--",
]


# --- Injection: free-text filter/query params ------------------------------------------


def test_sqli_payloads_in_case_filters_are_inert(authed_client, db_session, test_account):
    case = Case(
        id=uuid.uuid4(),
        account_id=test_account.account.id,
        filename="t.eml",
        verdict="malicious",
        score=80,
        from_addr="a@example.com",
        subject="s",
        channel="email",
        indicators=[],
        framework_mappings={},
    )
    db_session.add(case)
    db_session.commit()

    for payload in SQLI_PAYLOADS:
        response = authed_client.get("/api/cases", params={"channel": payload})
        assert response.status_code == 200, payload
        assert response.json()["items"] == []

    # The legitimate row must still be there and intact — no payload silently mutated data.
    survivors = authed_client.get("/api/cases").json()
    assert survivors["total"] == 1
    assert survivors["items"][0]["id"] == str(case.id)


def test_sqli_payloads_in_autonomy_action_filters_are_inert(authed_client):
    for payload in SQLI_PAYLOADS:
        response = authed_client.get("/api/autonomy/actions", params={"action_type": payload})
        assert response.status_code == 200, payload
        assert response.json()["items"] == []


def test_sqli_payloads_in_incident_actor_filter_are_inert(authed_client):
    for payload in SQLI_PAYLOADS:
        response = authed_client.get("/api/incidents", params={"actor": payload})
        assert response.status_code == 200, payload
        assert response.json()["items"] == []


def test_sqli_payload_in_graph_integration_tenant_id_is_stored_as_inert_text(authed_client):
    payload = "'; DROP TABLE accounts; --"
    response = authed_client.put("/api/autonomy/graph-integration", json={"tenant_id": payload})
    assert response.status_code == 200
    assert response.json()["tenant_id"] == payload  # stored/returned verbatim, never executed

    # The accounts table (and everything else) is still fully intact.
    still_works = authed_client.get("/api/auth/me")
    assert still_works.status_code == 200


def test_sqli_payload_as_email_subject_is_stored_and_returned_as_inert_text(authed_client, load_eml):
    # A crafted .eml whose Subject header carries a SQL-injection-shaped string — proves
    # the value flows through parse -> persist -> read as plain data end to end.
    payload_subject = "'; DROP TABLE cases; -- Free Money!!!"
    raw = (
        f"From: attacker@evil.example\r\n"
        f"To: victim@example.com\r\n"
        f"Subject: {payload_subject}\r\n"
        f"Date: Mon, 1 Jan 2026 00:00:00 +0000\r\n"
        f"Content-Type: text/plain\r\n\r\n"
        f"Click here.\r\n"
    ).encode()

    response = authed_client.post("/api/analyze", files={"file": ("t.eml", raw, "message/rfc822")})
    assert response.status_code == 200
    assert response.json()["summary"]["subject"] == payload_subject

    listing = authed_client.get("/api/cases").json()
    assert listing["total"] == 1  # the table is intact, not dropped


# --- Static guard: no raw SQL construction anywhere in the app -------------------------


def test_app_source_contains_no_raw_sql_construction():
    app_dir = Path(__file__).resolve().parents[2] / "app"
    suspicious = re.compile(r'\.execute\(\s*text\(\s*f["\']|\.execute\(\s*["\'].*%s|f["\'](SELECT|INSERT|UPDATE|DELETE)\s', re.IGNORECASE)
    offenders = []
    for path in app_dir.rglob("*.py"):
        text = path.read_text(errors="ignore")
        for lineno, line in enumerate(text.splitlines(), start=1):
            if suspicious.search(line):
                offenders.append(f"{path}:{lineno}: {line.strip()}")
    assert offenders == [], "Found raw/string-built SQL construction:\n" + "\n".join(offenders)


# --- Input abuse: oversized bodies ------------------------------------------------------


def test_oversized_eml_upload_rejected(authed_client):
    oversized = b"A" * (settings.max_upload_bytes + 1)
    response = authed_client.post(
        "/api/analyze", files={"file": ("big.eml", oversized, "message/rfc822")}
    )
    assert response.status_code == 400


def test_body_exceeding_the_hard_request_cap_gets_413_before_being_parsed(client):
    """Exercises app.core.body_limit.MaxBodySizeMiddleware directly at the ASGI boundary —
    a request declaring a Content-Length above settings.max_request_body_bytes must be
    rejected without ever reaching route/auth logic (no Authorization header is even sent
    here, proving the middleware runs before the auth dependency, not after)."""
    huge = b"A" * (settings.max_request_body_bytes + 1)
    response = client.post(
        "/api/analyze", files={"file": ("huge.eml", huge, "message/rfc822")}
    )
    assert response.status_code == 413


def test_oversized_pasted_text_rejected(authed_client):
    oversized_text = "A" * (settings.max_upload_bytes + 1)
    response = authed_client.post("/api/analyze/text", json={"raw_text": oversized_text})
    assert response.status_code == 400


def test_event_batch_over_the_cap_is_rejected_with_422(authed_client):
    events = [
        {"timestamp": "2026-01-01T00:00:00Z", "actor": "alice@corp.com", "action": "login"}
        for _ in range(1001)
    ]
    response = authed_client.post("/api/events", json={"events": events})
    assert response.status_code == 422


def test_event_batch_at_the_cap_is_accepted(authed_client):
    events = [
        {"timestamp": "2026-01-01T00:00:00Z", "actor": "alice@corp.com", "action": "login"}
        for _ in range(1000)
    ]
    response = authed_client.post("/api/events", json={"events": events})
    assert response.status_code == 200
    assert response.json()["accepted"] == 1000


def test_copilot_question_over_the_cap_is_rejected_with_422(authed_client, monkeypatch):
    monkeypatch.setattr(settings, "enable_copilot", True)
    monkeypatch.setenv("ANTHROPIC_API_KEY", "test-key")
    response = authed_client.post("/api/copilot/query", json={"question": "A" * 2001})
    assert response.status_code == 422


def test_label_note_over_the_cap_is_rejected_with_422(authed_client, db_session, test_account):
    case = Case(
        id=uuid.uuid4(),
        account_id=test_account.account.id,
        filename="t.eml",
        verdict="malicious",
        score=80,
        from_addr="a@example.com",
        subject="s",
        indicators=[],
        framework_mappings={},
    )
    db_session.add(case)
    db_session.commit()

    response = authed_client.post(
        f"/api/cases/{case.id}/label",
        json={"analyst_verdict": "malicious", "note": "A" * 5001},
    )
    assert response.status_code == 422


# --- Input abuse: malformed / adversarial .eml and MIME --------------------------------


def test_garbage_non_mime_bytes_do_not_crash_the_parser(authed_client):
    garbage = bytes(range(256)) * 100  # arbitrary binary noise, not valid MIME at all
    response = authed_client.post(
        "/api/analyze", files={"file": ("garbage.eml", garbage, "message/rfc822")}
    )
    # The stdlib email parser is extremely permissive (never raises on garbage — it just
    # produces a mostly-empty message), so this is expected to succeed with empty/blank
    # fields rather than 500. The contract under test is simply: never a 500.
    assert response.status_code in (200, 400)


def test_deeply_nested_multipart_does_not_hang_or_crash(authed_client):
    import time
    from email.message import EmailMessage

    def _nest(depth: int) -> EmailMessage:
        msg = EmailMessage()
        msg["Subject"] = "nested"
        if depth == 0:
            msg.set_content("leaf")
            return msg
        msg.make_mixed()
        msg.attach(_nest(depth - 1))
        return msg

    top = EmailMessage()
    top["From"] = "attacker@evil.example"
    top["To"] = "victim@example.com"
    top["Subject"] = "MIME bomb"
    top.make_mixed()
    top.attach(_nest(200))
    raw = top.as_bytes()

    start = time.monotonic()
    response = authed_client.post(
        "/api/analyze", files={"file": ("nested.eml", raw, "message/rfc822")}
    )
    elapsed = time.monotonic() - start

    assert response.status_code in (200, 400)
    assert elapsed < 5.0, f"parsing a deeply nested MIME message took {elapsed:.2f}s"


def test_email_with_thousands_of_tiny_attachments_does_not_hang(authed_client):
    import time
    from email.message import EmailMessage

    top = EmailMessage()
    top["From"] = "attacker@evil.example"
    top["To"] = "victim@example.com"
    top["Subject"] = "Attachment flood"
    top.make_mixed()
    for i in range(3000):
        top.add_attachment(b"x", maintype="application", subtype="octet-stream", filename=f"f{i}.bin")
    raw = top.as_bytes()
    assert len(raw) < settings.max_upload_bytes  # stay under the size gate to isolate parse cost

    start = time.monotonic()
    response = authed_client.post(
        "/api/analyze", files={"file": ("flood.eml", raw, "message/rfc822")}
    )
    elapsed = time.monotonic() - start

    assert response.status_code in (200, 400)
    assert elapsed < 10.0, f"parsing 3000 attachments took {elapsed:.2f}s"


def test_huge_single_header_does_not_crash_the_parser(authed_client):
    huge_subject = "A" * 200_000
    raw = (
        f"From: attacker@evil.example\r\n"
        f"To: victim@example.com\r\n"
        f"Subject: {huge_subject}\r\n"
        f"Content-Type: text/plain\r\n\r\n"
        f"body\r\n"
    ).encode()
    response = authed_client.post(
        "/api/analyze", files={"file": ("t.eml", raw, "message/rfc822")}
    )
    assert response.status_code in (200, 400)
