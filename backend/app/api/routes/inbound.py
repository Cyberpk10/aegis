"""POST /api/inbound/email/mime — email-forwarding intake webhook (M8 Stage 3).

Public endpoint — no `Depends(get_current_user)`. The provider's HMAC signature over the
request *is* the authentication; there's no logged-in user on the other end, only Mailgun's
servers. Maps the forwarded email to an account via the recipient address
(`pilot-<inbound_token>@<settings.inbound_email_domain>`), unwraps the original message out of
the forwarding wrapper (app.inbound.unwrap), and runs it through the same detection pipeline a
manual upload uses (app.analysis.email_pipeline) — same rule-based scoring, same optional LLM
narrative, same framework mappings.

Defensive analysis only — this never sends, replies to, blocks, or forwards anything; it only
reads the payload Mailgun already delivered and scores it.
"""

from __future__ import annotations

import hashlib
import re
import uuid
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy.orm import Session

from app.analysis.email_pipeline import run_email_pipeline
from app.auth.audit_log import log_event
from app.auth.rate_limit import limiter
from app.core.config import settings
from app.db.models import Account, Case
from app.db.session import get_db
from app.inbound.mailgun import extract_raw_email, verify_signature
from app.inbound.unwrap import unwrap_forwarded_email
from app.models.schemas import InboundEmailResponse
from app.storage.raw_email_store import save_raw_email

router = APIRouter(prefix="/api/inbound", tags=["inbound"])

# A coarse per-IP layer against gross endpoint abuse — the real per-tenant throttle is the
# per-account hourly cap below, since a provider's webhook traffic all comes from a small,
# shared set of source IPs (per-IP limiting alone wouldn't actually throttle one noisy account).
_WEBHOOK_RATE_LIMIT = "120/minute"

_RECIPIENT_RE = re.compile(r"^pilot-([a-z0-9]+)@", re.IGNORECASE)


def _client_ip(request: Request) -> str | None:
    return request.client.host if request.client else None


def _resolve_account(db: Session, recipient: str) -> Account | None:
    match = _RECIPIENT_RE.match(recipient.strip())
    if match is None:
        return None
    return db.query(Account).filter(Account.inbound_token == match.group(1).lower()).first()


def _recent_case_count(db: Session, account_id: uuid.UUID) -> int:
    window_start = datetime.now(timezone.utc) - timedelta(hours=1)
    return (
        db.query(Case)
        .filter(Case.account_id == account_id, Case.created_at >= window_start)
        .count()
    )


@router.post("/email/mime", response_model=InboundEmailResponse)
@limiter.limit(_WEBHOOK_RATE_LIMIT)
async def receive_inbound_email(
    request: Request, db: Session = Depends(get_db)
) -> InboundEmailResponse:
    if not settings.mailgun_webhook_signing_key:
        raise HTTPException(status_code=503, detail="Inbound email intake is not configured.")

    form = await request.form()

    signature_ok = verify_signature(
        timestamp=str(form.get("timestamp") or ""),
        token=str(form.get("token") or ""),
        signature=str(form.get("signature") or ""),
        signing_key=settings.mailgun_webhook_signing_key,
        max_age_seconds=settings.inbound_email_signature_max_age_seconds,
    )
    if not signature_ok:
        log_event(
            db,
            event_type="inbound_email_rejected_signature",
            detail={"recipient": str(form.get("recipient") or "")},
            ip_address=_client_ip(request),
        )
        db.commit()
        raise HTTPException(status_code=401, detail="Invalid signature.")

    recipient = str(form.get("recipient") or "")
    account = _resolve_account(db, recipient)
    if account is None:
        log_event(
            db,
            event_type="inbound_email_unknown_recipient",
            detail={"recipient": recipient},
            ip_address=_client_ip(request),
        )
        db.commit()
        raise HTTPException(status_code=404, detail="Unknown recipient.")

    if _recent_case_count(db, account.id) >= settings.inbound_email_rate_limit_per_account_per_hour:
        log_event(
            db,
            event_type="inbound_email_rate_limited",
            account_id=account.id,
            ip_address=_client_ip(request),
        )
        db.commit()
        raise HTTPException(status_code=429, detail="Too many forwarded emails for this account.")

    raw_bytes = extract_raw_email(form)
    if not raw_bytes or len(raw_bytes) > settings.max_upload_bytes:
        log_event(
            db,
            event_type="inbound_email_rejected_payload",
            account_id=account.id,
            ip_address=_client_ip(request),
        )
        db.commit()
        return InboundEmailResponse(status="rejected")

    unwrapped = unwrap_forwarded_email(raw_bytes)
    content_hash = hashlib.sha256(unwrapped).hexdigest()

    existing = (
        db.query(Case)
        .filter(Case.account_id == account.id, Case.content_hash == content_hash)
        .first()
    )
    if existing is not None:
        return InboundEmailResponse(
            status="duplicate", case_id=existing.id, verdict=existing.verdict, score=existing.score
        )

    try:
        result = run_email_pipeline(unwrapped)
    except Exception:  # noqa: BLE001 - unparseable even after unwrap; nothing a retry would fix
        log_event(
            db,
            event_type="inbound_email_rejected_unparseable",
            account_id=account.id,
            ip_address=_client_ip(request),
        )
        db.commit()
        return InboundEmailResponse(status="rejected")

    parsed = result.parsed
    case_id = uuid.uuid4()
    raw_email_path = save_raw_email(case_id, unwrapped)

    indicators_json = [i.model_dump(mode="json") for i in result.indicators]
    framework_mappings_json = {
        key: [ref.model_dump(mode="json") for ref in refs]
        for key, refs in result.framework_mappings.items()
    }

    case = Case(
        id=case_id,
        account_id=account.id,
        filename=(parsed.subject or "forwarded-email")[:200] + ".eml",
        verdict=result.verdict.value,
        score=result.score,
        from_addr=parsed.from_address,
        subject=parsed.subject,
        to_addresses=parsed.to_addresses,
        indicators=indicators_json,
        framework_mappings=framework_mappings_json,
        analyst_narrative=result.analyst_narrative,
        analyst_model=result.analyst_model,
        ml_probability=result.ml_probability,
        ml_model_version=result.ml_model_version,
        raw_email_path=raw_email_path,
        content_hash=content_hash,
    )
    db.add(case)

    log_event(
        db,
        event_type="inbound_email_ingested",
        account_id=account.id,
        detail={"case_id": str(case_id), "verdict": result.verdict.value},
        ip_address=_client_ip(request),
    )
    db.commit()
    db.refresh(case)

    return InboundEmailResponse(
        status="created", case_id=case.id, verdict=result.verdict, score=result.score
    )
