"""Aegis backend — FastAPI application entrypoint."""

from __future__ import annotations

import logging
from contextlib import asynccontextmanager

from fastapi import Depends, FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.httpsredirect import HTTPSRedirectMiddleware
from slowapi import _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from slowapi.middleware import SlowAPIMiddleware
from sqlalchemy import text
from sqlalchemy.orm import Session

from app.api.routes.analyze import router as analyze_router
from app.api.routes.audit import router as audit_router
from app.api.routes.auth import router as auth_router
from app.api.routes.autonomy import router as autonomy_router
from app.api.routes.cases import router as cases_router
from app.api.routes.copilot import router as copilot_router
from app.api.routes.dashboard import router as dashboard_router
from app.api.routes.events import router as events_router
from app.api.routes.incidents import router as incidents_router
from app.api.routes.labels import router as labels_router
from app.api.routes.messages import router as messages_router
from app.api.routes.monitoring import router as monitoring_router
from app.api.routes.remediation import cases_router as remediation_cases_router
from app.api.routes.remediation import incidents_router as remediation_incidents_router
from app.api.routes.remediation import targets_router as targets_router
from app.api.routes.risk import router as risk_router
from app.auth.rate_limit import limiter
from app.core.config import settings
from app.db.session import Base, engine, get_db
from app.storage.raw_email_store import purge_expired

logging.basicConfig(
    level=settings.log_level,
    format="%(asctime)s %(levelname)s %(name)s %(message)s",
)


@asynccontextmanager
async def lifespan(app: FastAPI):
    # SQLite fallback (local dev without Docker/Alembic): create tables if missing. Real
    # Postgres deployments are expected to have run `alembic upgrade head` instead.
    if settings.database_url.startswith("sqlite"):
        Base.metadata.create_all(bind=engine)
    purge_expired()
    yield


app = FastAPI(
    title="Aegis",
    description="Defensive email-security analysis API.",
    version="0.1.0",
    lifespan=lifespan,
)

# Rate limiting (M8 Stage 2) — only app.api.routes.auth's login/signup/password-reset/
# invite-accept endpoints actually apply @limiter.limit(...); everything else is
# unaffected. In-memory storage, see app.auth.rate_limit for why that's the right choice
# for the current single-instance deployment.
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)
app.add_middleware(SlowAPIMiddleware)

# Gated to production only — HTTPSRedirectMiddleware would otherwise break local
# http://localhost dev. Relies on the ASGI server trusting X-Forwarded-Proto from the
# platform's TLS-terminating proxy (uvicorn's --proxy-headers, see docker-entrypoint.sh) —
# without that, Starlette can't see the real scheme and this would redirect-loop.
if settings.environment == "production":
    app.add_middleware(HTTPSRedirectMiddleware)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(auth_router)
app.include_router(analyze_router)
app.include_router(cases_router)
app.include_router(labels_router)
app.include_router(dashboard_router)
app.include_router(audit_router)
app.include_router(remediation_cases_router)
app.include_router(targets_router)
app.include_router(copilot_router)
app.include_router(risk_router)
app.include_router(events_router)
app.include_router(incidents_router)
app.include_router(remediation_incidents_router)
app.include_router(autonomy_router)
app.include_router(monitoring_router)
app.include_router(messages_router)


@app.get("/health")
async def health(db: Session = Depends(get_db)) -> dict[str, str]:
    """Liveness + readiness: also confirms the database is actually reachable, so a deploy
    doesn't report healthy while the DB is down."""
    try:
        db.execute(text("SELECT 1"))
    except Exception as exc:  # noqa: BLE001 - surface any DB failure as a 503, not a 500
        raise HTTPException(status_code=503, detail=f"Database unavailable: {exc}") from exc
    return {"status": "ok"}
