"""Aegis backend — FastAPI application entrypoint."""

from __future__ import annotations

from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.api.routes.analyze import router as analyze_router
from app.api.routes.cases import router as cases_router
from app.api.routes.labels import router as labels_router
from app.core.config import settings
from app.db.session import Base, engine
from app.storage.raw_email_store import purge_expired


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

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(analyze_router)
app.include_router(cases_router)
app.include_router(labels_router)


@app.get("/health")
async def health() -> dict[str, str]:
    return {"status": "ok"}
