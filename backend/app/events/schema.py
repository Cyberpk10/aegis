"""Normalized, source-agnostic activity-event schema (M5 Stage 1). Any telemetry source
(IdP logs, file-server audit logs, VPN/proxy logs, DB audit logs, ...) is expected to be
mapped into this shape before being POSTed to /api/events — the detection engine
(app.detections) only ever reads this normalized shape, never a source-specific format.
"""

from __future__ import annotations

from datetime import datetime
from enum import Enum
from uuid import UUID

from pydantic import BaseModel, Field


class EventAction(str, Enum):
    LOGIN = "login"
    LOGOUT = "logout"
    AUTH_FAIL = "auth_fail"
    FILE_ACCESS = "file_access"
    FILE_DOWNLOAD = "file_download"
    DB_QUERY = "db_query"
    PRIVILEGE_CHANGE = "privilege_change"
    CONFIG_CHANGE = "config_change"
    DATA_TRANSFER = "data_transfer"


class GeoLocation(BaseModel):
    country: str | None = None
    region: str | None = None
    lat: float | None = None
    lon: float | None = None


class ActivityEvent(BaseModel):
    id: UUID | None = None
    timestamp: datetime
    actor: str
    source_ip: str | None = None
    geo: GeoLocation | None = None
    action: EventAction
    target: str | None = None
    bytes: int | None = Field(default=None, ge=0)
    device: str | None = None
    outcome: str | None = None
    raw: dict | None = None


class EventBatchRequest(BaseModel):
    # Capped (security review, M8 Stage 4): POST /api/events is authenticated but not
    # rate-limited (see app.auth.rate_limit — only login-adjacent and the inbound webhook
    # are), and every event in a batch triggers synchronous, in-request work (persist +
    # per-actor app.detections.engine.run_detections + a baseline update) with no batch-size
    # limit of its own. An unbounded list here let any authenticated account tie up a worker
    # for the duration of one oversized request. 1000 is generous for a real telemetry batch
    # while bounding worst-case per-request cost.
    events: list[ActivityEvent] = Field(max_length=1000)
