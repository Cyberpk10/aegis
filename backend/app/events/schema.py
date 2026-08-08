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
    events: list[ActivityEvent]
