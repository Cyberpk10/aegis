"""Pydantic response/data models shared across the API."""

from __future__ import annotations

from enum import Enum

from pydantic import BaseModel, Field


class AuthResultValue(str, Enum):
    PASS = "pass"
    FAIL = "fail"
    SOFTFAIL = "softfail"
    NEUTRAL = "neutral"
    NONE = "none"
    TEMPERROR = "temperror"
    PERMERROR = "permerror"
    UNKNOWN = "unknown"


class AuthResults(BaseModel):
    spf: AuthResultValue = AuthResultValue.UNKNOWN
    dkim: AuthResultValue = AuthResultValue.UNKNOWN
    dmarc: AuthResultValue = AuthResultValue.UNKNOWN
    raw_header: str | None = None


class LinkInfo(BaseModel):
    display_text: str
    href: str
    href_domain: str | None = None


class AttachmentInfo(BaseModel):
    filename: str
    content_type: str | None = None
    size_bytes: int = 0


class EmailSummary(BaseModel):
    from_display: str | None = None
    from_address: str | None = None
    reply_to_address: str | None = None
    to: list[str] = Field(default_factory=list)
    subject: str | None = None
    date: str | None = None
    auth_results: AuthResults = Field(default_factory=AuthResults)
    link_count: int = 0
    attachment_count: int = 0


class Severity(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


class Indicator(BaseModel):
    id: str
    category: str
    title: str
    description: str
    evidence: list[str] = Field(default_factory=list)
    severity: Severity
    score: float


class Verdict(str, Enum):
    SAFE = "safe"
    SUSPICIOUS = "suspicious"
    MALICIOUS = "malicious"


class FrameworkControlRef(BaseModel):
    indicator_id: str
    control_id: str
    control_name: str
    url: str | None = None


class AnalyzeResponse(BaseModel):
    verdict: Verdict
    score: int
    summary: EmailSummary
    indicators: list[Indicator]
    framework_mappings: dict[str, list[FrameworkControlRef]]
    analyst_narrative: str | None = None
    analyst_model: str | None = None
