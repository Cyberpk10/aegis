"""Pydantic response/data models shared across the API."""

from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Literal
from uuid import UUID

from pydantic import BaseModel, Field

from app.events.schema import ActivityEvent


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
    id: UUID
    created_at: datetime
    verdict: Verdict
    score: int
    summary: EmailSummary
    indicators: list[Indicator]
    framework_mappings: dict[str, list[FrameworkControlRef]]
    analyst_narrative: str | None = None
    analyst_model: str | None = None


class CaseSummary(BaseModel):
    """A single row in the paginated case list."""

    id: UUID
    created_at: datetime
    filename: str
    verdict: Verdict
    score: int
    from_addr: str | None = None
    subject: str | None = None

    model_config = {"from_attributes": True}


class CaseListResponse(BaseModel):
    items: list[CaseSummary]
    total: int
    page: int
    page_size: int


class LabelRequest(BaseModel):
    analyst_verdict: Verdict
    note: str | None = None


class LabelResponse(BaseModel):
    id: UUID
    case_id: UUID | None = None
    incident_id: UUID | None = None
    analyst_verdict: Verdict
    note: str | None = None
    labeled_by: str
    created_at: datetime

    model_config = {"from_attributes": True}


class CaseDetailResponse(BaseModel):
    """Everything persisted for a case, except the raw-email disk pointer (not exposed
    via the API)."""

    id: UUID
    created_at: datetime
    filename: str
    verdict: Verdict
    score: int
    from_addr: str | None = None
    subject: str | None = None
    indicators: list[Indicator]
    framework_mappings: dict[str, list[FrameworkControlRef]]
    analyst_narrative: str | None = None
    analyst_model: str | None = None
    latest_label: LabelResponse | None = None

    model_config = {"from_attributes": True}


class PeriodCount(BaseModel):
    """A count for the current period alongside the prior period-of-equal-length, for
    the dashboard's period-over-period deltas."""

    current: int
    previous: int
    delta: int
    delta_pct: float | None = None


class VerdictCounts(BaseModel):
    malicious: PeriodCount
    suspicious: PeriodCount
    safe: PeriodCount


class TopIndicator(BaseModel):
    indicator_id: str
    title: str
    category: str
    severity: Severity
    count: int


class MonthlyThreatCount(BaseModel):
    month: str
    count: int


class FrameworkCoverage(BaseModel):
    framework_key: str
    framework_name: str
    total_controls: int
    covered_controls: int
    coverage_pct: float


class AgreementRate(BaseModel):
    rate_pct: float | None = None
    labeled_count: int
    agreeing_count: int


class KRIs(BaseModel):
    malicious_catch_rate_pct: float | None = None
    false_positive_rate_pct: float | None = None
    mean_unlabeled_backlog_days: float | None = None
    unlabeled_count: int
    labeled_count: int


class DashboardSummaryResponse(BaseModel):
    period_start: datetime
    period_end: datetime
    previous_period_start: datetime
    previous_period_end: datetime
    total_analyzed: PeriodCount
    verdict_counts: VerdictCounts
    analyst_agreement: AgreementRate
    top_indicators: list[TopIndicator]
    monthly_threat_trend: list[MonthlyThreatCount]
    kris: KRIs
    framework_coverage: list[FrameworkCoverage]


class AuditFramework(str, Enum):
    NIST = "nist"
    ISO = "iso"
    SOC2 = "soc2"
    MITRE = "mitre"


class AuditCaseRef(BaseModel):
    id: UUID
    verdict: Verdict
    created_at: datetime


class AuditControlEvidence(BaseModel):
    control_id: str
    control_name: str
    detection_count: int
    sample_cases: list[AuditCaseRef]
    operating: bool


class AuditEvidenceResponse(BaseModel):
    framework_key: str
    framework_name: str
    period_start: datetime
    period_end: datetime
    controls: list[AuditControlEvidence]
    total_controls: int
    operating_controls: int


class AuditReportRequest(BaseModel):
    framework: AuditFramework
    date_from: datetime | None = None
    date_to: datetime | None = None


class AuditReportSummary(BaseModel):
    id: UUID
    created_at: datetime
    framework_key: str
    framework_name: str
    period_start: datetime
    period_end: datetime
    total_controls: int
    operating_controls: int
    total_supporting_cases: int


class AuditReportListResponse(BaseModel):
    items: list[AuditReportSummary]
    total: int
    page: int
    page_size: int


class RemediationStatus(str, Enum):
    RECOMMENDED = "recommended"
    APPROVED = "approved"
    DONE = "done"


class RemediationControlRef(BaseModel):
    framework_key: str
    control_id: str
    control_name: str


class PlaybookStepResponse(BaseModel):
    step_id: str
    title: str
    description: str
    category: str
    related_indicator_ids: list[str]
    control_refs: list[RemediationControlRef]
    status: RemediationStatus
    actor: str | None = None
    note: str | None = None
    acted_at: datetime | None = None


class RemediationPlaybookResponse(BaseModel):
    case_id: UUID
    generated_at: datetime
    steps: list[PlaybookStepResponse]


class RemediationActionRequest(BaseModel):
    status: Literal["approved", "done"]
    note: str | None = None


class RemediationActionResponse(BaseModel):
    id: UUID
    case_id: UUID | None = None
    incident_id: UUID | None = None
    step_id: str
    status: str
    actor: str
    note: str | None = None
    created_at: datetime


class TargetSummaryResponse(BaseModel):
    recipient: str
    hit_count: int
    flagged_for_training: bool
    top_indicator_id: str | None = None
    top_indicator_title: str | None = None
    recommendation: str | None = None
    sample_case_ids: list[UUID]
    first_flagged_at: datetime | None = None


class TargetsListResponse(BaseModel):
    threshold: int
    targets: list[TargetSummaryResponse]


class CopilotQueryRequest(BaseModel):
    question: str


class CopilotTemplateUsed(BaseModel):
    template: str
    params: dict


class CopilotQueryResponse(BaseModel):
    question: str
    narrative: str
    template_used: CopilotTemplateUsed
    result: dict
    generated_at: datetime


class RiskAttackTypeBreakdown(BaseModel):
    attack_type: str
    count: int
    avg_loss_usd: float
    prevention_weight: float
    subtotal_usd: float


class RiskExposureAvoided(BaseModel):
    total_usd: float
    by_attack_type: list[RiskAttackTypeBreakdown]


class RiskResidualRisk(BaseModel):
    total_usd: float
    false_negative_count: int
    by_attack_type: list[RiskAttackTypeBreakdown]
    note: str


class RiskDetectionCounts(BaseModel):
    malicious: int
    suspicious: int
    safe: int


class RiskAssumption(BaseModel):
    value: float
    source: str


class FinancialRiskResponse(BaseModel):
    period_start: datetime
    period_end: datetime
    exposure_avoided: RiskExposureAvoided
    residual_risk: RiskResidualRisk
    detection_counts: RiskDetectionCounts
    assumptions: dict[str, RiskAssumption]
    generated_at: datetime


class Finding(BaseModel):
    """One detection rule firing over a window of activity events (M5 Stage 1) — the
    intrusion-detection analog of Indicator, with `points` instead of `score` and
    references to the actual triggering Event rows instead of free-text evidence."""

    id: str
    category: str
    title: str
    description: str
    severity: Severity
    points: float
    evidence_event_ids: list[UUID] = Field(default_factory=list)


class IncidentSummary(BaseModel):
    id: UUID
    created_at: datetime
    title: str
    actor: str
    verdict: Verdict
    score: int
    detection_types: list[str]
    window_start: datetime
    window_end: datetime

    model_config = {"from_attributes": True}


class IncidentListResponse(BaseModel):
    items: list[IncidentSummary]
    total: int
    page: int
    page_size: int


class IncidentDetailResponse(BaseModel):
    id: UUID
    created_at: datetime
    title: str
    actor: str
    verdict: Verdict
    score: int
    detection_types: list[str]
    findings: list[Finding]
    framework_mappings: dict[str, list[FrameworkControlRef]]
    window_start: datetime
    window_end: datetime
    evidence_events: list[ActivityEvent]
    latest_label: LabelResponse | None = None


class EventBatchResponse(BaseModel):
    accepted: int
    incidents_created: list[IncidentSummary]


class AutonomyLevel(str, Enum):
    L0 = "L0"
    L1 = "L1"
    L2 = "L2"
    L3 = "L3"


class AutonomyPolicyRuleSchema(BaseModel):
    action_type: str
    min_confidence: float
    scopes: list[str] | None = None
    full_auto: bool = False


class AutonomyPolicyRequest(BaseModel):
    level: AutonomyLevel
    rules: list[AutonomyPolicyRuleSchema] = Field(default_factory=list)
    exclusions: list[str] = Field(default_factory=list)
    blast_radius_limit: int = Field(default=10, ge=1)
    blast_radius_window_minutes: int = Field(default=60, ge=1)


class AutonomyPolicyResponse(BaseModel):
    tenant_id: str
    level: AutonomyLevel
    rules: list[AutonomyPolicyRuleSchema]
    exclusions: list[str]
    blast_radius_limit: int
    blast_radius_window_minutes: int
    halted_at: datetime | None = None
    updated_at: datetime


class AutonomyActionResponse(BaseModel):
    id: UUID
    tenant_id: str
    created_at: datetime
    case_id: UUID | None = None
    incident_id: UUID | None = None
    trigger_finding_id: str
    action_type: str
    target: str
    confidence: float
    policy_rule: dict | None = None
    decision: str
    status: str
    result: dict | None = None
    reversible: bool
    mapped_controls: dict[str, list[FrameworkControlRef]]

    model_config = {"from_attributes": True}


class AutonomyActionListResponse(BaseModel):
    items: list[AutonomyActionResponse]
    total: int
    page: int
    page_size: int


class AutonomyHaltResponse(BaseModel):
    tenant_id: str
    level: AutonomyLevel
    halted_at: datetime
    halted_pending_count: int


class ControlHealthResponse(BaseModel):
    framework_key: str
    control_id: str
    control_name: str
    status: str
    last_evidence_at: datetime | None = None
    evidence_count: int
    expected_interval_days: int


class ControlHealthListResponse(BaseModel):
    items: list[ControlHealthResponse]
    total: int


class DriftAlertResponse(BaseModel):
    framework_key: str
    control_id: str
    control_name: str
    type: str
    since: datetime
    severity: str
    detail: str


class DriftAlertListResponse(BaseModel):
    items: list[DriftAlertResponse]
    total: int
