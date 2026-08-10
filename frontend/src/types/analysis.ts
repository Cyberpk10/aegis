export type AuthResultValue =
  | "pass"
  | "fail"
  | "softfail"
  | "neutral"
  | "none"
  | "temperror"
  | "permerror"
  | "unknown";

export interface AuthResults {
  spf: AuthResultValue;
  dkim: AuthResultValue;
  dmarc: AuthResultValue;
  raw_header: string | null;
}

export interface EmailSummary {
  from_display: string | null;
  from_address: string | null;
  reply_to_address: string | null;
  to: string[];
  subject: string | null;
  date: string | null;
  auth_results: AuthResults;
  link_count: number;
  attachment_count: number;
}

export type Severity = "low" | "medium" | "high";

export interface Indicator {
  id: string;
  category: string;
  title: string;
  description: string;
  evidence: string[];
  severity: Severity;
  score: number;
}

export type Verdict = "safe" | "suspicious" | "malicious";

export interface FrameworkControlRef {
  indicator_id: string;
  control_id: string;
  control_name: string;
  url: string | null;
}

export interface AnalyzeResponse {
  id: string;
  created_at: string;
  verdict: Verdict;
  score: number;
  summary: EmailSummary;
  indicators: Indicator[];
  framework_mappings: Record<string, FrameworkControlRef[]>;
  analyst_narrative: string | null;
  analyst_model: string | null;
}

export type MessageChannel = "email" | "slack" | "teams";

export interface CaseSummary {
  id: string;
  created_at: string;
  filename: string;
  channel: MessageChannel;
  verdict: Verdict;
  score: number;
  from_addr: string | null;
  subject: string | null;
}

export interface CaseListResponse {
  items: CaseSummary[];
  total: number;
  page: number;
  page_size: number;
}

export interface Label {
  id: string;
  case_id: string | null;
  incident_id: string | null;
  analyst_verdict: Verdict;
  note: string | null;
  labeled_by: string;
  created_at: string;
}

export interface CaseDetail {
  id: string;
  created_at: string;
  filename: string;
  channel: MessageChannel;
  verdict: Verdict;
  score: number;
  from_addr: string | null;
  subject: string | null;
  indicators: Indicator[];
  framework_mappings: Record<string, FrameworkControlRef[]>;
  analyst_narrative: string | null;
  analyst_model: string | null;
  latest_label: Label | null;
}

export interface PeriodCount {
  current: number;
  previous: number;
  delta: number;
  delta_pct: number | null;
}

export interface VerdictCounts {
  malicious: PeriodCount;
  suspicious: PeriodCount;
  safe: PeriodCount;
}

export interface TopIndicator {
  indicator_id: string;
  title: string;
  category: string;
  severity: Severity;
  count: number;
}

export interface MonthlyThreatCount {
  month: string;
  count: number;
}

export interface FrameworkCoverage {
  framework_key: string;
  framework_name: string;
  total_controls: number;
  covered_controls: number;
  coverage_pct: number;
}

export interface AgreementRate {
  rate_pct: number | null;
  labeled_count: number;
  agreeing_count: number;
}

export interface KRIs {
  malicious_catch_rate_pct: number | null;
  false_positive_rate_pct: number | null;
  mean_unlabeled_backlog_days: number | null;
  unlabeled_count: number;
  labeled_count: number;
}

export interface DashboardSummary {
  period_start: string;
  period_end: string;
  previous_period_start: string;
  previous_period_end: string;
  total_analyzed: PeriodCount;
  verdict_counts: VerdictCounts;
  analyst_agreement: AgreementRate;
  top_indicators: TopIndicator[];
  monthly_threat_trend: MonthlyThreatCount[];
  kris: KRIs;
  framework_coverage: FrameworkCoverage[];
}

export type AuditFrameworkAlias = "nist" | "iso" | "soc2" | "mitre";

export interface AuditCaseRef {
  id: string;
  verdict: Verdict;
  created_at: string;
}

export interface AuditControlEvidence {
  control_id: string;
  control_name: string;
  detection_count: number;
  sample_cases: AuditCaseRef[];
  operating: boolean;
}

export interface AuditEvidenceResponse {
  framework_key: string;
  framework_name: string;
  period_start: string;
  period_end: string;
  controls: AuditControlEvidence[];
  total_controls: number;
  operating_controls: number;
}

export interface AuditReportSummary {
  id: string;
  created_at: string;
  framework_key: string;
  framework_name: string;
  period_start: string;
  period_end: string;
  total_controls: number;
  operating_controls: number;
  total_supporting_cases: number;
}

export interface AuditReportListResponse {
  items: AuditReportSummary[];
  total: number;
  page: number;
  page_size: number;
}

export type RemediationStatus = "recommended" | "approved" | "done";

export interface RemediationControlRef {
  framework_key: string;
  control_id: string;
  control_name: string;
}

export interface PlaybookStep {
  step_id: string;
  title: string;
  description: string;
  category: string;
  related_indicator_ids: string[];
  control_refs: RemediationControlRef[];
  status: RemediationStatus;
  actor: string | null;
  note: string | null;
  acted_at: string | null;
}

export interface RemediationPlaybook {
  case_id: string;
  generated_at: string;
  steps: PlaybookStep[];
}

export interface TargetSummary {
  recipient: string;
  hit_count: number;
  flagged_for_training: boolean;
  top_indicator_id: string | null;
  top_indicator_title: string | null;
  recommendation: string | null;
  sample_case_ids: string[];
  first_flagged_at: string | null;
}

export interface TargetsListResponse {
  threshold: number;
  targets: TargetSummary[];
}

export interface CopilotTemplateUsed {
  template: string;
  params: Record<string, unknown>;
}

export interface CopilotQueryResponse {
  question: string;
  narrative: string;
  template_used: CopilotTemplateUsed;
  result: Record<string, unknown>;
  generated_at: string;
}

export interface RiskAttackTypeBreakdown {
  attack_type: string;
  count: number;
  avg_loss_usd: number;
  prevention_weight: number;
  subtotal_usd: number;
}

export interface RiskExposureAvoided {
  total_usd: number;
  by_attack_type: RiskAttackTypeBreakdown[];
}

export interface RiskResidualRisk {
  total_usd: number;
  false_negative_count: number;
  by_attack_type: RiskAttackTypeBreakdown[];
  note: string;
}

export interface RiskDetectionCounts {
  malicious: number;
  suspicious: number;
  safe: number;
}

export interface RiskAssumption {
  value: number;
  source: string;
}

export interface FinancialRiskResponse {
  period_start: string;
  period_end: string;
  exposure_avoided: RiskExposureAvoided;
  residual_risk: RiskResidualRisk;
  detection_counts: RiskDetectionCounts;
  assumptions: Record<string, RiskAssumption>;
  generated_at: string;
}

export type EventAction =
  | "login"
  | "logout"
  | "auth_fail"
  | "file_access"
  | "file_download"
  | "db_query"
  | "privilege_change"
  | "config_change"
  | "data_transfer";

export interface GeoLocation {
  country: string | null;
  region: string | null;
  lat: number | null;
  lon: number | null;
}

export interface ActivityEvent {
  id: string | null;
  timestamp: string;
  actor: string;
  source_ip: string | null;
  geo: GeoLocation | null;
  action: EventAction;
  target: string | null;
  bytes: number | null;
  device: string | null;
  outcome: string | null;
  raw: Record<string, unknown> | null;
}

export interface Finding {
  id: string;
  category: string;
  title: string;
  description: string;
  severity: Severity;
  points: number;
  evidence_event_ids: string[];
}

export interface IncidentSummary {
  id: string;
  created_at: string;
  title: string;
  actor: string;
  verdict: Verdict;
  score: number;
  detection_types: string[];
  window_start: string;
  window_end: string;
}

export interface IncidentListResponse {
  items: IncidentSummary[];
  total: number;
  page: number;
  page_size: number;
}

export interface IncidentDetail {
  id: string;
  created_at: string;
  title: string;
  actor: string;
  verdict: Verdict;
  score: number;
  detection_types: string[];
  findings: Finding[];
  framework_mappings: Record<string, FrameworkControlRef[]>;
  window_start: string;
  window_end: string;
  evidence_events: ActivityEvent[];
  latest_label: Label | null;
}

export interface EventBatchResponse {
  accepted: number;
  incidents_created: IncidentSummary[];
}

export type AutonomyLevel = "L0" | "L1" | "L2" | "L3";

export interface AutonomyPolicyRule {
  action_type: string;
  min_confidence: number;
  scopes: string[] | null;
  full_auto: boolean;
}

export interface AutonomyPolicy {
  tenant_id: string;
  level: AutonomyLevel;
  rules: AutonomyPolicyRule[];
  exclusions: string[];
  blast_radius_limit: number;
  blast_radius_window_minutes: number;
  halted_at: string | null;
  updated_at: string;
}

export interface AutonomyHaltResponse {
  tenant_id: string;
  level: AutonomyLevel;
  halted_at: string;
  halted_pending_count: number;
}

export type AutonomyDecision = "auto_execute" | "require_approval" | "skip";
export type AutonomyActionStatus = "executed" | "reversed" | "pending_approval" | "skipped" | "halted";

export interface AutonomyActionLogEntry {
  id: string;
  tenant_id: string;
  created_at: string;
  case_id: string | null;
  incident_id: string | null;
  trigger_finding_id: string;
  action_type: string;
  target: string;
  confidence: number;
  policy_rule: AutonomyPolicyRule | null;
  decision: AutonomyDecision;
  status: AutonomyActionStatus;
  result: Record<string, unknown> | null;
  reversible: boolean;
  mapped_controls: Record<string, FrameworkControlRef[]>;
}

export interface AutonomyActionListResponse {
  items: AutonomyActionLogEntry[];
  total: number;
  page: number;
  page_size: number;
}

export type ControlHealthStatus = "operating" | "degraded" | "stale" | "no_evidence";

export interface ControlHealth {
  framework_key: string;
  control_id: string;
  control_name: string;
  status: ControlHealthStatus;
  last_evidence_at: string | null;
  evidence_count: number;
  expected_interval_days: number;
}

export interface ControlHealthListResponse {
  items: ControlHealth[];
  total: number;
}

export type DriftAlertType = "went_quiet" | "auth_pass_rate_drop" | "coverage_drop";
export type DriftAlertSeverity = "medium" | "high" | "critical";

export interface DriftAlert {
  framework_key: string;
  control_id: string;
  control_name: string;
  type: DriftAlertType;
  since: string;
  severity: DriftAlertSeverity;
  detail: string;
}

export interface DriftAlertListResponse {
  items: DriftAlert[];
  total: number;
}
