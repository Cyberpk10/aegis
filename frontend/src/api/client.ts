import type {
  ActivityEvent,
  AnalyzeResponse,
  AuditEvidenceResponse,
  AuditFrameworkAlias,
  AuditReportListResponse,
  AuditReportSummary,
  AutonomyActionListResponse,
  AutonomyHaltResponse,
  AutonomyPolicy,
  CaseDetail,
  CaseListResponse,
  ControlHealthListResponse,
  CopilotQueryResponse,
  DashboardSummary,
  DriftAlertListResponse,
  EventBatchResponse,
  FinancialRiskResponse,
  IncidentDetail,
  IncidentListResponse,
  Label,
  MessageChannel,
  RemediationPlaybook,
  TargetsListResponse,
  Verdict,
} from "../types/analysis";
import { apiFetch } from "./authClient";

export class AnalyzeError extends Error {}

async function parseErrorOrThrow(response: Response): Promise<never> {
  const body = await response.json().catch(() => null);
  throw new AnalyzeError(body?.detail ?? `Request failed with status ${response.status}`);
}

export async function postAnalyze(file: File): Promise<AnalyzeResponse> {
  const formData = new FormData();
  formData.append("file", file, file.name);

  const response = await apiFetch(`/api/analyze`, {
    method: "POST",
    body: formData,
  });

  if (!response.ok) {
    return parseErrorOrThrow(response);
  }

  return response.json();
}

export interface ListCasesParams {
  page?: number;
  pageSize?: number;
  verdict?: Verdict | "";
  channel?: MessageChannel | "";
  dateFrom?: string;
  dateTo?: string;
}

export async function getCases(params: ListCasesParams = {}): Promise<CaseListResponse> {
  const query = new URLSearchParams();
  query.set("page", String(params.page ?? 1));
  query.set("page_size", String(params.pageSize ?? 20));
  if (params.verdict) query.set("verdict", params.verdict);
  if (params.channel) query.set("channel", params.channel);
  if (params.dateFrom) query.set("date_from", params.dateFrom);
  if (params.dateTo) query.set("date_to", params.dateTo);

  const response = await apiFetch(`/api/cases?${query.toString()}`);
  if (!response.ok) {
    return parseErrorOrThrow(response);
  }
  return response.json();
}

export async function getCase(id: string): Promise<CaseDetail> {
  const response = await apiFetch(`/api/cases/${id}`);
  if (!response.ok) {
    return parseErrorOrThrow(response);
  }
  return response.json();
}

export async function deleteCase(id: string): Promise<void> {
  const response = await apiFetch(`/api/cases/${id}`, { method: "DELETE" });
  if (!response.ok && response.status !== 204) {
    return parseErrorOrThrow(response);
  }
}

export interface SubmitLabelParams {
  analyst_verdict: Verdict;
  note?: string;
}

export async function submitLabel(caseId: string, params: SubmitLabelParams): Promise<Label> {
  const response = await apiFetch(`/api/cases/${caseId}/label`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(params),
  });
  if (!response.ok) {
    return parseErrorOrThrow(response);
  }
  return response.json();
}

export interface GetDashboardSummaryParams {
  dateFrom?: string;
  dateTo?: string;
  topN?: number;
}

export async function getDashboardSummary(
  params: GetDashboardSummaryParams = {}
): Promise<DashboardSummary> {
  const query = new URLSearchParams();
  if (params.dateFrom) query.set("date_from", params.dateFrom);
  if (params.dateTo) query.set("date_to", params.dateTo);
  if (params.topN) query.set("top_n", String(params.topN));

  const response = await apiFetch(`/api/dashboard/summary?${query.toString()}`);
  if (!response.ok) {
    return parseErrorOrThrow(response);
  }
  return response.json();
}

export interface GetAuditEvidenceParams {
  framework: AuditFrameworkAlias;
  dateFrom?: string;
  dateTo?: string;
}

export async function getAuditEvidence(
  params: GetAuditEvidenceParams
): Promise<AuditEvidenceResponse> {
  const query = new URLSearchParams();
  query.set("framework", params.framework);
  if (params.dateFrom) query.set("date_from", params.dateFrom);
  if (params.dateTo) query.set("date_to", params.dateTo);

  const response = await apiFetch(`/api/audit/evidence?${query.toString()}`);
  if (!response.ok) {
    return parseErrorOrThrow(response);
  }
  return response.json();
}

export interface GenerateAuditReportParams {
  framework: AuditFrameworkAlias;
  dateFrom?: string;
  dateTo?: string;
}

export async function generateAuditReport(
  params: GenerateAuditReportParams
): Promise<AuditReportSummary> {
  const response = await apiFetch(`/api/audit/report`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      framework: params.framework,
      date_from: params.dateFrom,
      date_to: params.dateTo,
    }),
  });
  if (!response.ok) {
    return parseErrorOrThrow(response);
  }
  return response.json();
}

export interface ListAuditReportsParams {
  page?: number;
  pageSize?: number;
}

export async function listAuditReports(
  params: ListAuditReportsParams = {}
): Promise<AuditReportListResponse> {
  const query = new URLSearchParams();
  query.set("page", String(params.page ?? 1));
  query.set("page_size", String(params.pageSize ?? 20));

  const response = await apiFetch(`/api/audit/reports?${query.toString()}`);
  if (!response.ok) {
    return parseErrorOrThrow(response);
  }
  return response.json();
}

export async function downloadAuditReport(id: string, format: "pdf" | "json"): Promise<void> {
  const response = await apiFetch(`/api/audit/reports/${id}/download?format=${format}`);
  if (!response.ok) {
    return parseErrorOrThrow(response);
  }

  const blob = await response.blob();
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = url;
  link.download = `aegis-audit-report.${format}`;
  document.body.appendChild(link);
  link.click();
  document.body.removeChild(link);
  URL.revokeObjectURL(url);
}

export async function getRemediationPlaybook(caseId: string): Promise<RemediationPlaybook> {
  const response = await apiFetch(`/api/cases/${caseId}/remediate`, { method: "POST" });
  if (!response.ok) {
    return parseErrorOrThrow(response);
  }
  return response.json();
}

export interface SubmitRemediationActionParams {
  status: "approved" | "done";
  note?: string;
}

export async function submitRemediationAction(
  caseId: string,
  stepId: string,
  params: SubmitRemediationActionParams
): Promise<void> {
  const response = await apiFetch(`/api/cases/${caseId}/remediate/${stepId}/action`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(params),
  });
  if (!response.ok) {
    return parseErrorOrThrow(response);
  }
}

export async function getTargets(): Promise<TargetsListResponse> {
  const response = await apiFetch(`/api/targets`);
  if (!response.ok) {
    return parseErrorOrThrow(response);
  }
  return response.json();
}

export interface GetFinancialRiskParams {
  dateFrom?: string;
  dateTo?: string;
}

export async function getFinancialRisk(
  params: GetFinancialRiskParams = {}
): Promise<FinancialRiskResponse> {
  const query = new URLSearchParams();
  if (params.dateFrom) query.set("date_from", params.dateFrom);
  if (params.dateTo) query.set("date_to", params.dateTo);

  const response = await apiFetch(`/api/risk/financial?${query.toString()}`);
  if (!response.ok) {
    return parseErrorOrThrow(response);
  }
  return response.json();
}

export async function postEventsBatch(
  events: Omit<ActivityEvent, "id">[]
): Promise<EventBatchResponse> {
  const response = await apiFetch(`/api/events`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ events }),
  });
  if (!response.ok) {
    return parseErrorOrThrow(response);
  }
  return response.json();
}

export interface ListIncidentsParams {
  page?: number;
  pageSize?: number;
  verdict?: Verdict | "";
  actor?: string;
  dateFrom?: string;
  dateTo?: string;
}

export async function getIncidents(
  params: ListIncidentsParams = {}
): Promise<IncidentListResponse> {
  const query = new URLSearchParams();
  query.set("page", String(params.page ?? 1));
  query.set("page_size", String(params.pageSize ?? 20));
  if (params.verdict) query.set("verdict", params.verdict);
  if (params.actor) query.set("actor", params.actor);
  if (params.dateFrom) query.set("date_from", params.dateFrom);
  if (params.dateTo) query.set("date_to", params.dateTo);

  const response = await apiFetch(`/api/incidents?${query.toString()}`);
  if (!response.ok) {
    return parseErrorOrThrow(response);
  }
  return response.json();
}

export async function getIncident(id: string): Promise<IncidentDetail> {
  const response = await apiFetch(`/api/incidents/${id}`);
  if (!response.ok) {
    return parseErrorOrThrow(response);
  }
  return response.json();
}

export async function deleteIncident(id: string): Promise<void> {
  const response = await apiFetch(`/api/incidents/${id}`, { method: "DELETE" });
  if (!response.ok && response.status !== 204) {
    return parseErrorOrThrow(response);
  }
}

export async function submitIncidentLabel(
  incidentId: string,
  params: SubmitLabelParams
): Promise<Label> {
  const response = await apiFetch(`/api/incidents/${incidentId}/label`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(params),
  });
  if (!response.ok) {
    return parseErrorOrThrow(response);
  }
  return response.json();
}

export async function getIncidentRemediationPlaybook(
  incidentId: string
): Promise<RemediationPlaybook> {
  const response = await apiFetch(`/api/incidents/${incidentId}/remediate`, { method: "POST" });
  if (!response.ok) {
    return parseErrorOrThrow(response);
  }
  return response.json();
}

export async function submitIncidentRemediationAction(
  incidentId: string,
  stepId: string,
  params: SubmitRemediationActionParams
): Promise<void> {
  const response = await apiFetch(`/api/incidents/${incidentId}/remediate/${stepId}/action`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(params),
  });
  if (!response.ok) {
    return parseErrorOrThrow(response);
  }
}

export async function queryCopilot(question: string): Promise<CopilotQueryResponse> {
  const response = await apiFetch(`/api/copilot/query`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ question }),
  });
  if (!response.ok) {
    return parseErrorOrThrow(response);
  }
  return response.json();
}

export async function getAutonomyPolicy(): Promise<AutonomyPolicy> {
  const response = await apiFetch(`/api/autonomy/policy`);
  if (!response.ok) {
    return parseErrorOrThrow(response);
  }
  return response.json();
}

export type PutAutonomyPolicyParams = Pick<
  AutonomyPolicy,
  "level" | "rules" | "exclusions" | "blast_radius_limit" | "blast_radius_window_minutes"
>;

export async function putAutonomyPolicy(
  params: PutAutonomyPolicyParams
): Promise<AutonomyPolicy> {
  const response = await apiFetch(`/api/autonomy/policy`, {
    method: "PUT",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(params),
  });
  if (!response.ok) {
    return parseErrorOrThrow(response);
  }
  return response.json();
}

export async function haltAutonomy(): Promise<AutonomyHaltResponse> {
  const response = await apiFetch(`/api/autonomy/halt`, { method: "POST" });
  if (!response.ok) {
    return parseErrorOrThrow(response);
  }
  return response.json();
}

export interface ListAutonomyActionsParams {
  page?: number;
  pageSize?: number;
  actionType?: string;
  decision?: string;
  status?: string;
}

export async function getAutonomyActions(
  params: ListAutonomyActionsParams = {}
): Promise<AutonomyActionListResponse> {
  const query = new URLSearchParams();
  query.set("page", String(params.page ?? 1));
  query.set("page_size", String(params.pageSize ?? 20));
  if (params.actionType) query.set("action_type", params.actionType);
  if (params.decision) query.set("decision", params.decision);
  if (params.status) query.set("status", params.status);

  const response = await apiFetch(`/api/autonomy/actions?${query.toString()}`);
  if (!response.ok) {
    return parseErrorOrThrow(response);
  }
  return response.json();
}

export async function reverseAutonomyAction(id: string): Promise<void> {
  const response = await apiFetch(`/api/autonomy/actions/${id}/reverse`, { method: "POST" });
  if (!response.ok) {
    return parseErrorOrThrow(response);
  }
}

export async function getMonitoringControls(
  framework?: string
): Promise<ControlHealthListResponse> {
  const query = new URLSearchParams();
  if (framework) query.set("framework", framework);
  const suffix = query.toString() ? `?${query.toString()}` : "";

  const response = await apiFetch(`/api/monitoring/controls${suffix}`);
  if (!response.ok) {
    return parseErrorOrThrow(response);
  }
  return response.json();
}

export async function getMonitoringDrift(): Promise<DriftAlertListResponse> {
  const response = await apiFetch(`/api/monitoring/drift`);
  if (!response.ok) {
    return parseErrorOrThrow(response);
  }
  return response.json();
}
