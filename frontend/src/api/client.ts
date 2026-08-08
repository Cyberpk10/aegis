import type {
  ActivityEvent,
  AnalyzeResponse,
  AuditEvidenceResponse,
  AuditFrameworkAlias,
  AuditReportListResponse,
  AuditReportSummary,
  CaseDetail,
  CaseListResponse,
  CopilotQueryResponse,
  DashboardSummary,
  EventBatchResponse,
  FinancialRiskResponse,
  IncidentDetail,
  IncidentListResponse,
  Label,
  RemediationPlaybook,
  TargetsListResponse,
  Verdict,
} from "../types/analysis";

export class AnalyzeError extends Error {}

async function parseErrorOrThrow(response: Response): Promise<never> {
  const body = await response.json().catch(() => null);
  throw new AnalyzeError(body?.detail ?? `Request failed with status ${response.status}`);
}

export async function postAnalyze(file: File): Promise<AnalyzeResponse> {
  const formData = new FormData();
  formData.append("file", file, file.name);

  const response = await fetch("/api/analyze", {
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
  dateFrom?: string;
  dateTo?: string;
}

export async function getCases(params: ListCasesParams = {}): Promise<CaseListResponse> {
  const query = new URLSearchParams();
  query.set("page", String(params.page ?? 1));
  query.set("page_size", String(params.pageSize ?? 20));
  if (params.verdict) query.set("verdict", params.verdict);
  if (params.dateFrom) query.set("date_from", params.dateFrom);
  if (params.dateTo) query.set("date_to", params.dateTo);

  const response = await fetch(`/api/cases?${query.toString()}`);
  if (!response.ok) {
    return parseErrorOrThrow(response);
  }
  return response.json();
}

export async function getCase(id: string): Promise<CaseDetail> {
  const response = await fetch(`/api/cases/${id}`);
  if (!response.ok) {
    return parseErrorOrThrow(response);
  }
  return response.json();
}

export async function deleteCase(id: string): Promise<void> {
  const response = await fetch(`/api/cases/${id}`, { method: "DELETE" });
  if (!response.ok && response.status !== 204) {
    return parseErrorOrThrow(response);
  }
}

export interface SubmitLabelParams {
  analyst_verdict: Verdict;
  note?: string;
}

export async function submitLabel(caseId: string, params: SubmitLabelParams): Promise<Label> {
  const response = await fetch(`/api/cases/${caseId}/label`, {
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

  const response = await fetch(`/api/dashboard/summary?${query.toString()}`);
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

  const response = await fetch(`/api/audit/evidence?${query.toString()}`);
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
  const response = await fetch("/api/audit/report", {
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

  const response = await fetch(`/api/audit/reports?${query.toString()}`);
  if (!response.ok) {
    return parseErrorOrThrow(response);
  }
  return response.json();
}

export async function downloadAuditReport(id: string, format: "pdf" | "json"): Promise<void> {
  const response = await fetch(`/api/audit/reports/${id}/download?format=${format}`);
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
  const response = await fetch(`/api/cases/${caseId}/remediate`, { method: "POST" });
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
  const response = await fetch(`/api/cases/${caseId}/remediate/${stepId}/action`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(params),
  });
  if (!response.ok) {
    return parseErrorOrThrow(response);
  }
}

export async function getTargets(): Promise<TargetsListResponse> {
  const response = await fetch("/api/targets");
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

  const response = await fetch(`/api/risk/financial?${query.toString()}`);
  if (!response.ok) {
    return parseErrorOrThrow(response);
  }
  return response.json();
}

export async function postEventsBatch(
  events: Omit<ActivityEvent, "id">[]
): Promise<EventBatchResponse> {
  const response = await fetch("/api/events", {
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

  const response = await fetch(`/api/incidents?${query.toString()}`);
  if (!response.ok) {
    return parseErrorOrThrow(response);
  }
  return response.json();
}

export async function getIncident(id: string): Promise<IncidentDetail> {
  const response = await fetch(`/api/incidents/${id}`);
  if (!response.ok) {
    return parseErrorOrThrow(response);
  }
  return response.json();
}

export async function deleteIncident(id: string): Promise<void> {
  const response = await fetch(`/api/incidents/${id}`, { method: "DELETE" });
  if (!response.ok && response.status !== 204) {
    return parseErrorOrThrow(response);
  }
}

export async function submitIncidentLabel(
  incidentId: string,
  params: SubmitLabelParams
): Promise<Label> {
  const response = await fetch(`/api/incidents/${incidentId}/label`, {
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
  const response = await fetch(`/api/incidents/${incidentId}/remediate`, { method: "POST" });
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
  const response = await fetch(`/api/incidents/${incidentId}/remediate/${stepId}/action`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(params),
  });
  if (!response.ok) {
    return parseErrorOrThrow(response);
  }
}

export async function queryCopilot(question: string): Promise<CopilotQueryResponse> {
  const response = await fetch("/api/copilot/query", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ question }),
  });
  if (!response.ok) {
    return parseErrorOrThrow(response);
  }
  return response.json();
}
