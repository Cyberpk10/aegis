import type { AnalyzeResponse, CaseDetail, CaseListResponse, Verdict } from "../types/analysis";

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
