import type { AnalyzeResponse } from "../types/analysis";

export class AnalyzeError extends Error {}

export async function postAnalyze(file: File): Promise<AnalyzeResponse> {
  const formData = new FormData();
  formData.append("file", file, file.name);

  const response = await fetch("/api/analyze", {
    method: "POST",
    body: formData,
  });

  if (!response.ok) {
    const body = await response.json().catch(() => null);
    throw new AnalyzeError(body?.detail ?? `Request failed with status ${response.status}`);
  }

  return response.json();
}
