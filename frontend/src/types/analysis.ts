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
  verdict: Verdict;
  score: number;
  summary: EmailSummary;
  indicators: Indicator[];
  framework_mappings: Record<string, FrameworkControlRef[]>;
}
