import type { Finding, Severity } from "../../types/analysis";

const SEVERITY_STYLES: Record<Severity, string> = {
  low: "bg-slate-100 text-slate-700 border-slate-300",
  medium: "bg-amber-100 text-amber-800 border-amber-300",
  high: "bg-red-100 text-red-800 border-red-300",
};

interface FindingListProps {
  findings: Finding[];
}

export default function FindingList({ findings }: FindingListProps) {
  if (findings.length === 0) {
    return (
      <p className="rounded-lg border border-slate-200 bg-slate-50 p-4 text-sm text-slate-500">
        No detections fired for this incident.
      </p>
    );
  }

  return (
    <ul className="flex flex-col gap-3">
      {findings.map((finding) => (
        <li key={finding.id} className="rounded-lg border border-slate-200 bg-white p-4 shadow-sm">
          <div className="flex flex-wrap items-center justify-between gap-2">
            <h3 className="font-semibold text-slate-800">{finding.title}</h3>
            <span
              className={`rounded-full border px-2.5 py-0.5 text-xs font-medium uppercase tracking-wide ${SEVERITY_STYLES[finding.severity]}`}
            >
              {finding.severity} · +{finding.points}
            </span>
          </div>
          <p className="mt-1 text-sm text-slate-600">{finding.description}</p>
          <p className="mt-2 text-xs text-slate-500">
            {finding.evidence_event_ids.length} triggering event
            {finding.evidence_event_ids.length === 1 ? "" : "s"} — see Evidence below.
          </p>
        </li>
      ))}
    </ul>
  );
}
