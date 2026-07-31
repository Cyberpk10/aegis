import type { Indicator, Severity } from "../types/analysis";

const SEVERITY_STYLES: Record<Severity, string> = {
  low: "bg-slate-100 text-slate-700 border-slate-300",
  medium: "bg-amber-100 text-amber-800 border-amber-300",
  high: "bg-red-100 text-red-800 border-red-300",
};

interface IndicatorListProps {
  indicators: Indicator[];
}

export default function IndicatorList({ indicators }: IndicatorListProps) {
  if (indicators.length === 0) {
    return (
      <p className="rounded-lg border border-slate-200 bg-slate-50 p-4 text-sm text-slate-500">
        No phishing indicators were detected in this email.
      </p>
    );
  }

  return (
    <ul className="flex flex-col gap-3">
      {indicators.map((indicator) => (
        <li key={indicator.id} className="rounded-lg border border-slate-200 bg-white p-4 shadow-sm">
          <div className="flex flex-wrap items-center justify-between gap-2">
            <h3 className="font-semibold text-slate-800">{indicator.title}</h3>
            <span
              className={`rounded-full border px-2.5 py-0.5 text-xs font-medium uppercase tracking-wide ${SEVERITY_STYLES[indicator.severity]}`}
            >
              {indicator.severity} · +{indicator.score}
            </span>
          </div>
          <p className="mt-1 text-sm text-slate-600">{indicator.description}</p>
          {indicator.evidence.length > 0 && (
            <ul className="mt-2 list-inside list-disc space-y-0.5 text-xs text-slate-500">
              {indicator.evidence.map((line, idx) => (
                <li key={idx}>{line}</li>
              ))}
            </ul>
          )}
        </li>
      ))}
    </ul>
  );
}
