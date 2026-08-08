import type { DashboardSummary } from "../../types/analysis";

type Tone = "positive-up" | "negative-up" | "neutral";

interface DeltaBadgeProps {
  delta: number;
  deltaPct: number | null;
  tone: Tone;
}

function DeltaBadge({ delta, deltaPct, tone }: DeltaBadgeProps) {
  if (delta === 0) {
    return <span className="text-xs font-medium text-slate-400">No change</span>;
  }

  const isUp = delta > 0;
  const colorClass =
    tone === "neutral" ? "text-slate-500" : (tone === "positive-up") === isUp ? "text-emerald-600" : "text-red-600";

  return (
    <span className={`text-xs font-semibold ${colorClass}`}>
      {isUp ? "▲" : "▼"} {Math.abs(delta)}
      {deltaPct !== null && ` (${deltaPct > 0 ? "+" : ""}${deltaPct}%)`}
    </span>
  );
}

const VERDICT_CARDS: { key: keyof DashboardSummary["verdict_counts"]; label: string; tone: Tone }[] = [
  { key: "malicious", label: "Malicious", tone: "negative-up" },
  { key: "suspicious", label: "Suspicious", tone: "negative-up" },
  { key: "safe", label: "Safe", tone: "positive-up" },
];

interface KpiCardsProps {
  summary: DashboardSummary;
}

export default function KpiCards({ summary }: KpiCardsProps) {
  return (
    <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
      <div className="rounded-xl border border-slate-200 bg-white p-5 shadow-sm">
        <p className="text-sm font-medium text-slate-500">Total Analyzed</p>
        <p className="mt-1 text-3xl font-bold text-slate-900">{summary.total_analyzed.current}</p>
        <div className="mt-1">
          <DeltaBadge
            delta={summary.total_analyzed.delta}
            deltaPct={summary.total_analyzed.delta_pct}
            tone="neutral"
          />
        </div>
      </div>
      {VERDICT_CARDS.map(({ key, label, tone }) => {
        const periodCount = summary.verdict_counts[key];
        return (
          <div key={key} className="rounded-xl border border-slate-200 bg-white p-5 shadow-sm">
            <p className="text-sm font-medium text-slate-500">{label}</p>
            <p className="mt-1 text-3xl font-bold text-slate-900">{periodCount.current}</p>
            <div className="mt-1">
              <DeltaBadge delta={periodCount.delta} deltaPct={periodCount.delta_pct} tone={tone} />
            </div>
          </div>
        );
      })}
    </div>
  );
}
