import type { Verdict } from "../types/analysis";

const VERDICT_STYLES: Record<Verdict, { label: string; classes: string }> = {
  safe: { label: "Safe", classes: "bg-emerald-100 text-emerald-800 border-emerald-300" },
  suspicious: { label: "Suspicious", classes: "bg-amber-100 text-amber-800 border-amber-300" },
  malicious: { label: "Malicious", classes: "bg-red-100 text-red-800 border-red-300" },
};

interface VerdictBadgeProps {
  verdict: Verdict;
  score: number;
}

export default function VerdictBadge({ verdict, score }: VerdictBadgeProps) {
  const style = VERDICT_STYLES[verdict];

  return (
    <div className="flex items-center gap-4">
      <span
        className={`inline-flex items-center rounded-full border px-4 py-1.5 text-lg font-semibold ${style.classes}`}
      >
        {style.label}
      </span>
      <div className="text-slate-700">
        <span className="text-2xl font-bold">{score}</span>
        <span className="text-sm text-slate-500"> / 100 risk score</span>
      </div>
    </div>
  );
}
