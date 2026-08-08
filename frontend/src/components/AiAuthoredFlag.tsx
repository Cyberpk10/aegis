import type { Indicator } from "../types/analysis";

interface AiAuthoredFlagProps {
  indicators: Indicator[];
}

export default function AiAuthoredFlag({ indicators }: AiAuthoredFlagProps) {
  const indicator = indicators.find((i) => i.id === "AI_AUTHORED_SUSPECTED");
  if (!indicator) {
    return null;
  }

  const reason = indicator.evidence[0] ?? indicator.description;

  return (
    <section className="rounded-xl border border-violet-300 bg-violet-50 p-4 shadow-sm">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <h2 className="text-sm font-semibold uppercase tracking-wide text-violet-800">
          Likely AI-generated
        </h2>
        <span className="rounded-full border border-violet-300 bg-white px-2.5 py-0.5 text-xs font-medium text-violet-700">
          {indicator.evidence.length} stylistic signal{indicator.evidence.length === 1 ? "" : "s"}
        </span>
      </div>
      <p className="mt-1 text-sm text-violet-900">{reason}</p>
    </section>
  );
}
