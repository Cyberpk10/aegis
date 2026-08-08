import { useEffect, useState } from "react";
import { getDashboardSummary } from "../../api/client";
import type { DashboardSummary } from "../../types/analysis";
import ExposureAvoidedCard from "./ExposureAvoidedCard";
import FrameworkCoveragePanel from "./FrameworkCoveragePanel";
import KpiCards from "./KpiCards";
import KriTable from "./KriTable";
import RepeatTargetsWidget from "./RepeatTargetsWidget";
import ThreatTrendChart from "./ThreatTrendChart";
import TopIndicatorsTable from "./TopIndicatorsTable";
import VerdictDonut from "./VerdictDonut";

export default function DashboardView() {
  const [dateFrom, setDateFrom] = useState("");
  const [dateTo, setDateTo] = useState("");
  const [summary, setSummary] = useState<DashboardSummary | null>(null);
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;
    setIsLoading(true);
    setError(null);

    getDashboardSummary({
      dateFrom: dateFrom ? `${dateFrom}T00:00:00` : undefined,
      dateTo: dateTo ? `${dateTo}T23:59:59` : undefined,
    })
      .then((data) => {
        if (!cancelled) setSummary(data);
      })
      .catch((err) => {
        if (!cancelled) setError(err instanceof Error ? err.message : "Failed to load dashboard.");
      })
      .finally(() => {
        if (!cancelled) setIsLoading(false);
      });

    return () => {
      cancelled = true;
    };
  }, [dateFrom, dateTo]);

  return (
    <div className="flex flex-col gap-6">
      <div className="flex flex-wrap items-end justify-between gap-4 rounded-xl border border-slate-800 bg-slate-900 p-5 shadow-sm">
        <div>
          <h2 className="text-lg font-semibold text-white">Threat &amp; Compliance Dashboard</h2>
          <p className="text-sm text-slate-300">
            {summary
              ? `${new Date(summary.period_start).toLocaleDateString()} – ${new Date(summary.period_end).toLocaleDateString()}`
              : "Loading period…"}
          </p>
        </div>
        <div className="flex gap-3">
          <label className="flex flex-col gap-1 text-sm text-slate-200">
            From
            <input
              type="date"
              value={dateFrom}
              onChange={(event) => setDateFrom(event.target.value)}
              className="rounded-lg border border-slate-300 bg-white px-3 py-1.5 text-sm text-slate-700"
            />
          </label>
          <label className="flex flex-col gap-1 text-sm text-slate-200">
            To
            <input
              type="date"
              value={dateTo}
              onChange={(event) => setDateTo(event.target.value)}
              className="rounded-lg border border-slate-300 bg-white px-3 py-1.5 text-sm text-slate-700"
            />
          </label>
        </div>
      </div>

      {error && (
        <div className="rounded-lg border border-red-300 bg-red-50 p-4 text-sm text-red-700">{error}</div>
      )}

      {isLoading && !summary && <p className="text-sm text-slate-500">Loading dashboard…</p>}

      {summary && (
        <>
          <KpiCards summary={summary} />

          <ExposureAvoidedCard />

          <div className="grid grid-cols-1 gap-6 lg:grid-cols-2">
            <VerdictDonut verdictCounts={summary.verdict_counts} />
            <ThreatTrendChart monthlyTrend={summary.monthly_threat_trend} />
          </div>

          <TopIndicatorsTable indicators={summary.top_indicators} />
          <FrameworkCoveragePanel coverage={summary.framework_coverage} />
          <RepeatTargetsWidget />
          <KriTable kris={summary.kris} />
        </>
      )}
    </div>
  );
}
