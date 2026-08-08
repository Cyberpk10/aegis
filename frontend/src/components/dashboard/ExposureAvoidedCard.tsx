import { useEffect, useState } from "react";
import { getFinancialRisk } from "../../api/client";
import type { FinancialRiskResponse, RiskAttackTypeBreakdown } from "../../types/analysis";

const ATTACK_TYPE_LABELS: Record<string, string> = {
  bec: "Business Email Compromise",
  credential_phishing: "Credential phishing",
  generic_phishing: "Generic phishing",
};

function formatUsd(value: number): string {
  return new Intl.NumberFormat("en-US", {
    style: "currency",
    currency: "USD",
    maximumFractionDigits: 0,
  }).format(value);
}

function BreakdownTable({ rows }: { rows: RiskAttackTypeBreakdown[] }) {
  return (
    <table className="w-full text-left text-sm">
      <thead className="text-xs uppercase tracking-wide text-slate-500">
        <tr>
          <th className="py-1.5 pr-3 font-medium">Attack type</th>
          <th className="py-1.5 pr-3 font-medium">Count</th>
          <th className="py-1.5 pr-3 font-medium">Avg loss</th>
          <th className="py-1.5 font-medium">Subtotal</th>
        </tr>
      </thead>
      <tbody className="divide-y divide-slate-100">
        {rows.map((row) => (
          <tr key={row.attack_type}>
            <td className="py-1.5 pr-3 text-slate-700">
              {ATTACK_TYPE_LABELS[row.attack_type] ?? row.attack_type}
            </td>
            <td className="py-1.5 pr-3 text-slate-600">{row.count}</td>
            <td className="py-1.5 pr-3 text-slate-600">{formatUsd(row.avg_loss_usd)}</td>
            <td className="py-1.5 font-medium text-slate-800">{formatUsd(row.subtotal_usd)}</td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}

export default function ExposureAvoidedCard() {
  const [risk, setRisk] = useState<FinancialRiskResponse | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [showAssumptions, setShowAssumptions] = useState(false);

  useEffect(() => {
    let cancelled = false;

    getFinancialRisk()
      .then((data) => {
        if (!cancelled) setRisk(data);
      })
      .catch((err) => {
        if (!cancelled) setError(err instanceof Error ? err.message : "Failed to load financial risk.");
      });

    return () => {
      cancelled = true;
    };
  }, []);

  if (error) {
    return (
      <div className="rounded-xl border border-red-300 bg-red-50 p-5 text-sm text-red-700 shadow-sm">
        {error}
      </div>
    );
  }

  if (!risk) {
    return (
      <div className="rounded-xl border border-slate-200 bg-white p-5 text-sm text-slate-500 shadow-sm">
        Loading financial risk…
      </div>
    );
  }

  return (
    <div className="rounded-xl border border-slate-200 bg-white shadow-sm">
      <div className="border-b border-slate-200 bg-slate-900 px-6 py-4">
        <div className="flex flex-wrap items-baseline justify-between gap-2">
          <div>
            <h3 className="text-base font-semibold text-white">Estimated Exposure Avoided This Quarter</h3>
            <p className="text-xs text-slate-300">
              {new Date(risk.period_start).toLocaleDateString()} –{" "}
              {new Date(risk.period_end).toLocaleDateString()}
            </p>
          </div>
          <button
            onClick={() => setShowAssumptions((v) => !v)}
            className="text-xs font-medium text-indigo-300 hover:text-indigo-200"
          >
            {showAssumptions ? "Hide assumptions" : "View assumptions"}
          </button>
        </div>
      </div>

      <div className="grid grid-cols-1 gap-6 p-6 lg:grid-cols-2">
        <div>
          <p className="text-sm font-medium text-slate-500">Exposure avoided</p>
          <p className="mt-1 text-3xl font-bold text-emerald-600">
            {formatUsd(risk.exposure_avoided.total_usd)}
          </p>
          <div className="mt-3">
            <BreakdownTable rows={risk.exposure_avoided.by_attack_type} />
          </div>
        </div>

        <div>
          <p className="text-sm font-medium text-slate-500">Residual risk</p>
          <p className="mt-1 text-3xl font-bold text-red-600">{formatUsd(risk.residual_risk.total_usd)}</p>
          <p className="mt-1 text-xs text-slate-500">
            {risk.residual_risk.false_negative_count} analyst-confirmed miss
            {risk.residual_risk.false_negative_count === 1 ? "" : "es"} this period.
          </p>
          <div className="mt-3">
            <BreakdownTable rows={risk.residual_risk.by_attack_type} />
          </div>
          <p className="mt-3 text-xs text-slate-400">{risk.residual_risk.note}</p>
        </div>
      </div>

      {showAssumptions && (
        <div className="border-t border-slate-200 bg-slate-50 px-6 py-4">
          <p className="text-xs font-medium uppercase tracking-wide text-slate-500">
            Assumptions used for this calculation
          </p>
          <table className="mt-2 w-full text-left text-sm">
            <thead className="text-xs uppercase tracking-wide text-slate-500">
              <tr>
                <th className="py-1.5 pr-3 font-medium">Assumption</th>
                <th className="py-1.5 pr-3 font-medium">Value</th>
                <th className="py-1.5 font-medium">Source</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-200">
              {Object.entries(risk.assumptions).map(([key, assumption]) => (
                <tr key={key}>
                  <td className="py-1.5 pr-3 font-mono text-xs text-slate-700">{key}</td>
                  <td className="py-1.5 pr-3 text-slate-700">{assumption.value}</td>
                  <td className="py-1.5 text-xs text-slate-500">{assumption.source}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}
