import type { Severity, TopIndicator } from "../../types/analysis";

const SEVERITY_STYLES: Record<Severity, string> = {
  low: "bg-slate-100 text-slate-700 border-slate-300",
  medium: "bg-amber-100 text-amber-800 border-amber-300",
  high: "bg-red-100 text-red-800 border-red-300",
};

interface TopIndicatorsTableProps {
  indicators: TopIndicator[];
}

export default function TopIndicatorsTable({ indicators }: TopIndicatorsTableProps) {
  return (
    <div className="overflow-hidden rounded-xl border border-slate-200 bg-white shadow-sm">
      <div className="border-b border-slate-200 bg-slate-900 px-6 py-3">
        <h3 className="text-base font-semibold text-white">Top Threat Indicators</h3>
      </div>
      <div className="overflow-x-auto">
        <table className="w-full text-left text-sm">
          <thead className="border-b border-slate-200 bg-slate-50 text-xs uppercase tracking-wide text-slate-500">
            <tr>
              <th className="px-6 py-3 font-medium">#</th>
              <th className="px-6 py-3 font-medium">Indicator</th>
              <th className="px-6 py-3 font-medium">Category</th>
              <th className="px-6 py-3 font-medium">Severity</th>
              <th className="px-6 py-3 font-medium">Count</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-slate-100">
            {indicators.map((indicator, index) => (
              <tr key={indicator.indicator_id}>
                <td className="px-6 py-3 text-slate-500">{index + 1}</td>
                <td className="px-6 py-3 font-medium text-slate-800">{indicator.title}</td>
                <td className="px-6 py-3 text-slate-600">{indicator.category}</td>
                <td className="px-6 py-3">
                  <span
                    className={`rounded-full border px-2.5 py-0.5 text-xs font-medium uppercase tracking-wide ${SEVERITY_STYLES[indicator.severity]}`}
                  >
                    {indicator.severity}
                  </span>
                </td>
                <td className="px-6 py-3 text-slate-600">{indicator.count}</td>
              </tr>
            ))}
            {indicators.length === 0 && (
              <tr>
                <td colSpan={5} className="px-6 py-8 text-center text-slate-500">
                  No indicators triggered in this period.
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}
