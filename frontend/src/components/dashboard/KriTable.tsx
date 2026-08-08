import type { KRIs } from "../../types/analysis";

function formatPct(value: number | null): string {
  return value === null ? "—" : `${value}%`;
}

interface KriTableProps {
  kris: KRIs;
}

export default function KriTable({ kris }: KriTableProps) {
  const rows = [
    {
      label: "Malicious Catch Rate",
      value: formatPct(kris.malicious_catch_rate_pct),
      note: `of ${kris.labeled_count} labeled case${kris.labeled_count === 1 ? "" : "s"}`,
    },
    {
      label: "False Positive Rate",
      value: formatPct(kris.false_positive_rate_pct),
      note: `of ${kris.labeled_count} labeled case${kris.labeled_count === 1 ? "" : "s"}`,
    },
    {
      label: "Mean Unlabeled Backlog",
      value:
        kris.mean_unlabeled_backlog_days === null ? "—" : `${kris.mean_unlabeled_backlog_days} days`,
      note: `${kris.unlabeled_count} unlabeled case${kris.unlabeled_count === 1 ? "" : "s"}`,
    },
  ];

  return (
    <div className="overflow-hidden rounded-xl border border-slate-200 bg-white shadow-sm">
      <div className="border-b border-slate-200 bg-slate-900 px-6 py-3">
        <h3 className="text-base font-semibold text-white">Key Risk Indicators</h3>
      </div>
      <table className="w-full text-left text-sm">
        <tbody className="divide-y divide-slate-100">
          {rows.map((row) => (
            <tr key={row.label}>
              <td className="px-6 py-3 font-medium text-slate-700">{row.label}</td>
              <td className="px-6 py-3 text-xl font-bold text-slate-900">{row.value}</td>
              <td className="px-6 py-3 text-xs text-slate-500">{row.note}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
