import { useEffect, useState } from "react";
import { getIncidents } from "../../api/client";
import type { IncidentSummary, Verdict } from "../../types/analysis";
import VerdictBadge from "../VerdictBadge";

const PAGE_SIZE = 20;

const VERDICT_OPTIONS: { label: string; value: Verdict | "" }[] = [
  { label: "All verdicts", value: "" },
  { label: "Suspicious", value: "suspicious" },
  { label: "Malicious", value: "malicious" },
];

interface IncidentsTableProps {
  onSelectIncident: (id: string) => void;
  refreshToken: number;
}

export default function IncidentsTable({ onSelectIncident, refreshToken }: IncidentsTableProps) {
  const [items, setItems] = useState<IncidentSummary[]>([]);
  const [total, setTotal] = useState(0);
  const [page, setPage] = useState(1);
  const [verdict, setVerdict] = useState<Verdict | "">("");
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;
    setIsLoading(true);
    setError(null);

    getIncidents({ page, pageSize: PAGE_SIZE, verdict })
      .then((response) => {
        if (cancelled) return;
        setItems(response.items);
        setTotal(response.total);
      })
      .catch((err) => {
        if (cancelled) return;
        setError(err instanceof Error ? err.message : "Failed to load incidents.");
      })
      .finally(() => {
        if (cancelled) return;
        setIsLoading(false);
      });

    return () => {
      cancelled = true;
    };
  }, [page, verdict, refreshToken]);

  const totalPages = Math.max(1, Math.ceil(total / PAGE_SIZE));

  return (
    <div className="flex flex-col gap-4">
      <div className="flex flex-wrap items-end gap-4">
        <label className="flex flex-col gap-1 text-sm text-slate-600">
          Verdict
          <select
            value={verdict}
            onChange={(event) => {
              setPage(1);
              setVerdict(event.target.value as Verdict | "");
            }}
            className="rounded-lg border border-slate-300 bg-white px-3 py-1.5 text-sm text-slate-700"
          >
            {VERDICT_OPTIONS.map((option) => (
              <option key={option.value} value={option.value}>
                {option.label}
              </option>
            ))}
          </select>
        </label>
      </div>

      {error && (
        <div className="rounded-lg border border-red-300 bg-red-50 p-4 text-sm text-red-700">
          {error}
        </div>
      )}

      <div className="overflow-hidden rounded-xl border border-slate-200 bg-white shadow-sm">
        <table className="w-full text-left text-sm">
          <thead className="border-b border-slate-200 bg-slate-50 text-xs uppercase tracking-wide text-slate-500">
            <tr>
              <th className="px-4 py-3 font-medium">Risk</th>
              <th className="px-4 py-3 font-medium">Actor</th>
              <th className="px-4 py-3 font-medium">Detection Types</th>
              <th className="px-4 py-3 font-medium">Time</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-slate-100">
            {items.map((item) => (
              <tr
                key={item.id}
                onClick={() => onSelectIncident(item.id)}
                className="cursor-pointer transition hover:bg-slate-50"
              >
                <td className="px-4 py-3">
                  <VerdictBadge verdict={item.verdict} score={item.score} />
                </td>
                <td className="px-4 py-3 text-slate-600">{item.actor}</td>
                <td className="px-4 py-3">
                  <div className="flex flex-wrap gap-1">
                    {item.detection_types.map((type) => (
                      <span
                        key={type}
                        className="rounded border border-slate-200 bg-slate-50 px-1.5 py-0.5 text-xs text-slate-600"
                      >
                        {type}
                      </span>
                    ))}
                  </div>
                </td>
                <td className="px-4 py-3 text-slate-500">
                  {new Date(item.created_at).toLocaleString()}
                </td>
              </tr>
            ))}
            {!isLoading && items.length === 0 && (
              <tr>
                <td colSpan={4} className="px-4 py-8 text-center text-slate-500">
                  No incidents match these filters.
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>

      <div className="flex items-center justify-between text-sm text-slate-600">
        <span>
          {total} incident{total === 1 ? "" : "s"}
        </span>
        <div className="flex items-center gap-3">
          <button
            onClick={() => setPage((p) => Math.max(1, p - 1))}
            disabled={page <= 1 || isLoading}
            className="rounded-lg border border-slate-300 px-3 py-1.5 disabled:cursor-not-allowed disabled:opacity-50"
          >
            Previous
          </button>
          <span>
            Page {page} of {totalPages}
          </span>
          <button
            onClick={() => setPage((p) => Math.min(totalPages, p + 1))}
            disabled={page >= totalPages || isLoading}
            className="rounded-lg border border-slate-300 px-3 py-1.5 disabled:cursor-not-allowed disabled:opacity-50"
          >
            Next
          </button>
        </div>
      </div>
    </div>
  );
}
