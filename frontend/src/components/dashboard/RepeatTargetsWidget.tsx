import { useEffect, useState } from "react";
import { getTargets } from "../../api/client";
import type { TargetSummary } from "../../types/analysis";

export default function RepeatTargetsWidget() {
  const [targets, setTargets] = useState<TargetSummary[]>([]);
  const [threshold, setThreshold] = useState<number | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;

    getTargets()
      .then((data) => {
        if (cancelled) return;
        setTargets(data.targets);
        setThreshold(data.threshold);
      })
      .catch((err) => {
        if (!cancelled) setError(err instanceof Error ? err.message : "Failed to load targets.");
      });

    return () => {
      cancelled = true;
    };
  }, []);

  const topTargets = targets.slice(0, 10);

  return (
    <div className="overflow-hidden rounded-xl border border-slate-200 bg-white shadow-sm">
      <div className="border-b border-slate-200 bg-slate-900 px-6 py-3">
        <h3 className="text-base font-semibold text-white">Repeat Targets</h3>
        {threshold !== null && (
          <p className="text-xs text-slate-300">
            Flagged for micro-training at {threshold}+ flagged attempts.
          </p>
        )}
      </div>
      {error && <div className="p-4 text-sm text-red-700">{error}</div>}
      <table className="w-full text-left text-sm">
        <thead className="border-b border-slate-200 bg-slate-50 text-xs uppercase tracking-wide text-slate-500">
          <tr>
            <th className="px-6 py-3 font-medium">Recipient</th>
            <th className="px-6 py-3 font-medium">Hits</th>
            <th className="px-6 py-3 font-medium">Status</th>
            <th className="px-6 py-3 font-medium">Training Recommendation</th>
          </tr>
        </thead>
        <tbody className="divide-y divide-slate-100">
          {topTargets.map((target) => (
            <tr key={target.recipient}>
              <td className="px-6 py-3 text-slate-800">{target.recipient}</td>
              <td className="px-6 py-3 text-slate-600">{target.hit_count}</td>
              <td className="px-6 py-3">
                {target.flagged_for_training ? (
                  <span className="rounded-full border border-red-300 bg-red-100 px-2.5 py-0.5 text-xs font-medium text-red-800">
                    Flagged
                  </span>
                ) : (
                  <span className="rounded-full border border-slate-300 bg-slate-100 px-2.5 py-0.5 text-xs font-medium text-slate-600">
                    Below threshold
                  </span>
                )}
              </td>
              <td className="px-6 py-3 text-slate-600">{target.recommendation ?? "—"}</td>
            </tr>
          ))}
          {topTargets.length === 0 && (
            <tr>
              <td colSpan={4} className="px-6 py-8 text-center text-slate-500">
                No repeat targets yet.
              </td>
            </tr>
          )}
        </tbody>
      </table>
    </div>
  );
}
