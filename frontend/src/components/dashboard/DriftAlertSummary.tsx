import { useEffect, useState } from "react";
import { getMonitoringDrift } from "../../api/client";
import type { DriftAlert, DriftAlertSeverity } from "../../types/analysis";

const SEVERITY_STYLES: Record<DriftAlertSeverity, string> = {
  medium: "bg-amber-100 text-amber-800 border-amber-300",
  high: "bg-orange-100 text-orange-800 border-orange-300",
  critical: "bg-red-100 text-red-800 border-red-300",
};

export default function DriftAlertSummary() {
  const [alerts, setAlerts] = useState<DriftAlert[]>([]);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;

    getMonitoringDrift()
      .then((data) => {
        if (cancelled) return;
        setAlerts(data.items);
      })
      .catch((err) => {
        if (!cancelled) setError(err instanceof Error ? err.message : "Failed to load drift alerts.");
      });

    return () => {
      cancelled = true;
    };
  }, []);

  const topAlerts = alerts.slice(0, 5);

  return (
    <div className="overflow-hidden rounded-xl border border-slate-200 bg-white shadow-sm">
      <div className="border-b border-slate-200 bg-slate-900 px-6 py-3">
        <h3 className="text-base font-semibold text-white">Control Drift</h3>
        <p className="text-xs text-slate-300">Top active drift alerts across all frameworks.</p>
      </div>
      {error && <div className="p-4 text-sm text-red-700">{error}</div>}
      <ul className="divide-y divide-slate-100">
        {topAlerts.map((alert, i) => (
          <li
            key={`${alert.framework_key}-${alert.control_id}-${alert.type}-${i}`}
            className="flex items-center justify-between gap-3 px-6 py-3"
          >
            <span className="truncate text-sm text-slate-700">
              {alert.control_id ? `${alert.control_id} — ${alert.control_name}` : alert.control_name}
            </span>
            <span
              className={`shrink-0 rounded-full border px-2.5 py-0.5 text-xs font-medium uppercase tracking-wide ${SEVERITY_STYLES[alert.severity]}`}
            >
              {alert.severity}
            </span>
          </li>
        ))}
        {topAlerts.length === 0 && !error && (
          <li className="px-6 py-8 text-center text-sm text-slate-500">No active drift alerts.</li>
        )}
      </ul>
    </div>
  );
}
