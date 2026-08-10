import { useEffect, useState } from "react";
import { getMonitoringControls } from "../../api/client";
import type { ControlHealth, ControlHealthStatus } from "../../types/analysis";

const STATUS_STYLES: Record<ControlHealthStatus, string> = {
  operating: "border-emerald-300 bg-emerald-50 text-emerald-800",
  degraded: "border-amber-300 bg-amber-50 text-amber-800",
  stale: "border-red-300 bg-red-50 text-red-800",
  no_evidence: "border-slate-200 bg-slate-50 text-slate-500",
};

const STATUS_LABELS: Record<ControlHealthStatus, string> = {
  operating: "Operating",
  degraded: "Degraded",
  stale: "Stale",
  no_evidence: "No evidence",
};

const FRAMEWORKS = [
  { value: "", label: "All frameworks" },
  { value: "mitre_attack", label: "MITRE ATT&CK" },
  { value: "nist_csf", label: "NIST CSF" },
  { value: "iso_27001", label: "ISO 27001" },
  { value: "soc2", label: "SOC 2" },
];

function formatLastEvidence(value: string | null): string {
  if (!value) return "Never";
  return new Date(value).toLocaleDateString();
}

export default function ControlGrid() {
  const [items, setItems] = useState<ControlHealth[]>([]);
  const [framework, setFramework] = useState("");
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    getMonitoringControls(framework || undefined)
      .then((data) => setItems(data.items))
      .catch((err) => setError(err instanceof Error ? err.message : "Failed to load controls."));
  }, [framework]);

  return (
    <section className="rounded-xl border border-slate-200 bg-white p-6 shadow-sm">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <h2 className="text-lg font-semibold text-slate-800">Control health</h2>
        <select
          value={framework}
          onChange={(e) => setFramework(e.target.value)}
          className="rounded-lg border border-slate-300 bg-white px-3 py-1.5 text-sm"
        >
          {FRAMEWORKS.map((fw) => (
            <option key={fw.value} value={fw.value}>
              {fw.label}
            </option>
          ))}
        </select>
      </div>

      {error && (
        <div className="mt-4 rounded-lg border border-red-300 bg-red-50 p-4 text-sm text-red-700">
          {error}
        </div>
      )}

      <div className="mt-4 grid grid-cols-2 gap-3 sm:grid-cols-3 lg:grid-cols-4">
        {items.map((c) => (
          <div
            key={`${c.framework_key}-${c.control_id}`}
            className={`rounded-lg border p-3 ${STATUS_STYLES[c.status]}`}
          >
            <div className="text-xs font-semibold uppercase tracking-wide opacity-70">
              {c.framework_key}
            </div>
            <div className="mt-1 truncate text-sm font-semibold" title={c.control_name}>
              {c.control_id}
            </div>
            <div className="truncate text-xs opacity-80" title={c.control_name}>
              {c.control_name}
            </div>
            <div className="mt-2 flex items-center justify-between text-xs">
              <span className="rounded-full bg-white/60 px-2 py-0.5 font-medium">
                {STATUS_LABELS[c.status]}
              </span>
              <span className="opacity-70">{formatLastEvidence(c.last_evidence_at)}</span>
            </div>
          </div>
        ))}
        {items.length === 0 && !error && (
          <div className="col-span-full py-8 text-center text-sm text-slate-500">
            No controls loaded yet.
          </div>
        )}
      </div>
    </section>
  );
}
