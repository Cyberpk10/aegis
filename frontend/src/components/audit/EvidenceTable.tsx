import type { AuditControlEvidence } from "../../types/analysis";

interface EvidenceTableProps {
  controls: AuditControlEvidence[];
}

export default function EvidenceTable({ controls }: EvidenceTableProps) {
  return (
    <div className="overflow-hidden rounded-xl border border-slate-200 bg-white shadow-sm">
      <div className="border-b border-slate-200 bg-slate-900 px-6 py-3">
        <h3 className="text-base font-semibold text-white">Per-Control Evidence</h3>
      </div>
      <div className="overflow-x-auto">
        <table className="w-full text-left text-sm">
          <thead className="border-b border-slate-200 bg-slate-50 text-xs uppercase tracking-wide text-slate-500">
            <tr>
              <th className="px-6 py-3 font-medium">Control</th>
              <th className="px-6 py-3 font-medium">Name</th>
              <th className="px-6 py-3 font-medium">Detections</th>
              <th className="px-6 py-3 font-medium">Status</th>
              <th className="px-6 py-3 font-medium">Sample Cases</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-slate-100">
            {controls.map((control) => (
              <tr key={control.control_id}>
                <td className="px-6 py-3 font-mono text-xs text-slate-700">{control.control_id}</td>
                <td className="px-6 py-3 text-slate-800">{control.control_name}</td>
                <td className="px-6 py-3 text-slate-600">{control.detection_count}</td>
                <td className="px-6 py-3">
                  <span
                    className={`rounded-full border px-2.5 py-0.5 text-xs font-medium ${
                      control.operating
                        ? "border-emerald-300 bg-emerald-100 text-emerald-800"
                        : "border-slate-300 bg-slate-100 text-slate-600"
                    }`}
                  >
                    {control.operating ? "Operating" : "No evidence"}
                  </span>
                </td>
                <td className="px-6 py-3">
                  <div className="flex flex-wrap gap-1">
                    {control.sample_cases.length === 0 && (
                      <span className="text-xs text-slate-400">—</span>
                    )}
                    {control.sample_cases.map((sample) => (
                      <span
                        key={sample.id}
                        title={new Date(sample.created_at).toLocaleString()}
                        className="rounded border border-slate-200 bg-slate-50 px-1.5 py-0.5 text-xs text-slate-600"
                      >
                        {sample.id.slice(0, 8)} · {sample.verdict}
                      </span>
                    ))}
                  </div>
                </td>
              </tr>
            ))}
            {controls.length === 0 && (
              <tr>
                <td colSpan={5} className="px-6 py-8 text-center text-slate-500">
                  No controls found for this framework.
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}
