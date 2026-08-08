import type { ActivityEvent } from "../../types/analysis";

interface EvidenceEventsTableProps {
  events: ActivityEvent[];
}

export default function EvidenceEventsTable({ events }: EvidenceEventsTableProps) {
  if (events.length === 0) {
    return (
      <p className="rounded-lg border border-slate-200 bg-slate-50 p-4 text-sm text-slate-500">
        No evidence events recorded.
      </p>
    );
  }

  return (
    <div className="overflow-x-auto rounded-xl border border-slate-200 bg-white shadow-sm">
      <table className="w-full text-left text-sm">
        <thead className="border-b border-slate-200 bg-slate-50 text-xs uppercase tracking-wide text-slate-500">
          <tr>
            <th className="px-4 py-3 font-medium">Time</th>
            <th className="px-4 py-3 font-medium">Action</th>
            <th className="px-4 py-3 font-medium">Source IP</th>
            <th className="px-4 py-3 font-medium">Target</th>
            <th className="px-4 py-3 font-medium">Bytes</th>
            <th className="px-4 py-3 font-medium">Outcome</th>
          </tr>
        </thead>
        <tbody className="divide-y divide-slate-100">
          {events.map((event) => (
            <tr key={event.id ?? event.timestamp}>
              <td className="px-4 py-3 text-slate-500">
                {new Date(event.timestamp).toLocaleString()}
              </td>
              <td className="px-4 py-3 text-slate-700">{event.action}</td>
              <td className="px-4 py-3 text-slate-600">{event.source_ip ?? "—"}</td>
              <td className="px-4 py-3 text-slate-600">{event.target ?? "—"}</td>
              <td className="px-4 py-3 text-slate-600">
                {event.bytes !== null ? event.bytes.toLocaleString() : "—"}
              </td>
              <td className="px-4 py-3 text-slate-600">{event.outcome ?? "—"}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
