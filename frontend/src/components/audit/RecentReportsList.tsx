import { useEffect, useState } from "react";
import { downloadAuditReport, listAuditReports } from "../../api/client";
import type { AuditReportSummary } from "../../types/analysis";

interface RecentReportsListProps {
  refreshToken: number;
}

export default function RecentReportsList({ refreshToken }: RecentReportsListProps) {
  const [reports, setReports] = useState<AuditReportSummary[]>([]);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;

    listAuditReports({ pageSize: 10 })
      .then((data) => {
        if (!cancelled) setReports(data.items);
      })
      .catch((err) => {
        if (!cancelled) setError(err instanceof Error ? err.message : "Failed to load reports.");
      });

    return () => {
      cancelled = true;
    };
  }, [refreshToken]);

  return (
    <div className="overflow-hidden rounded-xl border border-slate-200 bg-white shadow-sm">
      <div className="border-b border-slate-200 bg-slate-900 px-6 py-3">
        <h3 className="text-base font-semibold text-white">Recent Evidence Packs</h3>
      </div>
      {error && <div className="p-4 text-sm text-red-700">{error}</div>}
      <table className="w-full text-left text-sm">
        <thead className="border-b border-slate-200 bg-slate-50 text-xs uppercase tracking-wide text-slate-500">
          <tr>
            <th className="px-6 py-3 font-medium">Generated</th>
            <th className="px-6 py-3 font-medium">Framework</th>
            <th className="px-6 py-3 font-medium">Period</th>
            <th className="px-6 py-3 font-medium">Coverage</th>
            <th className="px-6 py-3 font-medium">Download</th>
          </tr>
        </thead>
        <tbody className="divide-y divide-slate-100">
          {reports.map((report) => (
            <tr key={report.id}>
              <td className="px-6 py-3 text-slate-600">{new Date(report.created_at).toLocaleString()}</td>
              <td className="px-6 py-3 text-slate-800">{report.framework_name}</td>
              <td className="px-6 py-3 text-slate-600">
                {new Date(report.period_start).toLocaleDateString()} –{" "}
                {new Date(report.period_end).toLocaleDateString()}
              </td>
              <td className="px-6 py-3 text-slate-600">
                {report.operating_controls}/{report.total_controls} controls
              </td>
              <td className="px-6 py-3">
                <div className="flex gap-3">
                  <button
                    onClick={() => downloadAuditReport(report.id, "pdf")}
                    className="font-medium text-indigo-600 hover:text-indigo-500"
                  >
                    PDF
                  </button>
                  <button
                    onClick={() => downloadAuditReport(report.id, "json")}
                    className="font-medium text-indigo-600 hover:text-indigo-500"
                  >
                    JSON
                  </button>
                </div>
              </td>
            </tr>
          ))}
          {reports.length === 0 && (
            <tr>
              <td colSpan={5} className="px-6 py-8 text-center text-slate-500">
                No evidence packs generated yet.
              </td>
            </tr>
          )}
        </tbody>
      </table>
    </div>
  );
}
