import type { FrameworkCoverage } from "../../types/analysis";

interface FrameworkCoveragePanelProps {
  coverage: FrameworkCoverage[];
}

export default function FrameworkCoveragePanel({ coverage }: FrameworkCoveragePanelProps) {
  return (
    <div className="overflow-hidden rounded-xl border border-slate-200 bg-white shadow-sm">
      <div className="border-b border-slate-200 bg-slate-900 px-6 py-3">
        <h3 className="text-base font-semibold text-white">Control Framework Coverage</h3>
      </div>
      <div className="grid grid-cols-1 gap-4 p-6 sm:grid-cols-2 lg:grid-cols-4">
        {coverage.map((framework) => (
          <div key={framework.framework_key} className="rounded-lg border border-slate-200 p-4">
            <p className="text-sm font-medium text-slate-700">{framework.framework_name}</p>
            <p className="mt-1 text-2xl font-bold text-slate-900">{framework.coverage_pct}%</p>
            <div className="mt-2 h-2 w-full overflow-hidden rounded-full bg-slate-200">
              <div
                className="h-full rounded-full bg-slate-700"
                style={{ width: `${Math.min(100, framework.coverage_pct)}%` }}
              />
            </div>
            <p className="mt-1 text-xs text-slate-500">
              {framework.covered_controls} / {framework.total_controls} controls
            </p>
          </div>
        ))}
      </div>
    </div>
  );
}
