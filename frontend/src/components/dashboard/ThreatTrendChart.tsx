import { Bar, BarChart, CartesianGrid, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";
import type { MonthlyThreatCount } from "../../types/analysis";

function toQuarterly(monthly: MonthlyThreatCount[]): { quarter: string; count: number }[] {
  const buckets = new Map<string, number>();
  for (const { month, count } of monthly) {
    const [year, monthNum] = month.split("-");
    const quarter = Math.ceil(Number(monthNum) / 3);
    const key = `${year} Q${quarter}`;
    buckets.set(key, (buckets.get(key) ?? 0) + count);
  }
  return Array.from(buckets.entries())
    .sort(([a], [b]) => a.localeCompare(b))
    .map(([quarter, count]) => ({ quarter, count }));
}

interface ThreatTrendChartProps {
  monthlyTrend: MonthlyThreatCount[];
}

export default function ThreatTrendChart({ monthlyTrend }: ThreatTrendChartProps) {
  const data = toQuarterly(monthlyTrend);

  return (
    <div className="rounded-xl border border-slate-200 bg-white p-6 shadow-sm">
      <h3 className="text-base font-semibold text-slate-900">Quarterly Threat Trend</h3>
      <p className="text-xs text-slate-500">Suspicious + malicious cases, bucketed by quarter.</p>
      {data.length === 0 ? (
        <p className="mt-4 text-sm text-slate-500">No threats in this period.</p>
      ) : (
        <ResponsiveContainer width="100%" height={260}>
          <BarChart data={data} margin={{ top: 16, right: 8, left: 0, bottom: 0 }}>
            <CartesianGrid strokeDasharray="3 3" stroke="#e2e8f0" vertical={false} />
            <XAxis
              dataKey="quarter"
              tick={{ fontSize: 12, fill: "#64748b" }}
              axisLine={{ stroke: "#cbd5e1" }}
              tickLine={false}
            />
            <YAxis allowDecimals={false} tick={{ fontSize: 12, fill: "#64748b" }} axisLine={false} tickLine={false} />
            <Tooltip cursor={{ fill: "#f1f5f9" }} />
            <Bar dataKey="count" fill="#334155" radius={[4, 4, 0, 0]} />
          </BarChart>
        </ResponsiveContainer>
      )}
    </div>
  );
}
