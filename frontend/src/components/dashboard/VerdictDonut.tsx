import { Cell, Legend, Pie, PieChart, ResponsiveContainer, Tooltip } from "recharts";
import type { VerdictCounts } from "../../types/analysis";

// Reuses the same verdict colors as VerdictBadge.tsx (emerald/amber/red) — validated via
// the dataviz skill's palette validator (light mode: all checks pass; the contrast WARN
// against a light surface is satisfied here by always-visible legend + direct segment
// labels, not relying on fill color alone).
const COLORS: Record<string, string> = {
  Safe: "#10b981",
  Suspicious: "#f59e0b",
  Malicious: "#ef4444",
};

interface VerdictDonutProps {
  verdictCounts: VerdictCounts;
}

export default function VerdictDonut({ verdictCounts }: VerdictDonutProps) {
  const data = [
    { name: "Safe", value: verdictCounts.safe.current },
    { name: "Suspicious", value: verdictCounts.suspicious.current },
    { name: "Malicious", value: verdictCounts.malicious.current },
  ];
  const total = data.reduce((sum, d) => sum + d.value, 0);

  return (
    <div className="rounded-xl border border-slate-200 bg-white p-6 shadow-sm">
      <h3 className="text-base font-semibold text-slate-900">Verdict Distribution</h3>
      {total === 0 ? (
        <p className="mt-4 text-sm text-slate-500">No cases in this period.</p>
      ) : (
        <ResponsiveContainer width="100%" height={260}>
          <PieChart>
            <Pie
              data={data}
              dataKey="value"
              nameKey="name"
              innerRadius={60}
              outerRadius={90}
              paddingAngle={2}
              label={(entry: { name?: string; value?: number }) => `${entry.name}: ${entry.value}`}
            >
              {data.map((entry) => (
                <Cell key={entry.name} fill={COLORS[entry.name]} />
              ))}
            </Pie>
            <Tooltip />
            <Legend />
          </PieChart>
        </ResponsiveContainer>
      )}
    </div>
  );
}
