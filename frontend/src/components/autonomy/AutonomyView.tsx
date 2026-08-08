import { useState } from "react";
import ActionsLog from "./ActionsLog";
import AutonomySettings from "./AutonomySettings";

type SubTab = "policy" | "log";

export default function AutonomyView() {
  const [subTab, setSubTab] = useState<SubTab>("policy");

  return (
    <div className="flex flex-col gap-6">
      <nav className="flex gap-1 border-b border-slate-200">
        {(["policy", "log"] as const).map((t) => (
          <button
            key={t}
            onClick={() => setSubTab(t)}
            className={`px-4 py-2 text-sm font-medium transition ${
              subTab === t
                ? "border-b-2 border-indigo-600 text-indigo-700"
                : "text-slate-500 hover:text-slate-700"
            }`}
          >
            {t === "policy" ? "Policy" : "Actions log"}
          </button>
        ))}
      </nav>

      {subTab === "policy" && <AutonomySettings />}
      {subTab === "log" && <ActionsLog />}
    </div>
  );
}
