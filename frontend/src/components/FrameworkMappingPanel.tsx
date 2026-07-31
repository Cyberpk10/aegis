import { useState } from "react";
import type { FrameworkControlRef } from "../types/analysis";

const FRAMEWORK_LABELS: Record<string, string> = {
  mitre_attack: "MITRE ATT&CK",
  nist_csf: "NIST CSF",
  iso_27001: "ISO 27001",
  soc2: "SOC 2",
};

interface FrameworkMappingPanelProps {
  frameworkMappings: Record<string, FrameworkControlRef[]>;
}

export default function FrameworkMappingPanel({ frameworkMappings }: FrameworkMappingPanelProps) {
  const frameworkKeys = Object.keys(frameworkMappings);
  const [activeKey, setActiveKey] = useState(frameworkKeys[0] ?? "");

  if (frameworkKeys.length === 0) {
    return null;
  }

  const activeRefs = frameworkMappings[activeKey] ?? [];
  const dedupedControls = Array.from(
    new Map(activeRefs.map((ref) => [ref.control_id, ref])).values()
  );

  return (
    <div className="rounded-lg border border-slate-200 bg-white shadow-sm">
      <div className="flex border-b border-slate-200">
        {frameworkKeys.map((key) => (
          <button
            key={key}
            onClick={() => setActiveKey(key)}
            className={`flex-1 px-3 py-2 text-sm font-medium transition ${
              key === activeKey
                ? "border-b-2 border-indigo-600 text-indigo-700"
                : "text-slate-500 hover:text-slate-700"
            }`}
          >
            {FRAMEWORK_LABELS[key] ?? key}
          </button>
        ))}
      </div>
      <div className="p-4">
        {dedupedControls.length === 0 ? (
          <p className="text-sm text-slate-500">No controls mapped for this framework.</p>
        ) : (
          <ul className="flex flex-col gap-2">
            {dedupedControls.map((control) => (
              <li key={control.control_id} className="text-sm">
                <span className="font-mono font-semibold text-slate-700">{control.control_id}</span>
                <span className="text-slate-600"> — {control.control_name}</span>
              </li>
            ))}
          </ul>
        )}
      </div>
    </div>
  );
}
