import { useState } from "react";
import type { CopilotQueryResponse } from "../../types/analysis";

interface CopilotMessageProps {
  question: string;
  response: CopilotQueryResponse | null;
  error: string | null;
}

export default function CopilotMessage({ question, response, error }: CopilotMessageProps) {
  const [showData, setShowData] = useState(false);

  return (
    <div className="flex flex-col gap-2">
      <div className="max-w-xl self-end rounded-lg bg-indigo-600 px-4 py-2 text-sm text-white shadow-sm">
        {question}
      </div>

      <div className="max-w-2xl rounded-lg border border-slate-200 bg-white p-4 shadow-sm">
        {error && <p className="text-sm text-red-700">{error}</p>}
        {!error && !response && <p className="text-sm text-slate-500">Thinking…</p>}
        {response && (
          <>
            <p className="text-sm text-slate-800">{response.narrative}</p>
            <button
              onClick={() => setShowData((value) => !value)}
              className="mt-2 text-xs font-medium text-indigo-600 hover:text-indigo-500"
            >
              {showData ? "Hide data" : "Show data"}
            </button>
            {showData && (
              <div className="mt-2 rounded-lg border border-slate-200 bg-slate-50 p-3">
                <p className="text-xs font-medium uppercase tracking-wide text-slate-500">
                  Query used
                </p>
                <p className="mt-1 break-all font-mono text-xs text-slate-700">
                  {response.template_used.template}({JSON.stringify(response.template_used.params)})
                </p>
                <p className="mt-3 text-xs font-medium uppercase tracking-wide text-slate-500">
                  Retrieved figures
                </p>
                <pre className="mt-1 overflow-x-auto whitespace-pre-wrap break-words text-xs text-slate-700">
                  {JSON.stringify(response.result, null, 2)}
                </pre>
              </div>
            )}
          </>
        )}
      </div>
    </div>
  );
}
