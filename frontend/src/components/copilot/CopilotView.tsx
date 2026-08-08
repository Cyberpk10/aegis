import { useState } from "react";
import { queryCopilot } from "../../api/client";
import type { CopilotQueryResponse } from "../../types/analysis";
import CopilotMessage from "./CopilotMessage";

interface ChatTurn {
  question: string;
  response: CopilotQueryResponse | null;
  error: string | null;
}

export default function CopilotView() {
  const [question, setQuestion] = useState("");
  const [turns, setTurns] = useState<ChatTurn[]>([]);
  const [isLoading, setIsLoading] = useState(false);

  const handleSubmit = async (event: React.FormEvent) => {
    event.preventDefault();
    const trimmed = question.trim();
    if (!trimmed || isLoading) return;

    setIsLoading(true);
    setQuestion("");
    const turnIndex = turns.length;
    setTurns((prev) => [...prev, { question: trimmed, response: null, error: null }]);

    try {
      const response = await queryCopilot(trimmed);
      setTurns((prev) => prev.map((t, i) => (i === turnIndex ? { ...t, response } : t)));
    } catch (err) {
      const message = err instanceof Error ? err.message : "Failed to get an answer.";
      setTurns((prev) => prev.map((t, i) => (i === turnIndex ? { ...t, error: message } : t)));
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <div className="flex flex-col gap-6">
      <div className="rounded-xl border border-slate-800 bg-slate-900 p-5 shadow-sm">
        <h2 className="text-lg font-semibold text-white">Threat Copilot</h2>
        <p className="text-sm text-slate-300">
          Ask questions about your Aegis data in plain English. Every answer is grounded in a
          whitelisted, parameterized query — never free-form SQL — and the underlying figures are
          shown alongside the narrative.
        </p>
      </div>

      <div className="flex flex-col gap-4">
        {turns.length === 0 && (
          <p className="rounded-lg border border-slate-200 bg-white p-4 text-sm text-slate-500">
            Try asking things like &quot;how many malicious emails this month,&quot; &quot;how
            often was alice@example.com targeted,&quot; or &quot;what&apos;s our MITRE
            coverage.&quot;
          </p>
        )}
        {turns.map((turn, index) => (
          <CopilotMessage
            key={index}
            question={turn.question}
            response={turn.response}
            error={turn.error}
          />
        ))}
      </div>

      <form onSubmit={handleSubmit} className="flex gap-3">
        <input
          type="text"
          value={question}
          onChange={(event) => setQuestion(event.target.value)}
          placeholder="Ask a question about your Aegis data…"
          className="flex-1 rounded-lg border border-slate-300 bg-white px-3 py-2 text-sm text-slate-700"
        />
        <button
          type="submit"
          disabled={isLoading || !question.trim()}
          className="whitespace-nowrap rounded-lg bg-indigo-600 px-5 py-2 text-sm font-semibold text-white shadow-sm transition hover:bg-indigo-500 disabled:cursor-not-allowed disabled:bg-slate-300"
        >
          {isLoading ? "Asking…" : "Ask"}
        </button>
      </form>
    </div>
  );
}
