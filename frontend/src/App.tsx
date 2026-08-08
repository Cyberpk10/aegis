import { useState } from "react";
import UploadForm from "./components/UploadForm";
import VerdictBadge from "./components/VerdictBadge";
import AiAuthoredFlag from "./components/AiAuthoredFlag";
import AIAnalystSummary from "./components/AIAnalystSummary";
import IndicatorList from "./components/IndicatorList";
import FrameworkMappingPanel from "./components/FrameworkMappingPanel";
import CasesView from "./components/CasesView";
import DashboardView from "./components/dashboard/DashboardView";
import AuditView from "./components/audit/AuditView";
import CopilotView from "./components/copilot/CopilotView";
import DetectionsView from "./components/detections/DetectionsView";
import AutonomyView from "./components/autonomy/AutonomyView";
import { postAnalyze, AnalyzeError } from "./api/client";
import type { AnalyzeResponse } from "./types/analysis";

type Tab = "analyze" | "cases" | "dashboard" | "audit" | "copilot" | "detections" | "autonomy";

export default function App() {
  const [tab, setTab] = useState<Tab>("analyze");
  const [result, setResult] = useState<AnalyzeResponse | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [isLoading, setIsLoading] = useState(false);

  const handleAnalyze = async (file: File) => {
    setIsLoading(true);
    setError(null);
    setResult(null);
    try {
      const response = await postAnalyze(file);
      setResult(response);
    } catch (err) {
      setError(err instanceof AnalyzeError ? err.message : "Something went wrong while analyzing the email.");
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <div className="min-h-screen bg-slate-50">
      <div
        className={`mx-auto px-4 py-10 ${
          tab === "dashboard" ||
          tab === "audit" ||
          tab === "copilot" ||
          tab === "detections" ||
          tab === "autonomy"
            ? "max-w-6xl"
            : "max-w-3xl"
        }`}
      >
        <header className="mb-8">
          <h1 className="text-3xl font-bold text-slate-900">Aegis</h1>
          <p className="mt-1 text-slate-600">
            Upload a <code className="rounded bg-slate-200 px-1 py-0.5 text-sm">.eml</code> file for
            deterministic phishing-indicator analysis.
          </p>
          <nav className="mt-4 flex gap-1 border-b border-slate-200">
            {(["analyze", "cases", "dashboard", "detections", "audit", "copilot", "autonomy"] as const).map((t) => (
              <button
                key={t}
                onClick={() => setTab(t)}
                className={`px-4 py-2 text-sm font-medium capitalize transition ${
                  tab === t
                    ? "border-b-2 border-indigo-600 text-indigo-700"
                    : "text-slate-500 hover:text-slate-700"
                }`}
              >
                {t}
              </button>
            ))}
          </nav>
        </header>

        {tab === "cases" && <CasesView />}

        {tab === "dashboard" && <DashboardView />}

        {tab === "detections" && <DetectionsView />}

        {tab === "autonomy" && <AutonomyView />}

        {tab === "audit" && <AuditView />}

        {tab === "copilot" && <CopilotView />}

        {tab === "analyze" && (
          <>
            <section className="rounded-xl border border-slate-200 bg-white p-6 shadow-sm">
              <UploadForm onSubmit={handleAnalyze} isLoading={isLoading} />
            </section>

            {error && (
              <div className="mt-6 rounded-lg border border-red-300 bg-red-50 p-4 text-sm text-red-700">
                {error}
              </div>
            )}

            {result && (
              <div className="mt-8 flex flex-col gap-6">
                <section className="rounded-xl border border-slate-200 bg-white p-6 shadow-sm">
                  <VerdictBadge verdict={result.verdict} score={result.score} />
                  <dl className="mt-4 grid grid-cols-1 gap-x-6 gap-y-1 text-sm text-slate-600 sm:grid-cols-2">
                    <div>
                      <dt className="inline font-medium text-slate-700">From: </dt>
                      <dd className="inline">
                        {result.summary.from_display} &lt;{result.summary.from_address}&gt;
                      </dd>
                    </div>
                    <div>
                      <dt className="inline font-medium text-slate-700">Subject: </dt>
                      <dd className="inline">{result.summary.subject}</dd>
                    </div>
                    <div>
                      <dt className="inline font-medium text-slate-700">SPF/DKIM/DMARC: </dt>
                      <dd className="inline">
                        {result.summary.auth_results.spf} / {result.summary.auth_results.dkim} /{" "}
                        {result.summary.auth_results.dmarc}
                      </dd>
                    </div>
                    <div>
                      <dt className="inline font-medium text-slate-700">Links / Attachments: </dt>
                      <dd className="inline">
                        {result.summary.link_count} / {result.summary.attachment_count}
                      </dd>
                    </div>
                  </dl>
                </section>

                <AiAuthoredFlag indicators={result.indicators} />

                <AIAnalystSummary narrative={result.analyst_narrative} model={result.analyst_model} />

                <section>
                  <h2 className="mb-3 text-lg font-semibold text-slate-800">Indicators</h2>
                  <IndicatorList indicators={result.indicators} />
                </section>

                <section>
                  <h2 className="mb-3 text-lg font-semibold text-slate-800">Framework Mapping</h2>
                  <FrameworkMappingPanel frameworkMappings={result.framework_mappings} />
                </section>
              </div>
            )}
          </>
        )}
      </div>
    </div>
  );
}
