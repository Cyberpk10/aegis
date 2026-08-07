import { useEffect, useState } from "react";
import { deleteCase, getCase } from "../api/client";
import type { CaseDetail as CaseDetailType } from "../types/analysis";
import AIAnalystSummary from "./AIAnalystSummary";
import FrameworkMappingPanel from "./FrameworkMappingPanel";
import IndicatorList from "./IndicatorList";
import VerdictBadge from "./VerdictBadge";

interface CaseDetailProps {
  caseId: string;
  onBack: () => void;
  onDeleted: () => void;
}

export default function CaseDetail({ caseId, onBack, onDeleted }: CaseDetailProps) {
  const [caseData, setCaseData] = useState<CaseDetailType | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [isDeleting, setIsDeleting] = useState(false);

  useEffect(() => {
    let cancelled = false;
    setCaseData(null);
    setError(null);

    getCase(caseId)
      .then((data) => {
        if (!cancelled) setCaseData(data);
      })
      .catch((err) => {
        if (!cancelled) setError(err instanceof Error ? err.message : "Failed to load case.");
      });

    return () => {
      cancelled = true;
    };
  }, [caseId]);

  const handleDelete = async () => {
    if (!window.confirm("Delete this case? This also removes the stored raw email.")) return;
    setIsDeleting(true);
    try {
      await deleteCase(caseId);
      onDeleted();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to delete case.");
      setIsDeleting(false);
    }
  };

  return (
    <div className="flex flex-col gap-6">
      <button
        onClick={onBack}
        className="self-start text-sm font-medium text-indigo-600 hover:text-indigo-500"
      >
        ← Back to cases
      </button>

      {error && (
        <div className="rounded-lg border border-red-300 bg-red-50 p-4 text-sm text-red-700">
          {error}
        </div>
      )}

      {!caseData && !error && <p className="text-sm text-slate-500">Loading case…</p>}

      {caseData && (
        <>
          <section className="rounded-xl border border-slate-200 bg-white p-6 shadow-sm">
            <div className="flex flex-wrap items-start justify-between gap-4">
              <VerdictBadge verdict={caseData.verdict} score={caseData.score} />
              <button
                onClick={handleDelete}
                disabled={isDeleting}
                className="rounded-lg border border-red-300 px-3 py-1.5 text-sm font-medium text-red-700 hover:bg-red-50 disabled:cursor-not-allowed disabled:opacity-50"
              >
                {isDeleting ? "Deleting…" : "Delete case"}
              </button>
            </div>
            <dl className="mt-4 grid grid-cols-1 gap-x-6 gap-y-1 text-sm text-slate-600 sm:grid-cols-2">
              <div>
                <dt className="inline font-medium text-slate-700">Sender: </dt>
                <dd className="inline">{caseData.from_addr ?? "—"}</dd>
              </div>
              <div>
                <dt className="inline font-medium text-slate-700">Subject: </dt>
                <dd className="inline">{caseData.subject ?? "—"}</dd>
              </div>
              <div>
                <dt className="inline font-medium text-slate-700">Filename: </dt>
                <dd className="inline">{caseData.filename}</dd>
              </div>
              <div>
                <dt className="inline font-medium text-slate-700">Analyzed: </dt>
                <dd className="inline">{new Date(caseData.created_at).toLocaleString()}</dd>
              </div>
            </dl>
          </section>

          <AIAnalystSummary narrative={caseData.analyst_narrative} model={caseData.analyst_model} />

          <section>
            <h2 className="mb-3 text-lg font-semibold text-slate-800">Indicators</h2>
            <IndicatorList indicators={caseData.indicators} />
          </section>

          <section>
            <h2 className="mb-3 text-lg font-semibold text-slate-800">Framework Mapping</h2>
            <FrameworkMappingPanel frameworkMappings={caseData.framework_mappings} />
          </section>
        </>
      )}
    </div>
  );
}
