import { useEffect, useState } from "react";
import {
  deleteIncident,
  getIncident,
  getIncidentRemediationPlaybook,
  submitIncidentLabel,
  submitIncidentRemediationAction,
} from "../../api/client";
import type { IncidentDetail as IncidentDetailType, Verdict } from "../../types/analysis";
import FrameworkMappingPanel from "../FrameworkMappingPanel";
import ResponsePlaybookPanel from "../ResponsePlaybookPanel";
import VerdictBadge from "../VerdictBadge";
import EvidenceEventsTable from "./EvidenceEventsTable";
import FindingList from "./FindingList";

interface IncidentDetailProps {
  incidentId: string;
  onBack: () => void;
  onDeleted: () => void;
}

export default function IncidentDetail({ incidentId, onBack, onDeleted }: IncidentDetailProps) {
  const [incident, setIncident] = useState<IncidentDetailType | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [isDeleting, setIsDeleting] = useState(false);
  const [labelVerdict, setLabelVerdict] = useState<Verdict>("safe");
  const [labelNote, setLabelNote] = useState("");
  const [isSubmittingLabel, setIsSubmittingLabel] = useState(false);
  const [labelError, setLabelError] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;
    setIncident(null);
    setError(null);

    getIncident(incidentId)
      .then((data) => {
        if (cancelled) return;
        setIncident(data);
        setLabelVerdict(data.latest_label?.analyst_verdict ?? data.verdict);
        setLabelNote(data.latest_label?.note ?? "");
      })
      .catch((err) => {
        if (!cancelled) setError(err instanceof Error ? err.message : "Failed to load incident.");
      });

    return () => {
      cancelled = true;
    };
  }, [incidentId]);

  const handleDelete = async () => {
    if (!window.confirm("Delete this incident?")) return;
    setIsDeleting(true);
    try {
      await deleteIncident(incidentId);
      onDeleted();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to delete incident.");
      setIsDeleting(false);
    }
  };

  const handleSubmitLabel = async () => {
    setIsSubmittingLabel(true);
    setLabelError(null);
    try {
      const label = await submitIncidentLabel(incidentId, {
        analyst_verdict: labelVerdict,
        note: labelNote.trim() || undefined,
      });
      setIncident((prev) => (prev ? { ...prev, latest_label: label } : prev));
    } catch (err) {
      setLabelError(err instanceof Error ? err.message : "Failed to submit label.");
    } finally {
      setIsSubmittingLabel(false);
    }
  };

  return (
    <div className="flex flex-col gap-6">
      <button
        onClick={onBack}
        className="self-start text-sm font-medium text-indigo-600 hover:text-indigo-500"
      >
        ← Back to detections
      </button>

      {error && (
        <div className="rounded-lg border border-red-300 bg-red-50 p-4 text-sm text-red-700">
          {error}
        </div>
      )}

      {!incident && !error && <p className="text-sm text-slate-500">Loading incident…</p>}

      {incident && (
        <>
          <section className="rounded-xl border border-slate-200 bg-white p-6 shadow-sm">
            <div className="flex flex-wrap items-start justify-between gap-4">
              <div className="flex flex-col gap-2">
                <VerdictBadge verdict={incident.verdict} score={incident.score} />
                {incident.latest_label && (
                  <p className="text-sm text-slate-600">
                    <span className="font-medium text-slate-700">Human label:</span>{" "}
                    <span className="capitalize">{incident.latest_label.analyst_verdict}</span>
                    {" by "}
                    {incident.latest_label.labeled_by}
                    {" · "}
                    {new Date(incident.latest_label.created_at).toLocaleString()}
                    {incident.latest_label.note && (
                      <span className="block text-slate-500">“{incident.latest_label.note}”</span>
                    )}
                  </p>
                )}
              </div>
              <button
                onClick={handleDelete}
                disabled={isDeleting}
                className="rounded-lg border border-red-300 px-3 py-1.5 text-sm font-medium text-red-700 hover:bg-red-50 disabled:cursor-not-allowed disabled:opacity-50"
              >
                {isDeleting ? "Deleting…" : "Delete incident"}
              </button>
            </div>
            <dl className="mt-4 grid grid-cols-1 gap-x-6 gap-y-1 text-sm text-slate-600 sm:grid-cols-2">
              <div>
                <dt className="inline font-medium text-slate-700">Actor: </dt>
                <dd className="inline">{incident.actor}</dd>
              </div>
              <div>
                <dt className="inline font-medium text-slate-700">Title: </dt>
                <dd className="inline">{incident.title}</dd>
              </div>
              <div>
                <dt className="inline font-medium text-slate-700">Detection window: </dt>
                <dd className="inline">
                  {new Date(incident.window_start).toLocaleString()} –{" "}
                  {new Date(incident.window_end).toLocaleString()}
                </dd>
              </div>
              <div>
                <dt className="inline font-medium text-slate-700">Detected: </dt>
                <dd className="inline">{new Date(incident.created_at).toLocaleString()}</dd>
              </div>
            </dl>
          </section>

          <section className="rounded-xl border border-slate-200 bg-white p-6 shadow-sm">
            <h2 className="text-lg font-semibold text-slate-800">Analyst Feedback</h2>
            <p className="mt-1 text-sm text-slate-500">
              Agree with the machine verdict as-is, or change it below before submitting to
              correct it. Submitting again relabels the incident — the prior label stays in
              history.
            </p>
            <div className="mt-4 flex flex-col gap-3 sm:flex-row sm:items-end">
              <label className="flex flex-col gap-1 text-sm text-slate-600">
                Verdict
                <select
                  value={labelVerdict}
                  onChange={(event) => setLabelVerdict(event.target.value as Verdict)}
                  className="rounded-lg border border-slate-300 bg-white px-3 py-1.5 text-sm text-slate-700"
                >
                  <option value="safe">Safe</option>
                  <option value="suspicious">Suspicious</option>
                  <option value="malicious">Malicious</option>
                </select>
              </label>
              <label className="flex flex-1 flex-col gap-1 text-sm text-slate-600">
                Note (optional)
                <input
                  type="text"
                  value={labelNote}
                  onChange={(event) => setLabelNote(event.target.value)}
                  placeholder="Why are you agreeing or correcting this verdict?"
                  className="rounded-lg border border-slate-300 bg-white px-3 py-1.5 text-sm text-slate-700"
                />
              </label>
              <button
                onClick={handleSubmitLabel}
                disabled={isSubmittingLabel}
                className="whitespace-nowrap rounded-lg bg-indigo-600 px-5 py-2 text-sm font-semibold text-white shadow-sm transition hover:bg-indigo-500 disabled:cursor-not-allowed disabled:bg-slate-300"
              >
                {isSubmittingLabel ? "Submitting…" : "Submit Label"}
              </button>
            </div>
            {labelError && <p className="mt-2 text-sm text-red-700">{labelError}</p>}
          </section>

          <ResponsePlaybookPanel
            caseId={incident.id}
            fetchPlaybook={getIncidentRemediationPlaybook}
            submitAction={submitIncidentRemediationAction}
          />

          <section>
            <h2 className="mb-3 text-lg font-semibold text-slate-800">Findings</h2>
            <FindingList findings={incident.findings} />
          </section>

          <section>
            <h2 className="mb-3 text-lg font-semibold text-slate-800">Evidence Events</h2>
            <EvidenceEventsTable events={incident.evidence_events} />
          </section>

          <section>
            <h2 className="mb-3 text-lg font-semibold text-slate-800">Framework Mapping</h2>
            <FrameworkMappingPanel frameworkMappings={incident.framework_mappings} />
          </section>
        </>
      )}
    </div>
  );
}
