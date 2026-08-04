interface AIAnalystSummaryProps {
  narrative: string | null;
  model: string | null;
}

export default function AIAnalystSummary({ narrative, model }: AIAnalystSummaryProps) {
  if (!narrative) {
    return null;
  }

  return (
    <section className="rounded-xl border border-indigo-200 bg-indigo-50 p-6 shadow-sm">
      <div className="flex items-center justify-between gap-2">
        <h2 className="text-lg font-semibold text-indigo-900">AI Analyst Summary</h2>
        {model && (
          <span className="rounded-full border border-indigo-300 bg-white px-2.5 py-0.5 text-xs font-medium text-indigo-700">
            {model}
          </span>
        )}
      </div>
      <p className="mt-2 text-sm text-indigo-900">{narrative}</p>
    </section>
  );
}
