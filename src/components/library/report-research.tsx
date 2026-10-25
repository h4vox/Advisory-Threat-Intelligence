import { Link } from "@tanstack/react-router";
import { researchCategory, type ResearchLabels } from "@/lib/aie/research-taxonomy";
import { DETECTION_CONTENT_NOUN, type TelemetryRefs } from "@/lib/aie/telemetry-refs";
import { cn } from "@/lib/cn";

/** Research types of a report as chips that open the Library filtered to that type. */
export function ResearchTypeChips({ research, className }: { research?: ResearchLabels; className?: string }) {
  const labels = research?.labels ?? [];
  if (!labels.length) return <span className="text-subtle">{research ? "None identified" : "Not labelled yet"}</span>;
  return (
    <span className={cn("flex flex-wrap gap-1.5", className)}>
      {labels.map((l) => {
        const c = researchCategory(l.id);
        return (
          <Link
            key={l.id}
            to="/library"
            search={{ research: l.id }}
            title={`${c?.label ?? l.id}. Matched: ${l.evidence.join(", ")}`}
            className={cn(
              "rounded-md border px-2 py-0.5 text-[11px] font-medium transition-colors hover:border-border-strong hover:text-fg",
              c?.scope === "bas" ? "border-dashed border-border text-muted" : "border-border bg-bg-subtle/60 text-fg",
            )}
          >
            {c?.short ?? l.id}
          </Link>
        );
      })}
    </span>
  );
}

/**
 * The telemetry a report itself names: event IDs, log sources and the detection content it
 * publishes, each with the sentence that states it. Facts from the source, kept apart from the
 * generated detection ideas.
 */
export function ReportTelemetry({ telemetry }: { telemetry?: TelemetryRefs }) {
  if (!telemetry) {
    return <p className="text-sm text-subtle">Not analysed yet. Opening the Library labels stored reports.</p>;
  }
  const { events, sources, content } = telemetry;
  if (!events.length && !sources.length && !content.length) {
    return <p className="text-sm text-subtle">The report names no event IDs, log sources or detection content.</p>;
  }
  return (
    <div className="space-y-5">
      {content.length > 0 && (
        <div>
          <h3 className="mb-2 text-sm font-medium text-fg">Detection content published in the report</h3>
          <div className="flex flex-wrap gap-2">
            {content.map((c) => (
              <span key={c.kind} className="rounded-md border border-border bg-bg-subtle/60 px-2 py-1 text-xs text-fg">
                <span className="tabular-nums">{c.count}</span> {DETECTION_CONTENT_NOUN[c.kind][c.count === 1 ? 0 : 1]}
              </span>
            ))}
          </div>
          <p className="mt-1.5 text-xs text-subtle">The rules and queries are in the Document and Extracted text tabs.</p>
        </div>
      )}

      {events.length > 0 && (
        <div>
          <h3 className="mb-2 text-sm font-medium text-fg">Event IDs</h3>
          <ul className="divide-y divide-border rounded-xl border border-border bg-bg-card">
            {events.map((e) => (
              <li key={`${e.log}:${e.id}`} className="grid gap-1 px-4 py-3 sm:grid-cols-[10rem_minmax(0,1fr)] sm:gap-4">
                <div className="min-w-0">
                  <div className="font-mono text-[13px] text-fg">{e.id}</div>
                  <div className="text-xs text-muted">
                    {e.log}
                    {e.meaning ? ` · ${e.meaning}` : ""}
                  </div>
                </div>
                <blockquote className="min-w-0 break-words border-l-2 border-border pl-3 text-xs text-muted">{e.quote}</blockquote>
              </li>
            ))}
          </ul>
        </div>
      )}

      {sources.length > 0 && (
        <div>
          <h3 className="mb-2 text-sm font-medium text-fg">Log sources</h3>
          <ul className="divide-y divide-border rounded-xl border border-border bg-bg-card">
            {sources.map((s) => (
              <li key={s.name} className="grid gap-1 px-4 py-3 sm:grid-cols-[14rem_minmax(0,1fr)] sm:gap-4">
                <span className="text-sm text-fg">{s.name}</span>
                <blockquote className="min-w-0 break-words border-l-2 border-border pl-3 text-xs text-muted">{s.quote}</blockquote>
              </li>
            ))}
          </ul>
        </div>
      )}
    </div>
  );
}
