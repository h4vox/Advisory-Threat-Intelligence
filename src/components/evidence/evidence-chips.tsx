import { Quote } from "lucide-react";
import type { Evidence, EvidenceLabel, IntelAnalysis, TargetingFact } from "@/lib/aie/types";
import { cn } from "@/lib/cn";
import {
  FIELD_TEXT,
  LABEL_HINT,
  LABEL_TEXT,
  TARGET_STATUS_TEXT,
  formatConfidence,
  useOpenQuote,
} from "./evidence-utils";

const chipBase =
  "inline-flex shrink-0 items-center rounded-full border px-2 py-0.5 font-mono text-[10px] uppercase tracking-wide";

export function LabelChip({ label, className }: { label: EvidenceLabel; className?: string }) {
  return (
    <span
      title={LABEL_HINT[label]}
      className={cn(
        chipBase,
        label === "observed" && "border-sage/40 bg-sage/10 text-sage",
        label === "inferred" && "border-dashed border-warn/50 bg-transparent text-warn",
        label !== "observed" && label !== "inferred" && "border-border bg-bg-subtle text-muted",
        className,
      )}
    >
      {LABEL_TEXT[label]}
    </span>
  );
}

export function StatusChip({ status }: { status: TargetingFact["status"] }) {
  return (
    <span
      className={cn(
        chipBase,
        (status === "targeted" || status === "compromised") && "border-danger/40 bg-danger/10 text-danger",
        status === "at_risk" && "border-warn/40 bg-warn/10 text-warn",
        status === "mentioned" && "border-border bg-bg-subtle text-muted",
      )}
    >
      {TARGET_STATUS_TEXT[status]}
    </span>
  );
}

export function ConfidenceText({ value }: { value: number | undefined }) {
  const text = formatConfidence(value);
  if (!text) return null;
  return (
    <span className="font-mono text-[10px] text-subtle" title="Extraction confidence">
      conf {text}
    </span>
  );
}

export function MethodBadge({ analysis }: { analysis: IntelAnalysis | null | undefined }) {
  if (!analysis) {
    return <span className={cn(chipBase, "border-border bg-bg-subtle text-muted")}>Not analysed</span>;
  }
  const { method, fieldOrigins } = analysis;
  const heuristicFields = Object.entries(fieldOrigins ?? {})
    .filter(([, origin]) => origin === "heuristic")
    .map(([field]) => FIELD_TEXT[field as keyof typeof FIELD_TEXT] ?? field);

  return (
    <div className="flex min-w-0 flex-col gap-1">
      <div className="flex flex-wrap items-center gap-2">
        <span
          className={cn(
            chipBase,
            method === "heuristic" && "border-border-strong bg-bg-subtle text-fg",
            method === "llm" && "border-accent/40 bg-accent/10 text-accent",
            method === "mixed" && "border-warn/40 bg-warn/10 text-warn",
          )}
        >
          {method === "heuristic" ? "Heuristic" : method === "llm" ? "AI" : "Mixed"}
        </span>
        <span className="text-xs text-muted">
          {method === "heuristic" && "Rule-based extraction — no AI model was used."}
          {method === "llm" && "Extracted by an AI model; review the supporting passages."}
          {method === "mixed" && "AI + heuristic: some fields fell back to rule-based extraction."}
        </span>
      </div>
      {method === "mixed" && heuristicFields.length > 0 ? (
        <p className="text-[11px] text-subtle">
          Heuristic fallback for: <span className="text-muted">{heuristicFields.join(", ")}</span>
        </p>
      ) : null}
    </div>
  );
}

/** A clickable quote that opens the full extracted text at this range. */
export function EvidenceQuote({ evidence }: { evidence: Evidence }) {
  const openQuote = useOpenQuote();
  const body = (
    <>
      {evidence.section ? (
        <span className="mb-1 block font-mono text-[10px] uppercase tracking-wide text-subtle">
          § {evidence.section}
        </span>
      ) : null}
      <span className="flex gap-2">
        <Quote className="mt-0.5 size-3 shrink-0 text-subtle" aria-hidden />
        <span className="min-w-0 whitespace-pre-wrap break-words [overflow-wrap:anywhere]">
          {evidence.quote}
        </span>
      </span>
    </>
  );
  const className =
    "block w-full min-w-0 rounded-md border-l-2 border-border-strong bg-bg-subtle/60 px-3 py-2 text-left text-xs leading-relaxed text-muted";
  if (!openQuote) return <div className={className}>{body}</div>;
  return (
    <button
      type="button"
      onClick={() => openQuote(evidence)}
      aria-label={`Show in source text: ${evidence.quote.slice(0, 120)}`}
      className={cn(
        className,
        "transition-colors hover:border-accent hover:bg-bg-subtle hover:text-fg focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring/70",
      )}
    >
      {body}
    </button>
  );
}

export function EvidenceQuotes({ evidence, max = 3 }: { evidence: Evidence[] | undefined; max?: number }) {
  if (!evidence || evidence.length === 0) {
    return <p className="text-[11px] italic text-subtle">No supporting passage recorded.</p>;
  }
  const shown = evidence.slice(0, max);
  return (
    <div className="space-y-1.5">
      {shown.map((e, idx) => (
        <EvidenceQuote key={`${e.start}-${e.end}-${idx}`} evidence={e} />
      ))}
      {evidence.length > max ? (
        <details className="group">
          <summary className="cursor-pointer text-[11px] text-subtle hover:text-fg">
            {evidence.length - max} more passage{evidence.length - max === 1 ? "" : "s"}
          </summary>
          <div className="mt-1.5 space-y-1.5">
            {evidence.slice(max).map((e, idx) => (
              <EvidenceQuote key={`${e.start}-${e.end}-more-${idx}`} evidence={e} />
            ))}
          </div>
        </details>
      ) : null}
    </div>
  );
}
