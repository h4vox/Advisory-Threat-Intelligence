import { useMemo } from "react";
import { Copy, Route, Sparkles } from "lucide-react";
import { toast } from "sonner";
import { StatusChip } from "@/components/ui/primitives";
import { EMULATION_SIMULATION_GRADE_META, assessEmulationSimulation, summarizeEmulationSimulation, type EmulationSimulationSummary } from "@/lib/aie/emulation-simulation";
import { buildEmulationSimulationBrief } from "@/lib/aie/emulation-simulation-brief";
import type { ReportRecord } from "@/lib/aie/types";
import { EMULATION_SIMULATION_TONE } from "./emulation-simulation-badge";

const REPRODUCIBLE_LABEL = { yes: "Reproducible from the report", partly: "Partly reproducible", no: "Not reproducible from the report" } as const;

/**
 * Emulation & simulation value of one report: the rules' grade with its reasons, the AI's grounded verdict (when
 * analysed) and the emulation & simulation brief — the report retold as infection-chain steps quoted from it.
 */
export function ReportEmulationSimulation({ report }: { report: ReportRecord }) {
  // Reports stored before grading existed are graded here from their text.
  const value: EmulationSimulationSummary | null = useMemo(() => {
    if (report.emulationSimulation?.steps?.length || (report.emulationSimulation && !report.extractedText)) return report.emulationSimulation ?? null;
    const text = report.extractedText ?? "";
    if (text.length < 300) return report.emulationSimulation ?? null;
    const fresh = summarizeEmulationSimulation(assessEmulationSimulation({ title: report.title, text }));
    return report.emulationSimulation?.ai ? { ...fresh, ai: report.emulationSimulation.ai } : fresh;
  }, [report]);
  const ai = report.aiAnalysis?.emulationSimulation ?? null;
  const brief = useMemo(
    () =>
      buildEmulationSimulationBrief({
        title: report.title,
        url: report.canonicalUrl || report.url,
        publisher: report.publisher,
        docTypes: report.docTypes,
        classification: report.classification,
        extractedText: report.extractedText,
        emulationSimulation: value,
        aiAnalysis: report.aiAnalysis ?? null,
      }),
    [report, value],
  );

  if (!value && !ai) return <p className="text-sm text-subtle">Not graded: the report has too little text.</p>;
  const grade = ai?.grade ?? value?.grade ?? "news";
  const meta = EMULATION_SIMULATION_GRADE_META[grade];

  const copyBrief = () => {
    void navigator.clipboard.writeText(brief.text);
    toast.success("Copied the emulation & simulation brief");
  };

  return (
    <div className="space-y-5">
      <div className="flex flex-wrap items-center gap-2">
        <StatusChip tone={EMULATION_SIMULATION_TONE[grade]}>
          <Route className="size-3" aria-hidden />
          {meta.label}
        </StatusChip>
        {value && <span className="text-sm tabular-nums text-muted">{value.score}/100 by the rules</span>}
        {ai && (
          <StatusChip tone="primary">
            <Sparkles className="size-3" aria-hidden />
            AI: {EMULATION_SIMULATION_GRADE_META[ai.grade].label} · {REPRODUCIBLE_LABEL[ai.reproducible]}
          </StatusChip>
        )}
      </div>
      <p className="max-w-3xl text-sm text-muted">{meta.description}</p>

      {value && value.signals.length > 0 && (
        <ul className="max-w-3xl list-disc space-y-1 pl-5 text-sm text-muted">
          {value.signals.map((s) => (
            <li key={s}>{s}</li>
          ))}
        </ul>
      )}

      {ai && (ai.note || ai.gradeNote || ai.missing.length > 0 || (ai.detections?.length ?? 0) > 0) && (
        <div className="max-w-3xl space-y-2 rounded-xl border border-border bg-bg-card p-4 text-sm">
          <p className="font-medium text-fg">AI assessment (every step checked against the report text)</p>
          {ai.note && <p className="text-muted">{ai.note}</p>}
          {ai.gradeNote && <p className="text-warn">{ai.gradeNote}</p>}
          {(ai.detections?.length ?? 0) > 0 && (
            <div>
              <p className="text-muted">What a simulation should trigger (stated in the report):</p>
              <ul className="list-disc pl-5 text-muted">
                {ai.detections.map((d) => (
                  <li key={d.quote}>{d.text}</li>
                ))}
              </ul>
            </div>
          )}
          {ai.missing.length > 0 && (
            <div>
              <p className="text-muted">Still needed to emulate or simulate it:</p>
              <ul className="list-disc pl-5 text-muted">
                {ai.missing.map((m) => (
                  <li key={m}>{m}</li>
                ))}
              </ul>
            </div>
          )}
        </div>
      )}

      <div className="rounded-xl border border-border bg-bg-card">
        <div className="flex flex-wrap items-center justify-between gap-2 border-b border-border px-4 py-2.5">
          <div>
            <p className="text-sm font-medium text-fg">Emulation & simulation brief</p>
            <p className="text-xs text-subtle">
              {brief.stepsFrom === "ai"
                ? "Steps verified by the AI analysis, quoted from the report."
                : brief.stepsFrom === "rules"
                  ? "Steps quoted from the report by the rules. Analyse with AI for a verified chain."
                  : "The report describes no procedure steps."}
            </p>
          </div>
          <button
            type="button"
            onClick={copyBrief}
            className="inline-flex h-8 items-center gap-1.5 rounded-lg border border-border px-2.5 text-xs font-medium text-fg hover:bg-bg-subtle"
          >
            <Copy className="size-3.5" aria-hidden />
            Copy
          </button>
        </div>
        <pre className="max-h-[520px] overflow-auto whitespace-pre-wrap break-words px-4 py-3 font-sans text-sm leading-relaxed text-fg">{brief.text}</pre>
      </div>
    </div>
  );
}
