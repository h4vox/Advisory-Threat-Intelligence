import { useEffect, useState } from "react";
import * as Dialog from "@radix-ui/react-dialog";
import { useQueryClient } from "@tanstack/react-query";
import { Eye, Sparkles, X } from "lucide-react";
import { toast } from "sonner";
import { ActionButton } from "@/components/layout/page";
import { Meter, StatusChip } from "@/components/ui/primitives";
import { evaluateReportWithAi } from "@/lib/aie/server";
import type { AgentScoreBreakdown, ResourceKind } from "@/lib/aie/types";
import { aiReview, kindLabel } from "./report-utils";

export type AiReviewSubject = {
  id: string;
  title: string;
  qualityScore: number;
  wordCount?: number;
  iocCount?: number;
  resourceKind?: ResourceKind;
  classification?: string;
  status?: string;
  aiVerified?: boolean;
  aiQualityScore?: number;
  aiAuditReason?: string;
  scoreBreakdown?: AgentScoreBreakdown;
  tags?: string[];
};

const DIMENSIONS: Array<{ key: keyof AgentScoreBreakdown; label: string; max: number }> = [
  { key: "proceduralDepth", label: "Procedural depth (commands, LOLBins)", max: 30 },
  { key: "attackProgression", label: "Attack progression (multi-stage flow)", max: 25 },
  { key: "attributionContext", label: "Attribution and threat context", max: 15 },
  { key: "emulationUtility", label: "Emulation and detection utility", max: 20 },
  { key: "iocVerifiability", label: "IOC and telemetry verifiability", max: 10 },
];

/** AI quality-gate review for one report: status, 5-dimension scorecard, rationale, re-evaluate. */
export function AiReviewDialog({
  report,
  onClose,
  onOpenPdf,
}: {
  report: AiReviewSubject | null;
  onClose: () => void;
  onOpenPdf?: (id: string) => void;
}) {
  const qc = useQueryClient();
  const [current, setCurrent] = useState<AiReviewSubject | null>(report);
  const [busy, setBusy] = useState(false);
  useEffect(() => setCurrent(report), [report]);

  const evaluate = async (id: string) => {
    setBusy(true);
    toast.info("Running the 5-dimension rubric evaluation…");
    try {
      const res = await evaluateReportWithAi({ data: { id } });
      if (res.success && res.result) {
        const score = res.result.passScore;
        if (res.isApproved) toast.success(`Approved by the AI agent (${score}/100)`);
        else toast.warning(`Rejected by the AI agent (${score}/100): ${res.result.rationale}`);
        setCurrent((prev) =>
          !prev || prev.id !== id
            ? prev
            : {
                ...prev,
                aiVerified: res.isApproved,
                aiQualityScore: score,
                aiAuditReason: res.isApproved
                  ? `AI Cognitive Approval (${score}/100): ${res.result.rationale}`
                  : `Rejected by AI Cognitive Gate (${score}/100): ${res.result.rationale}`,
                scoreBreakdown: res.result.scoreBreakdown,
                status: res.isApproved ? "acquired" : "rejected",
                classification: res.result.classification || prev.classification,
                resourceKind: (res.result.resourceKind as ResourceKind | undefined) || prev.resourceKind,
              },
        );
        void qc.invalidateQueries({ queryKey: ["reports-all"] });
        void qc.invalidateQueries({ queryKey: ["reports-search"] });
        void qc.invalidateQueries({ queryKey: ["report", id] });
      } else {
        toast.error(`Evaluation failed: ${res.error || "Unknown error"}`);
      }
    } catch (err: any) {
      toast.error(`Agent evaluation failed: ${err?.message || "Unknown error"}`);
    } finally {
      setBusy(false);
    }
  };

  const r = current;
  const review = r ? aiReview(r) : null;
  const total = r ? (r.scoreBreakdown?.totalScore ?? Math.round(r.qualityScore * 100)) : 0;

  return (
    <Dialog.Root open={Boolean(report)} onOpenChange={(o) => !o && onClose()}>
      <Dialog.Portal>
        <Dialog.Overlay className="fixed inset-0 z-50 bg-black/70 backdrop-blur-sm" />
        <Dialog.Content className="fixed left-1/2 top-[6vh] z-50 flex max-h-[88vh] w-[calc(100%-1.5rem)] max-w-lg -translate-x-1/2 flex-col overflow-hidden rounded-xl border border-border bg-bg-elevated shadow-2xl">
          <div className="flex items-start justify-between gap-3 border-b border-border px-5 py-4">
            <div className="min-w-0">
              <Dialog.Title className="flex items-center gap-2 text-base font-medium text-fg">
                <Sparkles className="size-4 text-accent" strokeWidth={1.75} />
                AI review
              </Dialog.Title>
              <Dialog.Description className="mt-0.5 truncate text-sm text-muted">{r?.title}</Dialog.Description>
            </div>
            <Dialog.Close
              aria-label="Close AI review"
              className="flex size-8 shrink-0 items-center justify-center rounded-lg text-muted transition-colors hover:bg-bg-subtle hover:text-fg"
            >
              <X className="size-4" />
            </Dialog.Close>
          </div>

          {r && review && (
            <div className="flex-1 space-y-6 overflow-y-auto px-5 py-5 text-sm">
              <dl className="grid grid-cols-[minmax(0,9rem)_minmax(0,1fr)] gap-x-4 gap-y-3">
                <dt className="text-muted">Status</dt>
                <dd>
                  <StatusChip tone={review.tone} dot>
                    {review.label}
                    {review.detail ? ` · ${review.detail}` : ""}
                  </StatusChip>
                </dd>
                <dt className="text-muted">Quality score</dt>
                <dd className="tabular-nums text-fg">{Math.round(r.qualityScore * 100)}%</dd>
                <dt className="text-muted">IOCs</dt>
                <dd className="tabular-nums text-fg">{r.iocCount ?? 0}</dd>
                <dt className="text-muted">Words</dt>
                <dd className="tabular-nums text-fg">{r.wordCount ?? 0}</dd>
                <dt className="text-muted">Type</dt>
                <dd className="text-fg">{kindLabel(r.resourceKind, r.classification)}</dd>
              </dl>

              <section className="border-t border-border pt-5">
                <div className="mb-3 flex items-baseline justify-between">
                  <h3 className="text-base font-medium text-fg">Validation scorecard</h3>
                  <span className="text-sm tabular-nums text-fg">{total} / 100</span>
                </div>
                {!r.scoreBreakdown && (
                  <p className="mb-3 text-xs text-subtle">
                    No AI breakdown stored yet; bars are estimated from the heuristic quality score.
                  </p>
                )}
                <div className="space-y-3">
                  {DIMENSIONS.map((d) => {
                    const v = r.scoreBreakdown?.[d.key] ?? Math.round(r.qualityScore * d.max);
                    return (
                      <div key={d.key} className="space-y-1.5">
                        <div className="flex justify-between gap-3 text-xs text-muted">
                          <span>{d.label}</span>
                          <span className="tabular-nums text-fg">
                            {v} / {d.max}
                          </span>
                        </div>
                        <Meter value={v / d.max} label={d.label} />
                      </div>
                    );
                  })}
                </div>
              </section>

              <section className="border-t border-border pt-5">
                <h3 className="mb-2 text-base font-medium text-fg">Assessment</h3>
                <p className="leading-relaxed text-muted">
                  {r.aiAuditReason ||
                    "No AI assessment stored for this report yet. Run an evaluation to score it against the rubric."}
                </p>
              </section>

              {r.tags && r.tags.length > 0 && (
                <section className="border-t border-border pt-5">
                  <h3 className="mb-2 text-base font-medium text-fg">Tags ({r.tags.length})</h3>
                  <div className="flex max-h-32 flex-wrap gap-1.5 overflow-y-auto">
                    {r.tags.map((t) => (
                      <span key={t} className="rounded-md bg-bg-subtle px-2 py-0.5 text-xs text-muted">
                        {t}
                      </span>
                    ))}
                  </div>
                </section>
              )}
            </div>
          )}

          {r && (
            <div className="flex flex-wrap items-center justify-between gap-2 border-t border-border px-5 py-4">
              <ActionButton variant="primary" icon={Sparkles} disabled={busy} onClick={() => void evaluate(r.id)}>
                {busy ? "Evaluating…" : r.aiVerified ? "Re-evaluate with AI" : "Evaluate with AI"}
              </ActionButton>
              {onOpenPdf && (
                <ActionButton
                  icon={Eye}
                  onClick={() => {
                    onClose();
                    onOpenPdf(r.id);
                  }}
                >
                  View document
                </ActionButton>
              )}
            </div>
          )}
        </Dialog.Content>
      </Dialog.Portal>
    </Dialog.Root>
  );
}
