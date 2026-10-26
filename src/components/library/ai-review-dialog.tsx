import { useEffect, useState } from "react";
import * as Dialog from "@radix-ui/react-dialog";
import { useQueryClient } from "@tanstack/react-query";
import { Check, EyeOff, Eye, Sparkles, X } from "lucide-react";
import { toast } from "sonner";
import { ActionButton } from "@/components/layout/page";
import { Meter, StatusChip } from "@/components/ui/primitives";
import { analyseReportWithAi, resolveReportReview } from "@/lib/aie/server-review";
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
  /** Set by the AI review when an analyst should decide. */
  needsReview?: boolean;
  review?: { action: string; reason: string };
};

const ACTION_TOAST: Record<string, string> = {
  keep: "Useful: kept in the library.",
  flag: "Kept and flagged for you to decide (Needs review).",
  hide: "Hidden: the AI is confident this is not threat research and nothing in it protects it. Restore it from Hidden if that is wrong.",
  restore_and_flag: "Restored to the library and flagged for you to confirm.",
  unchanged: "Analysed; the report's visibility is unchanged.",
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

  const refresh = (id: string) => {
    for (const key of ["reports-all", "reports-search", "nav-counts", "dashboard"]) void qc.invalidateQueries({ queryKey: [key] });
    void qc.invalidateQueries({ queryKey: ["report", id] });
  };

  // Grounded AI analysis plus the safe review: nothing is deleted, uncertain reports stay for review.
  const evaluate = async (id: string) => {
    setBusy(true);
    try {
      const res = await analyseReportWithAi({ data: { id } });
      if (!res.ok) {
        toast.error(res.error);
        return;
      }
      toast.success(ACTION_TOAST[res.action] ?? "Analysed.", { description: res.reason });
      setCurrent((prev) =>
        !prev || prev.id !== id
          ? prev
          : {
              ...prev,
              review: { action: res.action, reason: res.reason },
              needsReview: res.action === "flag" || res.action === "restore_and_flag" ? true : res.action === "keep" || res.action === "hide" ? false : prev.needsReview,
              status: res.action === "hide" ? "rejected" : res.action === "restore_and_flag" ? "acquired" : prev.status,
            },
      );
      refresh(id);
    } catch (err) {
      toast.error(`AI analysis failed: ${err instanceof Error ? err.message : "unknown error"}`);
    } finally {
      setBusy(false);
    }
  };

  const resolve = async (id: string, decision: "keep" | "hide") => {
    setBusy(true);
    try {
      const res = await resolveReportReview({ data: { id, decision } });
      if (!res.ok) {
        toast.error("The review could not be saved.");
        return;
      }
      toast.success(decision === "keep" ? "Kept: the rules and the AI review will not hide it." : "Hidden. Restore it from Hidden at any time.");
      setCurrent((prev) => (!prev || prev.id !== id ? prev : { ...prev, needsReview: false, status: decision === "hide" ? "rejected" : prev.status }));
      refresh(id);
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
                {r.needsReview && (
                  <p className="mb-2">
                    <StatusChip tone="warning" dot>
                      Needs review
                    </StatusChip>
                  </p>
                )}
                <p className="leading-relaxed text-muted">
                  {r.review?.reason ||
                    r.aiAuditReason ||
                    "No AI assessment stored for this report yet. Analyse it to get a grounded summary, indicators, attack chain and a usefulness review."}
                </p>
                <p className="mt-2 text-xs text-subtle">
                  The AI review never deletes. It hides a report only when it is confident the page is not threat research and the report has no
                  indicators, techniques or technical depth; anything uncertain stays in the library for you to decide.
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
              <div className="flex flex-wrap items-center gap-2">
                <ActionButton variant="primary" icon={Sparkles} disabled={busy} onClick={() => void evaluate(r.id)}>
                  {busy ? "Analysing…" : r.review ? "Analyse again" : "Analyse with AI"}
                </ActionButton>
                {r.needsReview && (
                  <>
                    <ActionButton icon={Check} disabled={busy} onClick={() => void resolve(r.id, "keep")} title="Keep it; the rules and the AI review will not hide it">
                      Keep
                    </ActionButton>
                    <ActionButton icon={EyeOff} disabled={busy} onClick={() => void resolve(r.id, "hide")} title="Hide it; restore it from Hidden at any time">
                      Hide
                    </ActionButton>
                  </>
                )}
              </div>
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
