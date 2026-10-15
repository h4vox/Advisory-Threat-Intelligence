import * as Dialog from "@radix-ui/react-dialog";
import { useQuery } from "@tanstack/react-query";
import { Link } from "@tanstack/react-router";
import { ArrowUpRight, X } from "lucide-react";
import { getReport } from "@/lib/aie/server";
import { EvidencePanel } from "./evidence-panel";

/** Full-report evidence view, loaded on demand (list items carry no text or evidence). */
export function ReportEvidenceDialog({
  reportId,
  title,
  open,
  onOpenChange,
}: {
  reportId: string;
  title: string;
  open: boolean;
  onOpenChange: (open: boolean) => void;
}) {
  const reportQuery = useQuery({
    queryKey: ["report", reportId],
    queryFn: () => getReport({ data: { id: reportId } }),
    enabled: open,
  });
  const report = reportQuery.data;

  return (
    <Dialog.Root open={open} onOpenChange={onOpenChange}>
      <Dialog.Portal>
        <Dialog.Overlay className="fixed inset-0 z-40 bg-black/60 backdrop-blur-[1px]" />
        <Dialog.Content className="fixed inset-x-2 top-[4vh] bottom-[4vh] z-40 mx-auto flex max-w-5xl flex-col overflow-hidden rounded-xl border border-border bg-bg shadow-xl sm:inset-x-6">
          <div className="flex items-start justify-between gap-3 border-b border-border px-4 py-3">
            <div className="min-w-0">
              <Dialog.Title className="text-sm font-semibold text-fg">Evidence</Dialog.Title>
              <Dialog.Description className="truncate text-xs text-muted">{title}</Dialog.Description>
            </div>
            <div className="flex shrink-0 items-center gap-2">
            <Link
              to="/library/$reportId"
              params={{ reportId }}
              search={{ tab: "evidence" }}
              onClick={() => onOpenChange(false)}
              className="inline-flex h-8 items-center gap-1.5 rounded-lg border border-border bg-bg-elevated px-2.5 text-sm font-medium text-fg transition-colors hover:bg-bg-subtle"
            >
              <ArrowUpRight className="size-4" strokeWidth={1.75} />
              Open report
            </Link>
            <Dialog.Close
              aria-label="Close evidence"
              className="rounded-md border border-border p-1.5 text-muted transition-colors hover:bg-bg-subtle hover:text-fg"
            >
              <X className="size-4" />
            </Dialog.Close>
            </div>
          </div>
          <div className="flex-1 overflow-y-auto px-4 py-4">
            {reportQuery.isPending && <p className="text-sm text-muted">Loading report…</p>}
            {reportQuery.isError && (
              <p className="text-sm text-danger">Could not load this report: {String(reportQuery.error?.message ?? "error")}</p>
            )}
            {report === null && <p className="text-sm text-muted">Report not found.</p>}
            {report && (
              <EvidencePanel analysis={report.analysis} iocs={report.iocs ?? []} extractedText={report.extractedText ?? ""} />
            )}
          </div>
        </Dialog.Content>
      </Dialog.Portal>
    </Dialog.Root>
  );
}
