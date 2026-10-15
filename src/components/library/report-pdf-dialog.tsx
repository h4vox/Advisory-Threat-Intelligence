import * as Dialog from "@radix-ui/react-dialog";
import { useQuery } from "@tanstack/react-query";
import { AlertTriangle, ArrowUpRight, Download, FileText, Printer, RefreshCw, X } from "lucide-react";
import { toast } from "sonner";
import { ActionButton } from "@/components/layout/page";
import { ActivitySpinner } from "@/components/ui/activity-spinner";
import { EmptyState } from "@/components/ui/primitives";
import { getReportPdf } from "@/lib/aie/server";
import { formatReportId } from "@/lib/aie/ids";
import { toSafeSrcDoc } from "@/lib/aie/safe-srcdoc";
import { downloadHtml, printHtml } from "./report-utils";

/** Document (PDF representation) preview for one report, loaded on demand. */
export function ReportPdfDialog({
  reportId,
  onClose,
  onOpenReport,
}: {
  reportId: string | null;
  onClose: () => void;
  /** Navigate to the full report page. */
  onOpenReport?: (id: string) => void;
}) {
  const { data, isLoading, isError, refetch } = useQuery({
    queryKey: ["report-pdf", reportId],
    queryFn: () => (reportId ? getReportPdf({ data: { id: reportId } }) : null),
    enabled: Boolean(reportId),
    staleTime: 60_000,
  });

  return (
    <Dialog.Root open={Boolean(reportId)} onOpenChange={(o) => !o && onClose()}>
      <Dialog.Portal>
        <Dialog.Overlay className="fixed inset-0 z-50 bg-black/70 backdrop-blur-sm" />
        <Dialog.Content className="fixed inset-x-2 top-[3vh] bottom-[3vh] z-50 mx-auto flex max-w-5xl flex-col overflow-hidden rounded-xl border border-border bg-bg-elevated shadow-2xl sm:inset-x-6">
          <div className="flex flex-col gap-3 border-b border-border bg-bg px-4 py-3 sm:flex-row sm:items-center sm:justify-between sm:px-5">
            <div className="flex min-w-0 items-center gap-3">
              <span className="flex size-9 shrink-0 items-center justify-center rounded-lg border border-border bg-bg-elevated text-accent">
                <FileText className="size-4" strokeWidth={1.75} />
              </span>
              <div className="min-w-0">
                <Dialog.Title className="truncate text-sm font-medium text-fg">
                  {data?.title || "Document preview"}
                </Dialog.Title>
                <Dialog.Description className="truncate text-xs text-muted">
                  <span className="font-mono">{reportId ? formatReportId(reportId) : ""}</span>
                  {(data?.canonicalUrl || data?.url) && <span> · {data?.canonicalUrl || data?.url}</span>}
                </Dialog.Description>
              </div>
            </div>
            <div className="flex flex-wrap items-center gap-2 whitespace-nowrap sm:shrink-0 sm:flex-nowrap">
              {data?.rawHtml && (
                <>
                  <ActionButton
                    icon={Printer}
                    onClick={() => {
                      if (!printHtml(data.rawHtml)) toast.info("Pop-up blocked. Allow pop-ups to print to PDF.");
                    }}
                  >
                    Print
                  </ActionButton>
                  <ActionButton
                    icon={Download}
                    onClick={() => {
                      downloadHtml(data.rawHtml, data.title);
                      toast.success("Document downloaded");
                    }}
                  >
                    Download
                  </ActionButton>
                </>
              )}
              {onOpenReport && reportId && (
                <ActionButton variant="primary" icon={ArrowUpRight} onClick={() => onOpenReport(reportId)}>
                  Open report
                </ActionButton>
              )}
              <Dialog.Close
                aria-label="Close preview"
                className="flex size-9 items-center justify-center rounded-lg text-muted transition-colors hover:bg-bg-subtle hover:text-fg"
              >
                <X className="size-4" />
              </Dialog.Close>
            </div>
          </div>

          <div className="flex-1 overflow-hidden bg-bg">
            {isLoading ? (
              <div className="flex h-full flex-col items-center justify-center gap-2 text-sm text-muted">
                <ActivitySpinner size="lg" className="text-accent" />
                <span>Loading document…</span>
              </div>
            ) : isError || (data && !data.ok) ? (
              <EmptyState
                className="h-full"
                icon={AlertTriangle}
                title="Unable to load the document"
                description={
                  data && !data.ok && data.error ? data.error : "A network error occurred or the connection was interrupted."
                }
                action={
                  <ActionButton icon={RefreshCw} onClick={() => void refetch()}>
                    Retry
                  </ActionButton>
                }
              />
            ) : data?.rawHtml ? (
              <iframe
                title="Document preview"
                srcDoc={toSafeSrcDoc(data.rawHtml)}
                className="size-full border-0 bg-white"
                sandbox=""
              />
            ) : (
              <EmptyState
                className="h-full"
                icon={FileText}
                title="No document layout stored for this report"
                description="Re-ingest or crawl the source to regenerate the document layout."
              />
            )}
          </div>
        </Dialog.Content>
      </Dialog.Portal>
    </Dialog.Root>
  );
}
