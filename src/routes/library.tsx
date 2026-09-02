import { useQuery } from "@tanstack/react-query";
import { createFileRoute, Link } from "@tanstack/react-router";
import { useState } from "react";
import {
  ArrowUpRight,
  Download,
  Eye,
  FileText,
  Printer,
  Search,
  Shield,
  ShieldAlert,
  Sparkles,
  X,
} from "lucide-react";
import { toast } from "sonner";
import { AppShell } from "@/components/app-shell";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { getReportPdf, listReports } from "@/lib/aie/server";
import { formatDateTime } from "@/lib/aie/format";
import { cn } from "@/lib/cn";
import type { ReportListItem, ResourceKind } from "@/lib/aie/types";

export const Route = createFileRoute("/library")({ component: LibraryPage });

const RESOURCE_KINDS: { id: string; label: string }[] = [
  { id: "ALL", label: "All Intelligence" },
  { id: "FULL_ATTACK_CHAIN", label: "Attack Chains" },
  { id: "CAMPAIGN_INTEL", label: "Campaigns" },
  { id: "PROCEDURE_DEEPDIVE", label: "Procedures & TTPs" },
  { id: "MALWARE_ANALYSIS", label: "Malware Analysis" },
  { id: "DETECTION_GUIDANCE", label: "Detections & Sigma" },
  { id: "VULNERABILITY_ADVISORY", label: "Vulnerability Advisories" },
];

export function LibraryPage() {
  const [q, setQ] = useState("");
  const [selectedKind, setSelectedKind] = useState("ALL");
  const [previewReportId, setPreviewReportId] = useState<string | null>(null);

  const { data, isLoading } = useQuery({
    queryKey: ["reports", q, selectedKind],
    queryFn: () =>
      listReports({
        data: {
          q,
          resourceKind: selectedKind !== "ALL" ? selectedKind : undefined,
        },
      }),
  });

  const { data: previewData, isLoading: isPreviewLoading } = useQuery({
    queryKey: ["report-pdf", previewReportId],
    queryFn: () => (previewReportId ? getReportPdf({ data: { id: previewReportId } }) : null),
    enabled: Boolean(previewReportId),
  });

  const handleDownloadPdf = (r: ReportListItem, e?: React.MouseEvent) => {
    if (e) e.stopPropagation();

    // Fetch full report if not in previewData
    void (async () => {
      try {
        toast.info("Preparing PDF Document for download...");
        const rep = await getReportPdf({ data: { id: r.id } });
        if (!rep.ok || !rep.rawHtml) {
          toast.error("PDF representation not available for this report");
          return;
        }

        const blob = new Blob([rep.rawHtml], { type: "text/html;charset=utf-8" });
        const dlUrl = URL.createObjectURL(blob);
        const a = document.createElement("a");
        a.href = dlUrl;
        const slug = (rep.title || "threat_report")
          .toLowerCase()
          .replace(/[^a-z0-9_-]/g, "_")
          .slice(0, 50);
        a.download = `${slug}_intel_report.html`;
        a.click();
        URL.revokeObjectURL(dlUrl);
        toast.success("Document Downloaded", {
          description: "High-fidelity PDF document saved. Open and select Print → Save as PDF for vector rendering.",
        });
      } catch (err) {
        toast.error("Failed downloading document");
      }
    })();
  };

  const handlePrintDocument = (html: string) => {
    const printWindow = window.open("", "_blank");
    if (printWindow) {
      printWindow.document.write(html);
      printWindow.document.close();
      printWindow.focus();
      setTimeout(() => {
        printWindow.print();
      }, 400);
    } else {
      toast.info("Pop-up blocked. Please allow pop-ups to print to PDF directly.");
    }
  };

  const getKindTone = (kind?: ResourceKind): "accent" | "warn" | "sage" | "neutral" => {
    switch (kind) {
      case "FULL_ATTACK_CHAIN":
        return "accent";
      case "MALWARE_ANALYSIS":
        return "warn";
      case "DETECTION_GUIDANCE":
        return "sage";
      case "VULNERABILITY_ADVISORY":
        return "warn";
      case "PROCEDURE_DEEPDIVE":
        return "accent";
      default:
        return "neutral";
    }
  };

  return (
    <AppShell>
      <div className="flex flex-col gap-4 md:flex-row md:items-end md:justify-between">
        <div>
          <p className="font-mono text-[11px] uppercase tracking-[0.2em] text-subtle">MongoDB Central Intelligence Store</p>
          <h1 className="mt-1 text-3xl font-medium tracking-tight">Intelligence Library</h1>
          <p className="mt-1 text-xs text-muted">
            Acquired adversary intelligence, normalized evidence, IOCs, and reconstructed attack chains stored in MongoDB Atlas.
          </p>
        </div>
        <div className="flex items-center gap-2">
          <Input
            value={q}
            onChange={(e) => setQ(e.target.value)}
            placeholder="Search CVE, actor, malware, procedure, or hash…"
            className="w-full md:w-80 text-xs"
          />
        </div>
      </div>

      {/* Category Pills */}
      <div className="mt-6 flex flex-wrap gap-1.5 border-b border-border pb-3">
        {RESOURCE_KINDS.map((c) => (
          <button
            key={c.id}
            type="button"
            onClick={() => setSelectedKind(c.id)}
            className={cn(
              "rounded-full px-3 py-1 text-xs font-medium transition-colors",
              selectedKind === c.id
                ? "bg-fg text-bg"
                : "bg-bg-elevated text-muted hover:text-fg border border-border",
            )}
          >
            {c.label}
          </button>
        ))}
      </div>

      <div className="mt-6 grid gap-3">
        {isLoading ? <p className="py-8 text-center text-sm text-muted">Loading MongoDB intelligence store…</p> : null}
        {!isLoading && data?.length === 0 ? (
          <div className="rounded-xl border border-border bg-bg-elevated py-12 text-center text-sm text-muted">
            No threat intelligence reports match your filter. Ingest new reports or run the autonomous crawler.
          </div>
        ) : null}

        {data?.map((r) => (
          <div
            key={r.id}
            className="group rounded-xl border border-border bg-bg-elevated p-5 transition-colors hover:border-border/80 hover:bg-bg-subtle/40"
          >
            <div className="flex flex-wrap items-center justify-between gap-2">
              <div className="flex flex-wrap items-center gap-2">
                <Badge tone="neutral">{r.sourceName}</Badge>
                {r.resourceKind && (
                  <Badge tone={getKindTone(r.resourceKind)} className="font-semibold">
                    {r.resourceKind.replace(/_/g, " ")}
                  </Badge>
                )}
                <Badge tone="accent">{r.classification}</Badge>
                <Badge tone={r.status === "acquired" ? "sage" : "warn"}>{r.status}</Badge>
                <Badge tone="sage" className="gap-1">
                  <FileText className="size-2.5" /> High-Fidelity PDF
                </Badge>
              </div>

              <span className="font-mono text-[11px] text-subtle tabular-nums">
                {Math.round(r.qualityScore * 100)}% quality · {r.wordCount} words · {r.iocCount} IOCs
              </span>
            </div>

            <div className="mt-3 flex items-start justify-between gap-4">
              <Link to="/library/$reportId" params={{ reportId: r.id }} className="flex-1">
                <h2 className="text-base font-medium leading-snug group-hover:text-accent transition-colors">
                  {r.title}
                </h2>
                <p className="mt-1.5 line-clamp-2 text-xs text-muted leading-relaxed">{r.excerpt}</p>
              </Link>

              <div className="flex shrink-0 items-center gap-2 pt-1">
                <Button
                  size="sm"
                  variant="secondary"
                  className="h-8 gap-1.5 text-xs"
                  onClick={() => setPreviewReportId(r.id)}
                  title="View PDF Document Representation"
                >
                  <Eye className="size-3.5" />
                  <span className="hidden sm:inline">View PDF</span>
                </Button>

                <Button
                  size="sm"
                  variant="ghost"
                  className="h-8 gap-1.5 text-xs text-muted hover:text-fg"
                  onClick={(e) => handleDownloadPdf(r, e)}
                  title="Download Document"
                >
                  <Download className="size-3.5" />
                  <span className="hidden sm:inline">Download</span>
                </Button>

                <Link
                  to="/library/$reportId"
                  params={{ reportId: r.id }}
                  className="p-1 text-subtle hover:text-fg transition-colors"
                >
                  <ArrowUpRight className="size-4" />
                </Link>
              </div>
            </div>

            <div className="mt-3 flex flex-wrap items-center justify-between gap-2 border-t border-border pt-2.5 font-mono text-[10px] text-subtle">
              <span>Domain: {r.sourceDomain || "Verified source"}</span>
              <div className="flex items-center gap-3">
                <button
                  type="button"
                  onClick={() => setPreviewReportId(r.id)}
                  className="text-accent hover:underline flex items-center gap-1"
                >
                  <FileText className="size-3" /> Preview Document & Evidence
                </button>
                <span>Ingested: {formatDateTime(r.ingestedAt)}</span>
              </div>
            </div>
          </div>
        ))}
      </div>

      {/* PDF / DOCUMENT VIEW MODAL */}
      {previewReportId && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/70 p-4 backdrop-blur-sm">
          <div className="flex h-[90vh] w-full max-w-5xl flex-col rounded-2xl border border-border bg-bg-elevated shadow-2xl overflow-hidden animate-in fade-in zoom-in-95 duration-200">
            {/* Modal Header */}
            <div className="flex items-center justify-between border-b border-border bg-bg px-6 py-4">
              <div className="flex items-center gap-3 overflow-hidden">
                <div className="flex size-9 shrink-0 items-center justify-center rounded-lg border border-border bg-bg-elevated">
                  <FileText className="size-4 text-accent" />
                </div>
                <div className="overflow-hidden">
                  <h3 className="truncate text-sm font-medium">
                    {previewData?.title || "High-Fidelity PDF Representation"}
                  </h3>
                  <p className="truncate text-xs text-muted font-mono">
                    {previewData?.canonicalUrl || previewData?.url}
                  </p>
                </div>
              </div>

              <div className="flex items-center gap-2">
                {previewData?.rawHtml && (
                  <>
                    <Button
                      size="sm"
                      variant="secondary"
                      className="h-8 gap-1.5 text-xs"
                      onClick={() => handlePrintDocument(previewData.rawHtml)}
                    >
                      <Printer className="size-3.5" />
                      <span>Print to PDF</span>
                    </Button>

                    <Button
                      size="sm"
                      variant="secondary"
                      className="h-8 gap-1.5 text-xs"
                      onClick={() => {
                        const blob = new Blob([previewData.rawHtml], { type: "text/html;charset=utf-8" });
                        const dlUrl = URL.createObjectURL(blob);
                        const a = document.createElement("a");
                        a.href = dlUrl;
                        a.download = `${previewData.title.slice(0, 40).replace(/[^a-z0-9_-]/gi, "_")}_report.html`;
                        a.click();
                        URL.revokeObjectURL(dlUrl);
                        toast.success("Document downloaded");
                      }}
                    >
                      <Download className="size-3.5" />
                      <span>Download File</span>
                    </Button>
                  </>
                )}

                <Link
                  to="/library/$reportId"
                  params={{ reportId: previewReportId }}
                  className="rounded-lg border border-border bg-bg-elevated px-3 py-1.5 text-xs text-muted hover:text-fg transition-colors"
                >
                  Full Report Detail
                </Link>

                <button
                  type="button"
                  onClick={() => setPreviewReportId(null)}
                  className="flex size-8 items-center justify-center rounded-lg text-muted hover:bg-bg-subtle hover:text-fg transition-colors"
                >
                  <X className="size-4" />
                </button>
              </div>
            </div>

            {/* Modal Body / Document Preview */}
            <div className="flex-1 overflow-hidden bg-neutral-900">
              {isPreviewLoading ? (
                <div className="flex h-full items-center justify-center text-muted text-sm">
                  Loading high-fidelity PDF document representation...
                </div>
              ) : previewData?.rawHtml ? (
                <iframe
                  title="Document PDF Preview"
                  srcDoc={previewData.rawHtml}
                  className="size-full border-0 bg-white"
                  sandbox="allow-same-origin allow-scripts allow-popups"
                />
              ) : (
                <div className="flex h-full flex-col items-center justify-center p-8 text-center text-muted">
                  <p className="text-sm">Raw document HTML not available for this record.</p>
                  <p className="mt-1 text-xs">You can re-ingest or crawl to regenerate pristine document layouts.</p>
                </div>
              )}
            </div>
          </div>
        </div>
      )}
    </AppShell>
  );
}
