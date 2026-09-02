import { useQuery } from "@tanstack/react-query";
import { createFileRoute, Link } from "@tanstack/react-router";
import { useState } from "react";
import {
  ArrowLeft,
  CheckCircle2,
  Code2,
  Compass,
  Copy,
  Download,
  ExternalLink,
  Eye,
  FileText,
  Flame,
  Globe,
  Layers,
  Maximize2,
  Printer,
  Search,
  Shield,
  ShieldAlert,
  Terminal,
  Workflow,
  Zap,
} from "lucide-react";
import { toast } from "sonner";
import { AppShell } from "@/components/app-shell";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { getReport } from "@/lib/aie/server";
import { formatDateTime } from "@/lib/aie/format";
import { cn } from "@/lib/cn";

export const Route = createFileRoute("/library/$reportId")({ component: ReportPage });

const TABS = [
  "Document & PDF Reader",
  "Attack Chain & TTPs",
  "Emulation & Detections",
  "Extracted Text",
  "IOCs",
  "Hashes & Evidence",
  "Quality Gate",
  "Provenance",
] as const;

function ReportPage() {
  const { reportId } = Route.useParams();
  const [tab, setTab] = useState<(typeof TABS)[number]>("Document & PDF Reader");
  const [isFullscreen, setIsFullscreen] = useState(false);

  const { data, isLoading } = useQuery({
    queryKey: ["report", reportId],
    queryFn: () => getReport({ data: { id: reportId } }),
  });

  const copyToClipboard = (text: string, label: string) => {
    void navigator.clipboard.writeText(text);
    toast.success(`Copied ${label} to clipboard`);
  };

  const downloadDocument = () => {
    if (!data?.rawHtml) {
      toast.error("Document content not available");
      return;
    }
    const blob = new Blob([data.rawHtml], { type: "text/html;charset=utf-8" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    const sanitizedTitle = (data.title || "threat_report")
      .toLowerCase()
      .replace(/[^a-z0-9_-]/g, "_")
      .slice(0, 50);
    a.download = `${sanitizedTitle}_intel_report.html`;
    a.click();
    URL.revokeObjectURL(url);
    toast.success("Document Downloaded", {
      description: "High-fidelity document saved. Open in browser and choose Print → 'Save as PDF' for vector PDF.",
    });
  };

  const printDocument = () => {
    if (!data?.rawHtml) return;
    const printWindow = window.open("", "_blank");
    if (printWindow) {
      printWindow.document.write(data.rawHtml);
      printWindow.document.close();
      printWindow.focus();
      setTimeout(() => {
        printWindow.print();
      }, 350);
    } else {
      toast.info("Pop-up blocked. Please allow pop-ups to print to PDF directly.");
    }
  };

  const analysis = data?.analysis;

  return (
    <AppShell>
      <div className="mb-4 flex items-center justify-between">
        <Link
          to="/library"
          className="inline-flex items-center gap-1.5 text-xs text-muted transition-colors hover:text-fg"
        >
          <ArrowLeft className="size-3.5" /> Back to Library
        </Link>

        {/* Action Buttons for PDF & Export */}
        {data && (
          <div className="flex items-center gap-2">
            <Button
              size="sm"
              variant="secondary"
              className="h-8 gap-1.5 text-xs"
              onClick={printDocument}
            >
              <Printer className="size-3.5" />
              <span>Print to PDF</span>
            </Button>
            <Button
              size="sm"
              className="h-8 gap-1.5 text-xs"
              onClick={downloadDocument}
            >
              <Download className="size-3.5" />
              <span>Download PDF File</span>
            </Button>
          </div>
        )}
      </div>

      {isLoading ? <p className="mt-6 text-sm text-muted">Loading intelligence record…</p> : null}
      {!isLoading && !data ? <p className="mt-6 text-sm text-danger">Report not found.</p> : null}

      {data ? (
        <>
          {/* Header Metadata */}
          <div className="mt-2 flex flex-wrap items-center gap-2">
            <Badge tone="neutral">{data.sourceName}</Badge>
            {data.resourceKind && (
              <Badge tone="accent" className="font-semibold">
                {data.resourceKind.replace(/_/g, " ")}
              </Badge>
            )}
            <Badge tone="neutral">{data.classification}</Badge>
            <Badge tone={data.status === "acquired" ? "sage" : "warn"}>{data.status}</Badge>
            <Badge tone="neutral">{data.contentType}</Badge>
            <Badge tone="neutral">via {data.discoveryMethod.replace(/_/g, " ")}</Badge>
            <Badge tone="sage">High-Fidelity PDF Document Ready</Badge>
          </div>

          <h1 className="mt-3 max-w-4xl text-2xl font-medium tracking-tight md:text-3xl">
            {data.title}
          </h1>

          <div className="mt-2 flex flex-wrap items-center gap-4 text-xs text-muted">
            <a
              href={data.url}
              target="_blank"
              rel="noreferrer"
              className="flex items-center gap-1 font-mono text-subtle hover:text-fg"
            >
              <span className="truncate max-w-md">{data.url}</span>
              <ExternalLink className="size-3 shrink-0" />
            </a>
            <span>·</span>
            <span>Ingested: {formatDateTime(data.ingestedAt)}</span>
            <span>·</span>
            <span>Quality: {Math.round(data.qualityScore * 100)}%</span>
            <span>·</span>
            <span>{data.wordCount} words</span>
          </div>

          {/* Navigation Tabs */}
          <div className="mt-8 flex flex-wrap gap-1 border-b border-border">
            {TABS.map((t) => (
              <button
                key={t}
                type="button"
                onClick={() => setTab(t)}
                className={cn(
                  "h-11 px-4 text-sm font-medium transition-colors",
                  tab === t ? "border-b-2 border-accent text-fg" : "text-muted hover:text-fg",
                )}
              >
                {t}
              </button>
            ))}
          </div>

          {/* TAB 1: DOCUMENT & PDF READER */}
          {tab === "Document & PDF Reader" && (
            <div className="mt-6 space-y-4">
              <div className="flex flex-col justify-between gap-3 rounded-xl border border-border bg-bg-elevated p-4 sm:flex-row sm:items-center">
                <div className="flex items-center gap-3">
                  <FileText className="size-5 text-accent" />
                  <div>
                    <div className="text-sm font-medium">Original Document & PDF Preview</div>
                    <div className="text-xs text-muted">
                      Exact resource formatting, headings, tables, code blocks, and cryptographic evidence.
                    </div>
                  </div>
                </div>

                <div className="flex items-center gap-2">
                  <Button
                    size="sm"
                    variant="secondary"
                    className="h-8 gap-1.5 text-xs"
                    onClick={() => setIsFullscreen(!isFullscreen)}
                  >
                    <Maximize2 className="size-3" />
                    <span>{isFullscreen ? "Standard View" : "Expanded View"}</span>
                  </Button>
                  <Button
                    size="sm"
                    variant="secondary"
                    className="h-8 gap-1.5 text-xs"
                    onClick={printDocument}
                  >
                    <Printer className="size-3" />
                    <span>Print / Save PDF</span>
                  </Button>
                  <Button
                    size="sm"
                    className="h-8 gap-1.5 text-xs"
                    onClick={downloadDocument}
                  >
                    <Download className="size-3" />
                    <span>Download</span>
                  </Button>
                </div>
              </div>

              {/* Document Frame */}
              <div
                className={cn(
                  "overflow-hidden rounded-xl border border-border bg-white shadow-sm transition-all",
                  isFullscreen ? "h-[90vh]" : "h-[750px]",
                )}
              >
                {data.rawHtml ? (
                  <iframe
                    srcDoc={data.rawHtml}
                    title={data.title}
                    className="size-full border-0"
                    sandbox="allow-same-origin"
                  />
                ) : (
                  <div className="flex size-full items-center justify-center p-8 text-sm text-neutral-500">
                    No visual document format stored. View the Extracted Text tab.
                  </div>
                )}
              </div>
            </div>
          )}

          {/* TAB 2: ATTACK CHAIN & TTPS */}
          {tab === "Attack Chain & TTPs" && (
            <div className="mt-6 space-y-6">
              {/* Threat Actor & Malware Chips */}
              <div className="grid gap-4 sm:grid-cols-2">
                <div className="rounded-xl border border-border bg-bg-elevated p-4">
                  <div className="flex items-center gap-2 text-xs font-medium uppercase tracking-wider text-subtle">
                    <ShieldAlert className="size-3.5 text-danger" /> Threat Actors / Adversary Groups
                  </div>
                  <div className="mt-3 flex flex-wrap gap-1.5">
                    {analysis?.threatActors && analysis.threatActors.length > 0 ? (
                      analysis.threatActors.map((actor) => (
                        <Badge key={actor} tone="danger" className="text-xs">
                          {actor}
                        </Badge>
                      ))
                    ) : (
                      <span className="text-xs text-muted">Unattributed or commodity adversary</span>
                    )}
                  </div>
                </div>

                <div className="rounded-xl border border-border bg-bg-elevated p-4">
                  <div className="flex items-center gap-2 text-xs font-medium uppercase tracking-wider text-subtle">
                    <Flame className="size-3.5 text-warn" /> Malware Families & Tools Observed
                  </div>
                  <div className="mt-3 flex flex-wrap gap-1.5">
                    {analysis?.malware && analysis.malware.length > 0 ? (
                      analysis.malware.map((tool) => (
                        <Badge key={tool} tone="warn" className="text-xs">
                          {tool}
                        </Badge>
                      ))
                    ) : (
                      <span className="text-xs text-muted">No named malware signatures in document</span>
                    )}
                  </div>
                </div>
              </div>

              {/* Reconstructed Attack Chain Sequence */}
              <div>
                <h2 className="text-base font-medium">Reconstructed Attack Chain Sequence</h2>
                <p className="text-xs text-muted">
                  Chronological progression of adversary tactics and mapped MITRE ATT&CK techniques.
                </p>

                {(!analysis?.attackChain || analysis.attackChain.length === 0) ? (
                  <div className="mt-4 rounded-xl border border-border bg-bg-elevated p-8 text-center text-sm text-muted">
                    No multi-stage attack chain observed in this report.
                  </div>
                ) : (
                  <div className="mt-4 space-y-3">
                    {analysis.attackChain.map((step) => (
                      <div
                        key={step.order}
                        className="relative flex gap-4 rounded-xl border border-border bg-bg-elevated p-4"
                      >
                        <div className="flex size-7 shrink-0 items-center justify-center rounded-full bg-accent/10 font-mono text-xs font-medium text-accent">
                          {step.order}
                        </div>
                        <div className="min-w-0 flex-1">
                          <div className="flex flex-wrap items-center gap-2">
                            <span className="text-sm font-medium text-fg">{step.tactic}</span>
                          </div>
                          <p className="mt-1 text-xs text-muted">{step.summary}</p>
                          <div className="mt-2.5 flex flex-wrap gap-1.5">
                            {step.techniques.map((tech) => (
                              <Badge key={tech} tone="neutral" className="font-mono text-[11px]">
                                {tech}
                              </Badge>
                            ))}
                          </div>
                        </div>
                      </div>
                    ))}
                  </div>
                )}
              </div>

              {/* Behavioral Indicators of Attack (IOAs) */}
              {analysis?.ioas && analysis.ioas.length > 0 && (
                <div className="rounded-xl border border-border bg-bg-elevated p-5">
                  <h3 className="text-sm font-medium">Indicators of Attack (IOAs) / Behavioral Signatures</h3>
                  <ul className="mt-3 space-y-2">
                    {analysis.ioas.map((ioa, idx) => (
                      <li key={idx} className="flex items-start gap-2 text-xs text-muted">
                        <CheckCircle2 className="mt-0.5 size-3.5 shrink-0 text-sage" />
                        <span>{ioa}</span>
                      </li>
                    ))}
                  </ul>
                </div>
              )}
            </div>
          )}

          {/* TAB 3: EMULATION & DETECTIONS */}
          {tab === "Emulation & Detections" && (
            <div className="mt-6 space-y-6">
              {/* Adversary Simulation Scenarios */}
              <div className="rounded-xl border border-border bg-bg-elevated p-5">
                <div className="flex items-center gap-2">
                  <Terminal className="size-4 text-accent" />
                  <h2 className="text-base font-medium">Adversary Emulation Commands (Atomic Red Team)</h2>
                </div>
                <p className="mt-1 text-xs text-muted">
                  Executable tests to validate purple-team detection coverage against observed techniques.
                </p>

                <div className="mt-4 space-y-3">
                  {analysis?.emulation && analysis.emulation.length > 0 ? (
                    analysis.emulation.map((cmd, idx) => (
                      <div key={idx} className="rounded-lg border border-border bg-bg-subtle p-3">
                        <div className="flex items-center justify-between gap-2">
                          <span className="font-mono text-[11px] text-accent">Atomic Test Scenario {idx + 1}</span>
                          <button
                            type="button"
                            onClick={() => copyToClipboard(cmd, "Emulation command")}
                            className="text-subtle hover:text-fg"
                          >
                            <Copy className="size-3.5" />
                          </button>
                        </div>
                        <pre className="mt-2 overflow-x-auto font-mono text-xs text-fg">{cmd}</pre>
                      </div>
                    ))
                  ) : (
                    <p className="text-xs text-muted">No emulation commands mapped.</p>
                  )}
                </div>
              </div>

              {/* Sigma & Detection Engineering Rules */}
              <div className="rounded-xl border border-border bg-bg-elevated p-5">
                <div className="flex items-center gap-2">
                  <Shield className="size-4 text-sage" />
                  <h2 className="text-base font-medium">Detection Opportunities & Sigma Rules</h2>
                </div>
                <p className="mt-1 text-xs text-muted">
                  Defensive detection opportunities tailored to the adversary procedure in this report.
                </p>

                <div className="mt-4 space-y-2">
                  {analysis?.detections?.map((d, idx) => (
                    <div key={idx} className="rounded-lg border border-border bg-bg-subtle px-3 py-2.5 text-xs">
                      <span className="font-mono text-sage">{d}</span>
                    </div>
                  ))}
                </div>
              </div>

              {/* Threat Hunting Hypotheses */}
              <div className="rounded-xl border border-border bg-bg-elevated p-5">
                <div className="flex items-center gap-2">
                  <Search className="size-4 text-warn" />
                  <h2 className="text-base font-medium">Threat Hunting Queries & Hypotheses</h2>
                </div>
                <p className="mt-1 text-xs text-muted">
                  Proactive hunting search patterns across EDR / SIEM logs.
                </p>

                <div className="mt-4 space-y-2">
                  {analysis?.hunting?.map((h, idx) => (
                    <div key={idx} className="rounded-lg border border-border bg-bg-subtle px-3 py-2.5 text-xs text-muted">
                      {h}
                    </div>
                  ))}
                </div>
              </div>
            </div>
          )}

          {/* TAB 4: EXTRACTED TEXT */}
          {tab === "Extracted Text" && (
            <div className="mt-6 rounded-xl border border-border bg-bg-elevated p-5">
              <pre className="whitespace-pre-wrap font-sans text-sm leading-relaxed text-muted">
                {data.extractedText}
              </pre>
            </div>
          )}

          {/* TAB 5: IOCS */}
          {tab === "IOCs" && (
            <div className="mt-6 overflow-x-auto rounded-xl border border-border bg-bg-elevated">
              {data.iocs.length === 0 ? (
                <p className="p-8 text-center text-sm text-muted">No regex IOCs found in this document.</p>
              ) : (
                <table className="w-full min-w-[500px] text-left text-xs">
                  <thead className="border-b border-border bg-bg-subtle font-mono text-[10px] uppercase text-subtle">
                    <tr>
                      <th className="p-3">Type</th>
                      <th className="p-3">Value</th>
                      <th className="p-3 text-right">Action</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-border">
                    {data.iocs.map((i, idx) => (
                      <tr key={`${i.kind}-${i.value}-${idx}`} className="hover:bg-bg-subtle/50">
                        <td className="p-3">
                          <Badge tone="neutral">{i.kind}</Badge>
                        </td>
                        <td className="p-3 font-mono text-xs break-all">{i.value}</td>
                        <td className="p-3 text-right">
                          <button
                            type="button"
                            onClick={() => copyToClipboard(i.value, i.kind)}
                            className="text-subtle hover:text-fg"
                          >
                            <Copy className="size-3.5" />
                          </button>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              )}
            </div>
          )}

          {/* TAB 6: HASHES & EVIDENCE */}
          {tab === "Hashes & Evidence" && (
            <div className="mt-6 max-w-3xl rounded-xl border border-border bg-bg-elevated p-5">
              <dl className="space-y-4 font-mono text-xs">
                <div>
                  <dt className="text-subtle">Raw Source Bytes SHA-256</dt>
                  <dd className="mt-1 break-all rounded bg-bg-subtle p-2 text-fg">{data.rawHash}</dd>
                </div>
                <div>
                  <dt className="text-subtle">Normalized Clean Text SHA-256</dt>
                  <dd className="mt-1 break-all rounded bg-bg-subtle p-2 text-fg">{data.textHash}</dd>
                </div>
                <div>
                  <dt className="text-subtle">Canonical URL</dt>
                  <dd className="mt-1 break-all rounded bg-bg-subtle p-2 text-fg">{data.canonicalUrl}</dd>
                </div>
                <div>
                  <dt className="text-subtle">Content Size</dt>
                  <dd className="mt-1 text-fg">{data.wordCount} words</dd>
                </div>
              </dl>
            </div>
          )}

          {/* TAB 7: QUALITY GATE */}
          {tab === "Quality Gate" && (
            <div className="mt-6 max-w-2xl rounded-xl border border-border bg-bg-elevated p-5">
              <div className="flex items-baseline gap-3">
                <span className="font-mono text-3xl font-medium tabular-nums">
                  {Math.round(data.qualityScore * 100)}%
                </span>
                <span className="text-xs text-muted">Heuristic Threat Signal Score</span>
              </div>

              <ul className="mt-6 space-y-2">
                {data.qualityReasons.map((r) => (
                  <li
                    key={r.label}
                    className="flex justify-between gap-4 border-b border-border py-2 text-sm"
                  >
                    <span className="text-muted">{r.label}</span>
                    <span className={r.delta < 0 ? "text-danger font-mono" : "text-sage font-mono"}>
                      {r.delta > 0 ? "+" : ""}
                      {r.delta}
                    </span>
                  </li>
                ))}
              </ul>
            </div>
          )}

          {/* TAB 8: PROVENANCE */}
          {tab === "Provenance" && (
            <div className="mt-6 max-w-3xl rounded-xl border border-border bg-bg-elevated p-5">
              <h3 className="text-sm font-medium">Intelligence Provenance Record</h3>
              <p className="text-xs text-muted">Complete audit trail of where and how this intelligence was acquired.</p>

              <dl className="mt-5 space-y-3 font-mono text-xs">
                <div className="flex justify-between border-b border-border pb-2">
                  <dt className="text-subtle">Publisher</dt>
                  <dd className="text-fg">{data.publisher || data.sourceName}</dd>
                </div>
                <div className="flex justify-between border-b border-border pb-2">
                  <dt className="text-subtle">Source Feed</dt>
                  <dd className="text-fg">{data.sourceName}</dd>
                </div>
                <div className="flex justify-between border-b border-border pb-2">
                  <dt className="text-subtle">Discovery Method</dt>
                  <dd className="text-fg">{data.discoveryMethod}</dd>
                </div>
                {data.discoveryQuery && (
                  <div className="flex justify-between border-b border-border pb-2">
                    <dt className="text-subtle">Discovery Query</dt>
                    <dd className="text-accent">{data.discoveryQuery}</dd>
                  </div>
                )}
                <div className="flex justify-between border-b border-border pb-2">
                  <dt className="text-subtle">Source Domain</dt>
                  <dd className="text-fg">{data.sourceDomain || new URL(data.url).hostname}</dd>
                </div>
                <div className="flex justify-between border-b border-border pb-2">
                  <dt className="text-subtle">Ingested At</dt>
                  <dd className="text-fg">{formatDateTime(data.ingestedAt)}</dd>
                </div>
                <div className="flex justify-between border-b border-border pb-2">
                  <dt className="text-subtle">Document Version</dt>
                  <dd className="text-fg">v{data.version}</dd>
                </div>
                {data.discoveryPath && data.discoveryPath.length > 1 && (
                  <div className="pt-2">
                    <dt className="text-subtle mb-2">Discovery Ancestry Chain</dt>
                    <dd className="space-y-1.5 pl-2 border-l-2 border-accent/40">
                      {data.discoveryPath.map((step, idx) => (
                        <div key={idx} className="flex items-center gap-2 text-[11px] truncate">
                          <span className="text-accent font-semibold">Hop {idx}:</span>
                          <a href={step} target="_blank" rel="noreferrer" className="truncate text-muted hover:text-fg">
                            {step}
                          </a>
                        </div>
                      ))}
                    </dd>
                  </div>
                )}
              </dl>
            </div>
          )}
        </>
      ) : null}
    </AppShell>
  );
}
