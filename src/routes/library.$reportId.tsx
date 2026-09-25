import { useQuery, useQueryClient } from "@tanstack/react-query";
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
  Sparkles,
  RefreshCw,
  X,
  FileCode,
  Check,
  AlertTriangle,
} from "lucide-react";
import { toast } from "sonner";
import { AppShell } from "@/components/app-shell";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { IdBadge } from "@/components/id-badge";
import { formatDomainId, formatReportId } from "@/lib/aie/ids";
import {
  getReport,
  synthesizeReportAttackChain,
  generateReportSigmaRule,
  generateReportEmulationPlan,
  evaluateReportWithAi,
} from "@/lib/aie/server";
import { formatDateTime } from "@/lib/aie/format";
import { cn } from "@/lib/cn";

export const Route = createFileRoute("/library/$reportId")({
  component: ReportPage,
});

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

  const queryClient = useQueryClient();
  const [isSynthesizing, setIsSynthesizing] = useState(false);
  const [isGeneratingSigma, setIsGeneratingSigma] = useState(false);
  const [isGeneratingEmulation, setIsGeneratingEmulation] = useState(false);
  const [isAuditingAi, setIsAuditingAi] = useState(false);
  const [sigmaModalData, setSigmaModalData] = useState<{ open: boolean; content: string; filename: string } | null>(null);
  const [emulationModalData, setEmulationModalData] = useState<{ open: boolean; content: string; filename: string } | null>(null);

  const { data, isLoading } = useQuery({
    queryKey: ["report", reportId],
    queryFn: () => getReport({ data: { id: reportId } }),
  });

  const handleSynthesizeAttackChain = async () => {
    setIsSynthesizing(true);
    toast.info("Synthesizing multi-stage attack chain and tradecraft via AI Provider...");
    try {
      const res = await synthesizeReportAttackChain({ data: { reportId } });
      if (res.success) {
        toast.success(`Attack chain synthesized (${res.analysis.attackChain.length} stages)!`);
        void queryClient.invalidateQueries({ queryKey: ["report", reportId] });
        void queryClient.invalidateQueries({ queryKey: ["reports-all"] });
        setTab("Attack Chain & TTPs");
      } else {
        toast.error("Failed to synthesize attack chain");
      }
    } catch (err: any) {
      toast.error(`Synthesis failed: ${err?.message || "Unknown error"}`);
    } finally {
      setIsSynthesizing(false);
    }
  };

  const handleGenerateSigmaRule = async () => {
    setIsGeneratingSigma(true);
    toast.info("Generating production-ready defensive Sigma YAML rule via AI Provider...");
    try {
      const res = await generateReportSigmaRule({ data: { reportId } });
      if (res.success && res.rule) {
        setSigmaModalData({
          open: true,
          content: res.rule,
          filename: res.filename || "sigma_detection_rule.yml",
        });
        toast.success("Defensive Sigma rule generated!");
      } else {
        toast.error(`Sigma generation failed: ${res.error || "No rule returned"}`);
      }
    } catch (err: any) {
      toast.error(`Sigma generation failed: ${err?.message || "Unknown error"}`);
    } finally {
      setIsGeneratingSigma(false);
    }
  };

  const handleGenerateEmulationPlan = async () => {
    setIsGeneratingEmulation(true);
    toast.info("Generating Atomic Red Team adversary emulation blueprint via AI Provider...");
    try {
      const res = await generateReportEmulationPlan({ data: { reportId, platform: "windows" } });
      if (res.success && res.plan) {
        const cleanName = (data?.title || "adversary").toLowerCase().replace(/[^a-z0-9_-]/g, "_").slice(0, 30);
        setEmulationModalData({
          open: true,
          content: res.plan,
          filename: `${cleanName}_atomic_emulation_plan.md`,
        });
        toast.success("Adversary emulation plan synthesized!");
      } else {
        toast.error(`Emulation generation failed: ${res.error || "No plan returned"}`);
      }
    } catch (err: any) {
      toast.error(`Emulation generation failed: ${err?.message || "Unknown error"}`);
    } finally {
      setIsGeneratingEmulation(false);
    }
  };

  const handleAuditReportAi = async () => {
    setIsAuditingAi(true);
    toast.info("Running cognitive 5D rubric evaluation via active AI Provider...");
    try {
      const res = await evaluateReportWithAi({ data: { id: reportId } });
      if (res.success && res.result) {
        if (res.isApproved) {
          toast.success(`Report Approved by AI Agent (${res.result.passScore}/100)!`);
        } else {
          toast.warning(`Report Flagged by AI Agent (${res.result.passScore}/100): ${res.result.rationale}`);
        }
        void queryClient.invalidateQueries({ queryKey: ["report", reportId] });
        void queryClient.invalidateQueries({ queryKey: ["reports-all"] });
      } else {
        toast.error(`Audit failed: ${res.error || "Evaluation error"}`);
      }
    } catch (err: any) {
      toast.error(`AI Audit failed: ${err?.message || "Unknown error"}`);
    } finally {
      setIsAuditingAi(false);
    }
  };

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
          search={{ selected: reportId }}
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
          {/* Standardized AIE ID Bar: RST and DOM only */}
          <div className="mt-2 flex flex-wrap items-center gap-2 p-2.5 rounded-lg border border-border/60 bg-bg-elevated/70">
            <IdBadge id={formatReportId(data.id)} category="report" size="sm" />
            {(data.sourceDomain || data.url) && (
              <IdBadge id={formatDomainId(data.sourceDomain || data.url)} category="domain" size="sm" />
            )}
          </div>

          {/* Header Metadata */}
          <div className="mt-3 flex flex-wrap items-center gap-2">
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

          {/* AI Cognitive Operations Toolbar */}
          <div className="mt-4 flex flex-wrap items-center justify-between gap-3 rounded-xl border border-accent/25 bg-accent/5 p-3.5 backdrop-blur-sm">
            <div className="flex flex-wrap items-center gap-2.5">
              <div className="flex items-center gap-1.5 text-xs font-semibold text-accent">
                <Sparkles className="size-4" />
                <span>AI Cognitive Operations:</span>
              </div>
              {data.aiVerified ? (
                <Badge tone="sage" className="gap-1 font-mono text-xs">
                  <CheckCircle2 className="size-3" />
                  AI Verified {data.aiQualityScore ? `· ${data.aiQualityScore}/100` : ""}
                </Badge>
              ) : data.status === "rejected" ? (
                <Badge tone="danger" className="gap-1 font-mono text-xs">
                  <AlertTriangle className="size-3" />
                  Rejected by AI {data.aiQualityScore ? `· ${data.aiQualityScore}/100` : ""}
                </Badge>
              ) : (
                <Badge tone="neutral" className="font-mono text-xs">
                  Pending AI Audit
                </Badge>
              )}
              <Button
                size="sm"
                variant="outline"
                className="h-7 text-xs gap-1 border-accent/30 text-accent hover:bg-accent/10"
                disabled={isAuditingAi}
                onClick={handleAuditReportAi}
                title="Execute 5-dimensional rubric scoring across Procedural Depth, Attack Progression, Attribution, Emulation, and Telemetry"
              >
                <RefreshCw className={cn("size-3", isAuditingAi && "animate-spin")} />
                <span>{isAuditingAi ? "Auditing Rubric..." : "Run AI 5D Audit"}</span>
              </Button>
            </div>

            <div className="flex flex-wrap items-center gap-2">
              <Button
                size="sm"
                variant="secondary"
                className="h-7 text-xs gap-1.5 bg-bg-elevated hover:bg-bg border border-border shadow-xs"
                disabled={isSynthesizing}
                onClick={handleSynthesizeAttackChain}
                title="Synthesize chronological attack chain stages, threat actors, and MITRE techniques using AI"
              >
                <Workflow className={cn("size-3 text-accent", isSynthesizing && "animate-spin")} />
                <span>{isSynthesizing ? "Synthesizing Chain..." : "AI Attack Chain"}</span>
              </Button>

              <Button
                size="sm"
                variant="secondary"
                className="h-7 text-xs gap-1.5 bg-bg-elevated hover:bg-bg border border-border shadow-xs"
                disabled={isGeneratingSigma}
                onClick={handleGenerateSigmaRule}
                title="Generate production-ready defensive Sigma YAML detection rule"
              >
                <Shield className={cn("size-3 text-sage", isGeneratingSigma && "animate-spin")} />
                <span>{isGeneratingSigma ? "Generating Sigma..." : "AI Sigma Rule"}</span>
              </Button>

              <Button
                size="sm"
                variant="secondary"
                className="h-7 text-xs gap-1.5 bg-bg-elevated hover:bg-bg border border-border shadow-xs"
                disabled={isGeneratingEmulation}
                onClick={handleGenerateEmulationPlan}
                title="Synthesize Atomic Red Team adversary emulation replay commands"
              >
                <Terminal className={cn("size-3 text-warn", isGeneratingEmulation && "animate-spin")} />
                <span>{isGeneratingEmulation ? "Synthesizing Plan..." : "AI Emulation Plan"}</span>
              </Button>
            </div>
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
                    sandbox="allow-scripts allow-popups"
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
                <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
                  <div>
                    <div className="flex items-center gap-2">
                      <h2 className="text-base font-medium">Reconstructed Attack Chain Sequence</h2>
                      {analysis?.method && (
                        <Badge tone={analysis.method === "ai_structured" ? "accent" : "neutral"} className="text-[10px] font-mono">
                          {analysis.method === "ai_structured" ? "AI Synthesized" : "Heuristic"}
                        </Badge>
                      )}
                    </div>
                    <p className="text-xs text-muted">
                      Chronological progression of adversary tactics and mapped MITRE ATT&CK techniques.
                    </p>
                  </div>
                  <Button
                    size="sm"
                    variant="secondary"
                    className="h-8 gap-1.5 text-xs bg-bg-elevated hover:bg-bg border border-border shrink-0"
                    disabled={isSynthesizing}
                    onClick={handleSynthesizeAttackChain}
                  >
                    <Workflow className={cn("size-3.5 text-accent", isSynthesizing && "animate-spin")} />
                    <span>{isSynthesizing ? "Synthesizing Chain..." : "Re-Synthesize Chain (AI)"}</span>
                  </Button>
                </div>

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
                <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
                  <div>
                    <div className="flex items-center gap-2">
                      <Terminal className="size-4 text-accent" />
                      <h2 className="text-base font-medium">Adversary Emulation Commands (Atomic Red Team)</h2>
                    </div>
                    <p className="mt-1 text-xs text-muted">
                      Executable tests to validate purple-team detection coverage against observed techniques.
                    </p>
                  </div>
                  <Button
                    size="sm"
                    variant="secondary"
                    className="h-8 gap-1.5 text-xs bg-bg-elevated hover:bg-bg border border-border shrink-0"
                    disabled={isGeneratingEmulation}
                    onClick={handleGenerateEmulationPlan}
                  >
                    <Zap className={cn("size-3.5 text-warn", isGeneratingEmulation && "animate-spin")} />
                    <span>{isGeneratingEmulation ? "Synthesizing Plan..." : "Generate Emulation Plan (AI)"}</span>
                  </Button>
                </div>

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
                <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
                  <div>
                    <div className="flex items-center gap-2">
                      <Shield className="size-4 text-sage" />
                      <h2 className="text-base font-medium">Detection Opportunities & Sigma Rules</h2>
                    </div>
                    <p className="mt-1 text-xs text-muted">
                      Defensive detection opportunities tailored to the adversary procedure in this report.
                    </p>
                  </div>
                  <Button
                    size="sm"
                    variant="secondary"
                    className="h-8 gap-1.5 text-xs bg-bg-elevated hover:bg-bg border border-border shrink-0"
                    disabled={isGeneratingSigma}
                    onClick={handleGenerateSigmaRule}
                  >
                    <FileCode className={cn("size-3.5 text-sage", isGeneratingSigma && "animate-spin")} />
                    <span>{isGeneratingSigma ? "Generating Sigma..." : "Generate Sigma Rule (AI)"}</span>
                  </Button>
                </div>

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
              <div className="flex items-center justify-between border-b border-border pb-3 mb-4">
                <span className="font-mono text-[11px] text-subtle">
                  Clean Extracted Text ({data.wordCount} words)
                </span>
                <Button
                  size="sm"
                  variant="secondary"
                  className="h-7 text-xs gap-1"
                  onClick={() => copyToClipboard(data.extractedText, "Extracted text")}
                >
                  <Copy className="size-3" />
                  <span>Copy Text</span>
                </Button>
              </div>
              <pre className="whitespace-pre-wrap font-sans text-sm leading-relaxed text-muted select-text">
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

              {/* Cognitive 5D Rubric Breakdown */}
              {data.scoreBreakdown && (
                <div className="mt-6 pt-5 border-t border-border">
                  <div className="flex items-center justify-between">
                    <span className="text-xs font-semibold text-accent uppercase tracking-wider">
                      Cognitive 5-Dimensional Tradecraft Rubric
                    </span>
                    <span className="font-mono text-xs font-bold text-fg">
                      {data.scoreBreakdown.totalScore} / 100
                    </span>
                  </div>

                  <div className="mt-4 space-y-3">
                    <div>
                      <div className="flex justify-between text-xs mb-1">
                        <span className="text-muted">Procedural Depth (Execution, LOLBins, APIs)</span>
                        <span className="font-mono text-fg">{data.scoreBreakdown.proceduralDepth} / 30</span>
                      </div>
                      <div className="h-1.5 w-full bg-bg-subtle rounded-full overflow-hidden">
                        <div
                          className="h-full bg-accent rounded-full transition-all"
                          style={{ width: `${(data.scoreBreakdown.proceduralDepth / 30) * 100}%` }}
                        />
                      </div>
                    </div>

                    <div>
                      <div className="flex justify-between text-xs mb-1">
                        <span className="text-muted">Attack Progression (Multi-stage Kill Chain)</span>
                        <span className="font-mono text-fg">{data.scoreBreakdown.attackProgression} / 25</span>
                      </div>
                      <div className="h-1.5 w-full bg-bg-subtle rounded-full overflow-hidden">
                        <div
                          className="h-full bg-accent rounded-full transition-all"
                          style={{ width: `${(data.scoreBreakdown.attackProgression / 25) * 100}%` }}
                        />
                      </div>
                    </div>

                    <div>
                      <div className="flex justify-between text-xs mb-1">
                        <span className="text-muted">Attribution & Context (Actors, Malware, CVEs)</span>
                        <span className="font-mono text-fg">{data.scoreBreakdown.attributionContext} / 15</span>
                      </div>
                      <div className="h-1.5 w-full bg-bg-subtle rounded-full overflow-hidden">
                        <div
                          className="h-full bg-accent rounded-full transition-all"
                          style={{ width: `${(data.scoreBreakdown.attributionContext / 15) * 100}%` }}
                        />
                      </div>
                    </div>

                    <div>
                      <div className="flex justify-between text-xs mb-1">
                        <span className="text-muted">Emulation Utility (Atomic Red Team, Detections)</span>
                        <span className="font-mono text-fg">{data.scoreBreakdown.emulationUtility} / 20</span>
                      </div>
                      <div className="h-1.5 w-full bg-bg-subtle rounded-full overflow-hidden">
                        <div
                          className="h-full bg-accent rounded-full transition-all"
                          style={{ width: `${(data.scoreBreakdown.emulationUtility / 20) * 100}%` }}
                        />
                      </div>
                    </div>

                    <div>
                      <div className="flex justify-between text-xs mb-1">
                        <span className="text-muted">IOC & Telemetry Verifiability</span>
                        <span className="font-mono text-fg">{data.scoreBreakdown.iocVerifiability} / 10</span>
                      </div>
                      <div className="h-1.5 w-full bg-bg-subtle rounded-full overflow-hidden">
                        <div
                          className="h-full bg-accent rounded-full transition-all"
                          style={{ width: `${(data.scoreBreakdown.iocVerifiability / 10) * 100}%` }}
                        />
                      </div>
                    </div>
                  </div>

                  {data.aiAuditReason && (
                    <div className="mt-4 p-3 rounded-lg bg-bg-subtle border border-border text-xs text-muted">
                      <span className="font-semibold text-fg">AI Audit Rationale: </span>
                      {data.aiAuditReason}
                    </div>
                  )}
                </div>
              )}
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
      {/* AI SIGMA RULE MODAL */}
      {sigmaModalData && sigmaModalData.open && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/75 p-4 backdrop-blur-sm">
          <div className="flex w-full max-w-3xl flex-col rounded-2xl border border-border bg-bg-elevated shadow-2xl overflow-hidden animate-in fade-in zoom-in-95 duration-150 max-h-[85vh]">
            <div className="flex items-center justify-between border-b border-border bg-bg px-5 py-3.5">
              <div className="flex items-center gap-2.5">
                <div className="flex size-8 items-center justify-center rounded-lg bg-sage/15 text-sage border border-sage/30">
                  <Shield className="size-4" />
                </div>
                <div>
                  <h3 className="text-sm font-semibold text-fg">Defensive Sigma Rule (YAML)</h3>
                  <p className="text-xs text-muted font-mono">{sigmaModalData.filename}</p>
                </div>
              </div>
              <div className="flex items-center gap-2">
                <Button
                  size="sm"
                  variant="secondary"
                  className="h-8 gap-1.5 text-xs"
                  onClick={() => copyToClipboard(sigmaModalData.content, "Sigma YAML")}
                >
                  <Copy className="size-3.5" />
                  <span>Copy YAML</span>
                </Button>
                <Button
                  size="sm"
                  className="h-8 gap-1.5 text-xs"
                  onClick={() => {
                    const blob = new Blob([sigmaModalData.content], { type: "text/yaml;charset=utf-8" });
                    const dlUrl = URL.createObjectURL(blob);
                    const a = document.createElement("a");
                    a.href = dlUrl;
                    a.download = sigmaModalData.filename;
                    a.click();
                    URL.revokeObjectURL(dlUrl);
                    toast.success("Sigma Rule downloaded");
                  }}
                >
                  <Download className="size-3.5" />
                  <span>Download .yml</span>
                </Button>
                <button
                  type="button"
                  onClick={() => setSigmaModalData(null)}
                  className="flex size-8 items-center justify-center rounded-lg text-muted hover:bg-bg-subtle hover:text-fg transition-colors"
                >
                  <X className="size-4" />
                </button>
              </div>
            </div>
            <div className="flex-1 overflow-auto p-4 bg-neutral-950 font-mono text-xs text-neutral-200 select-text leading-relaxed">
              <pre className="whitespace-pre-wrap">{sigmaModalData.content}</pre>
            </div>
          </div>
        </div>
      )}

      {/* AI ADVERSARY EMULATION PLAN MODAL */}
      {emulationModalData && emulationModalData.open && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/75 p-4 backdrop-blur-sm">
          <div className="flex w-full max-w-4xl flex-col rounded-2xl border border-border bg-bg-elevated shadow-2xl overflow-hidden animate-in fade-in zoom-in-95 duration-150 max-h-[85vh]">
            <div className="flex items-center justify-between border-b border-border bg-bg px-5 py-3.5">
              <div className="flex items-center gap-2.5">
                <div className="flex size-8 items-center justify-center rounded-lg bg-warn/15 text-warn border border-warn/30">
                  <Terminal className="size-4" />
                </div>
                <div>
                  <h3 className="text-sm font-semibold text-fg">Adversary Emulation Execution Plan (Atomic Red Team)</h3>
                  <p className="text-xs text-muted font-mono">{emulationModalData.filename}</p>
                </div>
              </div>
              <div className="flex items-center gap-2">
                <Button
                  size="sm"
                  variant="secondary"
                  className="h-8 gap-1.5 text-xs"
                  onClick={() => copyToClipboard(emulationModalData.content, "Emulation Plan")}
                >
                  <Copy className="size-3.5" />
                  <span>Copy Markdown</span>
                </Button>
                <Button
                  size="sm"
                  className="h-8 gap-1.5 text-xs"
                  onClick={() => {
                    const blob = new Blob([emulationModalData.content], { type: "text/markdown;charset=utf-8" });
                    const dlUrl = URL.createObjectURL(blob);
                    const a = document.createElement("a");
                    a.href = dlUrl;
                    a.download = emulationModalData.filename;
                    a.click();
                    URL.revokeObjectURL(dlUrl);
                    toast.success("Emulation Plan downloaded");
                  }}
                >
                  <Download className="size-3.5" />
                  <span>Download .md</span>
                </Button>
                <button
                  type="button"
                  onClick={() => setEmulationModalData(null)}
                  className="flex size-8 items-center justify-center rounded-lg text-muted hover:bg-bg-subtle hover:text-fg transition-colors"
                >
                  <X className="size-4" />
                </button>
              </div>
            </div>
            <div className="flex-1 overflow-auto p-5 bg-neutral-950 font-mono text-xs text-neutral-200 select-text leading-relaxed">
              <pre className="whitespace-pre-wrap">{emulationModalData.content}</pre>
            </div>
          </div>
        </div>
      )}
    </AppShell>
  );
}
