import { useQuery } from "@tanstack/react-query";
import { createFileRoute, useNavigate } from "@tanstack/react-router";
import { useMemo, useState, type ReactNode } from "react";
import { z } from "zod";
import type { ColumnDef } from "@tanstack/react-table";
import {
  ArrowUpRight,
  Copy,
  Download,
  ExternalLink,
  FileText,
  FileX,
  Link2,
  Maximize2,
  Minimize2,
  Printer,
  Shield,
  Sparkles,
  Swords,
} from "lucide-react";
import { toast } from "sonner";
import { AppShell } from "@/components/app-shell";
import { EvidencePanel } from "@/components/evidence/evidence-panel";
import { ActivitySpinner } from "@/components/ui/activity-spinner";
import { DataTable, type DataTableColumnMeta } from "@/components/ui/data-table";
import { EmptyState, Meter, PropertyList, StatusChip } from "@/components/ui/primitives";
import { ActionButton, SegmentedTabs } from "@/components/layout/page";
import { DetailPageTemplate } from "@/components/templates/page-templates";
import { ActionMenu } from "@/components/library/action-menu";
import { AiReviewDialog } from "@/components/library/ai-review-dialog";
import { aiReview, downloadHtml, formatDate, kindLabel, printHtml, qualityTone } from "@/components/library/report-utils";
import { formatReportId } from "@/lib/aie/ids";
import { getReport } from "@/lib/aie/server";
import { formatDateTime } from "@/lib/aie/format";
import { cn } from "@/lib/cn";
import { toSafeSrcDoc } from "@/lib/aie/safe-srcdoc";
import type { IocHit } from "@/lib/aie/types";
import { DocTypeBadge, EntityChip, EntityIcon, type EntityKind } from "@/components/ui/entity";
import { TierDot } from "@/components/library/report-card";
import { AttackCoverageStrip } from "@/components/library/attack-coverage";
import { StructuredPanel } from "@/components/library/structured-panel";
import { ReportEmulation } from "@/components/library/report-emulation";
import { CollectionRecord } from "@/components/library/collection-record";
import { TIER_META, actorsOf, cvesOf, docTypesOf, malwareOf, techniquesOf, tierOf } from "@/components/library/intel-taxonomy";
import { DOC_TYPE_META } from "@/components/ui/entity";

const TABS = [
  { value: "overview", label: "Overview" },
  { value: "document", label: "Document" },
  { value: "attack-chain", label: "Attack chain" },
  { value: "emulation", label: "Emulation" },
  { value: "evidence", label: "Evidence" },
  { value: "iocs", label: "IOCs" },
  { value: "detections", label: "Detections" },
  { value: "text", label: "Extracted text" },
  { value: "provenance", label: "Provenance" },
] as const;
type TabValue = (typeof TABS)[number]["value"];

const searchSchema = z.object({
  tab: z.enum(TABS.map((t) => t.value) as [TabValue, ...TabValue[]]).optional(),
});

// Non-nested route (library_): renders on its own page at /library/$reportId instead of inside /library.
export const Route = createFileRoute("/library_/$reportId")({
  validateSearch: (search) => searchSchema.parse(search),
  component: ReportPage,
});

function Section({ title, description, actions, children }: { title: ReactNode; description?: ReactNode; actions?: ReactNode; children: ReactNode }) {
  return (
    <section className="border-t border-border pt-8 first:border-t-0 first:pt-0">
      <div className="mb-4 flex flex-wrap items-start justify-between gap-3">
        <div className="min-w-0">
          <h2 className="text-xl font-semibold tracking-tight text-fg">{title}</h2>
          {description && <p className="mt-1.5 max-w-3xl text-sm text-muted">{description}</p>}
        </div>
        {actions && <div className="flex flex-wrap items-center gap-2">{actions}</div>}
      </div>
      {children}
    </section>
  );
}

function InlineList({ items, empty }: { items: string[] | undefined; empty: string }) {
  if (!items || items.length === 0) return <span className="text-subtle">{empty}</span>;
  return (
    <div className="flex flex-wrap gap-1.5">
      {items.map((i) => (
        <span key={i} className="rounded-md bg-bg-subtle px-2 py-0.5 text-sm text-fg">
          {i}
        </span>
      ))}
    </div>
  );
}

function EntityCard({ kind, title, items, empty }: { kind: EntityKind; title: string; items: string[]; empty: string }) {
  return (
    <div className="rounded-xl border border-border bg-bg-card p-4">
      <div className="mb-3 flex items-center gap-2.5">
        <EntityIcon kind={kind} size="sm" />
        <h3 className="text-sm font-medium text-fg">{title}</h3>
        <span className="ml-auto font-mono text-[11px] tabular-nums text-subtle">{items.length}</span>
      </div>
      {items.length ? (
        <div className="flex flex-wrap gap-1.5">
          {items.map((i) => (
            <EntityChip key={i} kind={kind}>
              {i}
            </EntityChip>
          ))}
        </div>
      ) : (
        <p className="text-sm text-subtle">{empty}</p>
      )}
    </div>
  );
}

function CopyButton({ value, label }: { value: string; label: string }) {
  return (
    <button
      type="button"
      aria-label={`Copy ${label}`}
      title={`Copy ${label}`}
      onClick={() => {
        void navigator.clipboard.writeText(value);
        toast.success(`Copied ${label}`);
      }}
      className="inline-flex size-7 shrink-0 items-center justify-center rounded-md text-muted transition-colors hover:bg-bg-subtle hover:text-fg"
    >
      <Copy className="size-3.5" strokeWidth={1.75} />
    </button>
  );
}

function shortUrl(u: string): string {
  return u.replace(/^https?:\/\//, "").replace(/^www\./, "");
}

function ReportPage() {
  const { reportId } = Route.useParams();
  const search = Route.useSearch();
  const navigate = useNavigate({ from: "/library/$reportId" });
  const tab: TabValue = search.tab ?? "overview";
  const setTab = (t: TabValue) =>
    void navigate({ search: (prev) => ({ ...prev, tab: t === "overview" ? undefined : t }), replace: true });
  const [expanded, setExpanded] = useState(false);
  const [aiOpen, setAiOpen] = useState(false);

  const { data, isLoading, isError, error } = useQuery({
    queryKey: ["report", reportId],
    queryFn: () => getReport({ data: { id: reportId } }),
  });

  const copy = (text: string, label: string) => {
    void navigator.clipboard.writeText(text);
    toast.success(`Copied ${label}`);
  };

  const downloadDocument = () => {
    if (!data?.rawHtml) {
      toast.error("Document content not available");
      return;
    }
    downloadHtml(data.rawHtml, data.title);
    toast.success("Document downloaded", {
      description: "Open it in a browser and choose Print → Save as PDF for a vector PDF.",
    });
  };

  const printDocument = () => {
    if (!data?.rawHtml) {
      toast.error("Document content not available");
      return;
    }
    if (!printHtml(data.rawHtml)) toast.info("Pop-up blocked. Allow pop-ups to print to PDF.");
  };

  const analysis = data?.analysis;
  const review = data ? aiReview(data) : null;

  const summary = useMemo(() => {
    const text = (data?.extractedText ?? "").trim();
    if (!text) return "";
    const paras = text.split(/\n{2,}/).map((p) => p.trim()).filter((p) => p.length > 60);
    const out: string[] = [];
    let len = 0;
    for (const p of paras.length ? paras : [text]) {
      out.push(p);
      len += p.length;
      if (len > 700) break;
    }
    const joined = out.join("\n\n");
    return joined.length > 1100 ? `${joined.slice(0, 1100).trimEnd()}…` : joined;
  }, [data?.extractedText]);

  const techniques = useMemo(() => (data ? techniquesOf(data) : []), [data]);

  const aiSubject = useMemo(
    () => (aiOpen && data ? { ...data, iocCount: data.iocs.length } : null),
    [aiOpen, data],
  );

  const iocColumns = useMemo<ColumnDef<IocHit, any>[]>(
    () => [
      {
        id: "kind",
        accessorKey: "kind",
        header: "Type",
        cell: ({ row }) => <span className="whitespace-nowrap text-muted">{row.original.kind}</span>,
        meta: { className: "w-40" } satisfies DataTableColumnMeta,
      },
      {
        id: "value",
        accessorKey: "value",
        header: "Value",
        cell: ({ row }) => <span className="break-all font-mono text-[13px] text-fg">{row.original.value}</span>,
      },
      {
        id: "copy",
        enableSorting: false,
        header: () => <span className="sr-only">Copy</span>,
        cell: ({ row }) => <CopyButton value={row.original.value} label={row.original.kind} />,
        meta: { align: "right", className: "w-12" } satisfies DataTableColumnMeta,
      },
    ],
    [],
  );

  if (isLoading) {
    return (
      <AppShell>
        <div className="flex flex-col items-center justify-center py-24 text-muted">
          <ActivitySpinner size="lg" className="mb-2 text-accent" />
          <p className="text-sm">Loading report…</p>
        </div>
      </AppShell>
    );
  }

  if (!data) {
    return (
      <AppShell>
        <DetailPageTemplate header={{ backTo: "/library", icon: FileText, title: "Report not found" }}>
          <EmptyState
            icon={FileX}
            title={isError ? "Could not load this report" : "This report does not exist"}
            description={
              isError
                ? String((error as Error | null)?.message ?? "Unknown error")
                : `No report matches “${reportId}”. It may have been removed or merged into another record.`
            }
            action={<ActionButton to="/library">Back to library</ActionButton>}
          />
        </DetailPageTemplate>
      </AppShell>
    );
  }

  const original = data.url;
  const norm = (u: string) => shortUrl(u).replace(/\/+$/, "").toLowerCase();
  const canonical = data.canonicalUrl && (!original || norm(data.canonicalUrl) !== norm(original)) ? data.canonicalUrl : null;
  const publisher = data.publisher || data.sourceName || null;
  const actors = actorsOf(data);
  const malware = malwareOf(data);
  const cves = cvesOf(data);
  const docTypes = docTypesOf(data);
  const tier = tierOf(data);
  const reportedOrder = analysis?.evidence?.chain?.orderBasis === "reported";

  return (
    <AppShell>
      <DetailPageTemplate
        header={{
          backTo: "/library",
          icon: FileText,
          title: <span className="line-clamp-3 whitespace-normal">{data.title}</span>,
          description: (
            <span className="mt-1.5 flex flex-wrap items-center gap-x-3 gap-y-1.5">
              {docTypes.map((t) => (
                <DocTypeBadge key={t} type={t} />
              ))}
              <span className="inline-flex items-center gap-1.5 text-muted">
                <TierDot tier={tier} withLabel />
              </span>
              {publisher && <span className="font-medium text-fg">{publisher}</span>}
              {formatDate(data.publishedAt) && <span className="tabular-nums text-subtle">{formatDate(data.publishedAt)}</span>}
            </span>
          ),
          actions: (
            <div className="flex flex-wrap items-center gap-2 whitespace-nowrap md:flex-nowrap">
              <ActionButton icon={Printer} onClick={printDocument}>
                Print
              </ActionButton>
              {original && (
                <a
                  href={original}
                  target="_blank"
                  rel="noreferrer"
                  className="inline-flex h-9 items-center gap-2 rounded-lg border border-border bg-bg-elevated px-3 text-sm font-medium text-fg transition-colors hover:bg-bg-subtle"
                >
                  <ArrowUpRight className="size-4" strokeWidth={1.75} />
                  Open original
                </a>
              )}
              <ActionButton variant="primary" icon={Download} onClick={downloadDocument}>
                Download PDF
              </ActionButton>
              <ActionMenu
                label="More report actions"
                size="md"
                items={[
                  { label: "AI review", icon: Sparkles, onSelect: () => setAiOpen(true) },
                  { label: "View evidence", icon: Shield, onSelect: () => setTab("evidence") },
                  "separator",
                  { label: "Copy link", icon: Link2, onSelect: () => copy(window.location.href.split("?")[0], "link") },
                  { label: "Copy report ID", icon: Copy, onSelect: () => copy(formatReportId(data.id), "report ID") },
                ]}
              />
            </div>
          ),
          tabs: (
            <SegmentedTabs
              ariaLabel="Report sections"
              items={TABS.map((t) => ({
                value: t.value,
                label: t.label,
                count:
                  t.value === "iocs"
                    ? data.iocs.length
                    : t.value === "attack-chain"
                      ? (analysis?.attackChain?.length ?? 0)
                      : t.value === "emulation"
                        ? techniques.length
                        : undefined,
              }))}
              value={tab}
              onChange={setTab}
            />
          ),
        }}
        properties={
          <>
            <PropertyList
              items={[
                {
                  label: "ID",
                  value: (
                    <span className="inline-flex items-center gap-1">
                      <span className="font-mono text-[13px]">{formatReportId(data.id)}</span>
                      <CopyButton value={formatReportId(data.id)} label="report ID" />
                    </span>
                  ),
                },
                { label: "Publisher", value: publisher },
                { label: "Published", value: formatDate(data.publishedAt) },
                { label: "Ingested", value: formatDate(data.ingestedAt) ?? formatDateTime(data.ingestedAt) },
                { label: "Source", value: data.sourceName || data.sourceDomain || null },
                {
                  label: "Document type",
                  value: docTypes.map((t) => DOC_TYPE_META[t]?.label ?? t).join(", "),
                },
                {
                  label: "Source tier",
                  value: tier ? TIER_META[tier].label : <span className="text-subtle">Unrated (not a registry source)</span>,
                },
                {
                  label: "Source confidence",
                  hidden: typeof data.sourceConfidence !== "number",
                  value: <span className="tabular-nums">{Math.round((data.sourceConfidence ?? 0) * 100)}%</span>,
                },
                { label: "Content profile", value: kindLabel(data.resourceKind, data.classification) },
                {
                  label: "Classification",
                  value: data.classification || null,
                  hidden: !data.classification || kindLabel(data.resourceKind, data.classification) === kindLabel(undefined, data.classification),
                },
                {
                  label: "Quality",
                  value: (
                    <span className="flex items-center gap-2.5">
                      <span className="w-24">
                        <Meter value={data.qualityScore} tone={qualityTone(data.qualityScore)} label="Quality score" />
                      </span>
                      <span className="tabular-nums">{Math.round(data.qualityScore * 100)}%</span>
                    </span>
                  ),
                },
                { label: "Words", value: <span className="tabular-nums">{data.wordCount.toLocaleString()}</span> },
                {
                  label: "AI review",
                  value: review ? (
                    <button type="button" onClick={() => setAiOpen(true)} title="Open AI review">
                      <StatusChip tone={review.tone} dot>
                        {review.label}
                        {review.detail ? ` · ${review.detail}` : ""}
                      </StatusChip>
                    </button>
                  ) : null,
                },
                {
                  label: "Content hash",
                  hidden: !data.textHash,
                  value: (
                    <span className="inline-flex items-center gap-1">
                      <span className="font-mono text-[13px]" title={data.textHash}>
                        {data.textHash.slice(0, 12)}…
                      </span>
                      <CopyButton value={data.textHash} label="content hash" />
                    </span>
                  ),
                },
              ]}
            />
            <section className="border-t border-border pt-6">
              <h2 className="mb-3 text-base font-medium text-fg">References</h2>
              <ul className="space-y-2 text-sm">
                {[original, canonical].filter(Boolean).map((u) => (
                  <li key={u}>
                    <a
                      href={u!}
                      target="_blank"
                      rel="noreferrer"
                      className="group flex min-w-0 items-center gap-1.5 text-accent hover:underline"
                    >
                      <span className="truncate">{shortUrl(u!)}</span>
                      <ExternalLink className="size-3.5 shrink-0" />
                    </a>
                  </li>
                ))}
              </ul>
            </section>
          </>
        }
      >
        {tab === "overview" && (
          <>
            <Section title="Summary" actions={data.extractedText ? <ActionButton variant="ghost" onClick={() => setTab("text")}>Read full text</ActionButton> : undefined}>
              {summary ? (
                <div className="space-y-3 text-[15px] leading-relaxed text-muted">
                  {summary.split(/\n{2,}/).map((p, i) => (
                    <p key={i}>{p}</p>
                  ))}
                </div>
              ) : (
                <p className="text-sm text-subtle">No extracted text stored for this report.</p>
              )}
            </Section>

            {data.structured && (
              <Section title="Structured intelligence" description="Fields parsed from the structured source record.">
                <StructuredPanel data={data.structured} />
              </Section>
            )}

            <Section title="Threat context" description="Entities named in the analysis of this report.">
              <div className="grid gap-3 md:grid-cols-3">
                <EntityCard kind="actor" title="Threat actors" items={actors} empty="Unattributed or commodity activity" />
                <EntityCard kind="malware" title="Malware & tools" items={malware} empty="No named malware" />
                <EntityCard kind="cve" title="Vulnerabilities" items={cves} empty="No CVEs referenced" />
              </div>
              {data.tags && data.tags.length > 0 && (
                <div className="mt-4 flex flex-wrap items-center gap-2 text-sm">
                  <span className="text-muted">Tags</span>
                  <InlineList items={data.tags} empty="" />
                </div>
              )}
            </Section>

            <Section
              title="ATT&CK coverage"
              description="Techniques mapped from this report, grouped by enterprise tactic."
              actions={
                techniques.length > 0 ? (
                  <ActionButton icon={Swords} onClick={() => setTab("emulation")}>
                    Plan emulation
                  </ActionButton>
                ) : undefined
              }
            >
              {techniques.length > 0 ? (
                <>
                  <AttackCoverageStrip techniques={techniques} onSelectTactic={() => setTab("attack-chain")} />
                  <div className="mt-4 flex flex-wrap gap-1.5">
                    {techniques.map((t) => (
                      <EntityChip key={t.id} kind="technique" title={`${t.id}${t.name ? ` · ${t.name}` : ""} (${t.label})`}>
                        {t.id}
                        {t.name && <span className="font-normal opacity-80"> {t.name}</span>}
                      </EntityChip>
                    ))}
                  </div>
                </>
              ) : (
                <p className="text-sm text-subtle">No ATT&CK techniques mapped for this report.</p>
              )}
            </Section>

            <Section
              title="Quality gate"
              description="Heuristic threat-signal score from the ingest pipeline. Each factor adds to or subtracts from the score."
            >
              <div className="mb-4 flex items-baseline gap-3">
                <span className="text-[32px] font-semibold leading-none tabular-nums text-fg">
                  {Math.round(data.qualityScore * 100)}%
                </span>
                <span className="text-sm text-muted">quality score</span>
              </div>
              {data.qualityReasons.length > 0 ? (
                <ul className="divide-y divide-border rounded-xl border border-border bg-bg-card">
                  {data.qualityReasons.map((r) => (
                    <li key={r.label} className="flex justify-between gap-4 px-4 py-2.5 text-sm">
                      <span className="text-muted">{r.label}</span>
                      <span className={cn("tabular-nums", r.delta < 0 ? "text-danger" : "text-sage")}>
                        {r.delta > 0 ? "+" : ""}
                        {r.delta}
                      </span>
                    </li>
                  ))}
                </ul>
              ) : (
                <p className="text-sm text-subtle">No scoring factors stored.</p>
              )}
            </Section>

            <Section
              title="AI review"
              actions={
                <ActionButton icon={Sparkles} onClick={() => setAiOpen(true)}>
                  Open AI review
                </ActionButton>
              }
            >
              <div className="space-y-3 text-sm">
                {review && (
                  <StatusChip tone={review.tone} dot>
                    {review.label}
                    {review.detail ? ` · ${review.detail}` : ""}
                  </StatusChip>
                )}
                <p className="max-w-3xl leading-relaxed text-muted">
                  {data.aiAuditReason || "This report has not been evaluated by the AI quality gate yet."}
                </p>
              </div>
            </Section>
          </>
        )}

        {tab === "document" && (
          <Section
            title="Document"
            description="The stored document layout: headings, tables, code blocks and figures as published."
            actions={
              <ActionButton icon={expanded ? Minimize2 : Maximize2} onClick={() => setExpanded(!expanded)}>
                {expanded ? "Standard height" : "Expand"}
              </ActionButton>
            }
          >
            <div
              className={cn(
                "overflow-hidden rounded-xl border border-border bg-white transition-all",
                expanded ? "h-[90vh]" : "h-[min(750px,75vh)]",
              )}
            >
              {data.rawHtml ? (
                <iframe srcDoc={toSafeSrcDoc(data.rawHtml)} title={data.title} className="size-full border-0" sandbox="" />
              ) : (
                <div className="flex size-full items-center justify-center bg-bg-card p-8 text-sm text-muted">
                  No document layout stored. See the Extracted text tab.
                </div>
              )}
            </div>
          </Section>
        )}

        {tab === "attack-chain" && (
          <>
            <Section
              title="Attack chain"
              description="Tactics and mapped ATT&CK techniques as summarised by the analysis. Step order is not a verified timeline; see Evidence for the order reported in the source and the supporting passages."
            >
              {!analysis?.attackChain || analysis.attackChain.length === 0 ? (
                <EmptyState title="No multi-stage attack chain observed" className="rounded-xl border border-border bg-bg-card" />
              ) : (
                <ol className="divide-y divide-border rounded-xl border border-border bg-bg-card">
                  {analysis.attackChain.map((step) => (
                    <li key={step.order} className="flex gap-4 px-5 py-4">
                      <span className="flex size-7 shrink-0 items-center justify-center rounded-full bg-bg-subtle text-xs font-medium tabular-nums text-muted">
                        {step.order}
                      </span>
                      <div className="min-w-0 flex-1">
                        <p className="text-sm font-medium text-fg">{step.tactic}</p>
                        <p className="mt-1 text-sm text-muted">{step.summary}</p>
                        {step.techniques.length > 0 && (
                          <p className="mt-2 flex flex-wrap gap-1.5">
                            {step.techniques.map((tech) => {
                              const m = tech.match(/^(T\d{4}(?:\.\d{3})?)\s*[-–:]\s*(.+)$/);
                              return (
                                <span key={tech} className="inline-flex items-center gap-1.5 rounded-md bg-bg-subtle px-2 py-0.5 text-xs text-fg">
                                  <span className="font-mono text-muted">{m ? m[1] : tech}</span>
                                  {m && <span>{m[2]}</span>}
                                </span>
                              );
                            })}
                          </p>
                        )}
                      </div>
                    </li>
                  ))}
                </ol>
              )}
            </Section>

            <Section title="Adversary">
              <dl className="grid grid-cols-1 gap-x-6 gap-y-4 text-sm sm:grid-cols-[10rem_minmax(0,1fr)]">
                <dt className="text-muted">Threat actors</dt>
                <dd>
                  <InlineList items={actors} empty="Unattributed or commodity activity" />
                </dd>
                <dt className="text-muted">Malware and tools</dt>
                <dd>
                  <InlineList items={malware} empty="No named malware" />
                </dd>
              </dl>
            </Section>

            {analysis?.ioas && analysis.ioas.length > 0 && (
              <Section title="Indicators of attack" description="Behavioural signatures described in the report.">
                <ul className="list-disc space-y-2 pl-5 text-sm text-muted marker:text-subtle">
                  {analysis.ioas.map((ioa, idx) => (
                    <li key={idx}>{ioa}</li>
                  ))}
                </ul>
              </Section>
            )}
          </>
        )}

        {tab === "emulation" && (
          <ReportEmulation reportId={data.id} title={data.title} url={data.canonicalUrl || data.url} techniques={techniques} reportedOrder={reportedOrder} />
        )}

        {tab === "evidence" && (
          <EvidencePanel analysis={analysis} iocs={data.iocs} extractedText={data.extractedText} />
        )}

        {tab === "iocs" && (
          <Section title="Indicators of compromise" description={`${data.iocs.length} indicators extracted from the document.`}>
            <DataTable
              data={data.iocs}
              columns={iocColumns}
              getRowId={(i) => `${i.kind}:${i.value}`}
              dense
              caption="Indicators of compromise"
              empty={<EmptyState title="No IOCs found in this document" />}
            />
          </Section>
        )}

        {tab === "detections" && (
          <>
            <Section
              title="Detection ideas"
              description="Sigma-style drafts generated for the procedure in this report; not tested rules. Validate against your telemetry before deploying."
            >
              {analysis?.detections && analysis.detections.length > 0 ? (
                <ul className="divide-y divide-border rounded-xl border border-border bg-bg-card">
                  {analysis.detections.map((d, idx) => (
                    <li key={idx} className="flex items-start justify-between gap-3 px-4 py-3">
                      <span className="min-w-0 break-words font-mono text-[13px] text-fg">{d}</span>
                      <CopyButton value={d} label="detection idea" />
                    </li>
                  ))}
                </ul>
              ) : (
                <p className="text-sm text-subtle">No detection ideas generated.</p>
              )}
            </Section>

            <Section
              title="Emulation ideas"
              description="Atomic Red Team–style drafts for purple-team planning; not vetted tests. Review and adapt before running anything in a lab."
            >
              {analysis?.emulation && analysis.emulation.length > 0 ? (
                <div className="space-y-3">
                  {analysis.emulation.map((cmd, idx) => (
                    <div key={idx} className="rounded-xl border border-border bg-bg-card">
                      <div className="flex items-center justify-between gap-2 border-b border-border px-4 py-2">
                        <span className="text-xs text-muted">Draft {idx + 1}</span>
                        <CopyButton value={cmd} label="emulation command" />
                      </div>
                      <pre className="overflow-x-auto px-4 py-3 font-mono text-xs text-fg">{cmd}</pre>
                    </div>
                  ))}
                </div>
              ) : (
                <p className="text-sm text-subtle">No emulation commands mapped.</p>
              )}
            </Section>

            <Section title="Hunting hypotheses" description="Search patterns to try across EDR and SIEM logs (drafts).">
              {analysis?.hunting && analysis.hunting.length > 0 ? (
                <ul className="list-disc space-y-2 pl-5 text-sm text-muted marker:text-subtle">
                  {analysis.hunting.map((h, idx) => (
                    <li key={idx}>{h}</li>
                  ))}
                </ul>
              ) : (
                <p className="text-sm text-subtle">No hunting hypotheses generated.</p>
              )}
            </Section>
          </>
        )}

        {tab === "text" && (
          <Section
            title="Extracted text"
            description={`${data.wordCount.toLocaleString()} words of normalized text.`}
            actions={
              <ActionButton icon={Copy} onClick={() => copy(data.extractedText, "extracted text")}>
                Copy text
              </ActionButton>
            }
          >
            <pre className="select-text whitespace-pre-wrap rounded-xl border border-border bg-bg-card p-5 font-sans text-sm leading-relaxed text-muted">
              {data.extractedText || "No extracted text stored."}
            </pre>
          </Section>
        )}

        {tab === "provenance" && (
          <>
            <Section title="Provenance" description="Where and how this intelligence was acquired.">
              <PropertyList
                title={null}
                items={[
                  { label: "Publisher", value: publisher },
                  { label: "Source feed", value: data.sourceName || null },
                  { label: "Discovery method", value: data.discoveryMethod?.replace(/_/g, " ") || null },
                  { label: "Discovery query", value: data.discoveryQuery || null, hidden: !data.discoveryQuery },
                  { label: "Ingest origin", value: data.ingestOrigin || null },
                  { label: "Source domain", value: data.sourceDomain || null },
                  { label: "Content type", value: data.contentType || null },
                  { label: "Ingested at", value: formatDateTime(data.ingestedAt) },
                  { label: "Document version", value: `v${data.version}` },
                ]}
              />
              {data.discoveryPath && data.discoveryPath.length > 1 && (
                <div className="mt-6">
                  <h3 className="mb-2 text-sm font-medium text-fg">Discovery path</h3>
                  <ol className="space-y-1.5 border-l border-border pl-4 text-sm">
                    {data.discoveryPath.map((step, idx) => (
                      <li key={idx} className="flex min-w-0 items-center gap-2">
                        <span className="shrink-0 text-xs tabular-nums text-subtle">Hop {idx}</span>
                        <a href={step} target="_blank" rel="noreferrer" className="truncate text-muted hover:text-fg">
                          {step}
                        </a>
                      </li>
                    ))}
                  </ol>
                </div>
              )}
            </Section>

            <Section title="Collection record" description="What the collector recorded: ATT&CK entities recognised at ingest, mirrors, content versions, attached PDFs and the pre-fetch relevance score.">
              <CollectionRecord reportId={data.id} />
            </Section>

            <Section title="Hashes" description="Integrity fingerprints for the stored source and its normalized text.">
              <dl className="space-y-4 text-sm">
                {(
                  [
                    ["Raw source bytes (SHA-256)", data.rawHash],
                    ["Normalized text (SHA-256)", data.textHash],
                    ["Canonical URL", data.canonicalUrl],
                  ] as const
                ).map(([label, value]) => (
                  <div key={label}>
                    <dt className="mb-1 text-muted">{label}</dt>
                    <dd className="flex items-start gap-2">
                      <code className="min-w-0 flex-1 break-all rounded-lg bg-bg-subtle px-3 py-2 font-mono text-xs text-fg">
                        {value || "—"}
                      </code>
                      {value && <CopyButton value={value} label={label} />}
                    </dd>
                  </div>
                ))}
              </dl>
            </Section>
          </>
        )}
      </DetailPageTemplate>

      <AiReviewDialog
        report={aiSubject}
        onClose={() => setAiOpen(false)}
        onOpenPdf={() => setTab("document")}
      />
    </AppShell>
  );
}
