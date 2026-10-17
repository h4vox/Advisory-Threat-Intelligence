import type { ReactNode } from "react";
import { useQuery } from "@tanstack/react-query";
import { ArrowUpRight, FileText, Fingerprint, GitCommitVertical, Link2, Radar } from "lucide-react";
import { getReportCollectorMeta } from "@/lib/aie/server-collector";
import type { AttackEntityRef, ReportAttachment, ReportMirror } from "@/lib/aie/types";
import { EntityChip } from "@/components/ui/entity";
import { EmptyState, Meter, StatusChip, type Tone } from "@/components/ui/primitives";
import { formatDateTime } from "@/lib/aie/format";

/**
 * Collection record for one report (Provenance tab): what the incremental collector recorded at
 * ingest — canonical ATT&CK references with the alias the report used, mirrors ("also seen at"),
 * content versions, attached full-report PDFs, the pre-fetch relevance score and dedup fingerprints.
 */

const MATCH_LABEL: Record<ReportMirror["matchKind"], string> = {
  canonical_url: "same canonical URL",
  content_sha256: "identical content",
  normalized_text: "identical normalised text",
  title_publisher: "same title and publisher",
  simhash: "near-duplicate (SimHash)",
};

const ATTACHMENT_STATUS: Record<ReportAttachment["status"], { label: string; tone: Tone }> = {
  attached: { label: "Attached", tone: "success" },
  too_large: { label: "Too large", tone: "warning" },
  no_text: { label: "No text layer", tone: "warning" },
  failed: { label: "Failed", tone: "danger" },
  skipped: { label: "Skipped", tone: "neutral" },
};

function SubHeading({ icon: Icon, children }: { icon: typeof Radar; children: ReactNode }) {
  return (
    <h3 className="mb-2.5 flex items-center gap-2 text-sm font-medium text-fg">
      <Icon className="size-4 text-muted" strokeWidth={1.75} />
      {children}
    </h3>
  );
}

function refKind(r: AttackEntityRef) {
  return r.kind === "software" ? ("malware" as const) : ("actor" as const);
}

export function CollectionRecord({ reportId }: { reportId: string }) {
  const meta = useQuery({
    queryKey: ["report-collector-meta", reportId],
    queryFn: () => getReportCollectorMeta({ data: { reportId } }),
    staleTime: 60_000,
  });

  if (meta.isLoading) return <div className="h-40 animate-pulse rounded-xl border border-border bg-bg-card" aria-label="Loading collection record" />;
  const m = meta.data;
  const refs = m?.attackRefs ?? [];
  const mirrors = m?.mirrors ?? [];
  const versions = m?.versionHistory ?? [];
  const attachments = m?.attachments ?? [];
  const empty = !m || (refs.length === 0 && mirrors.length === 0 && versions.length === 0 && attachments.length === 0 && !m.relevance && !m.fingerprints);

  if (empty) {
    return (
      <EmptyState
        icon={Radar}
        title="No collection record for this report"
        description="Reports stored before the incremental collector, or seeded with the workspace, carry no fingerprints, mirrors or version history yet. New crawls and ingests record them."
        className="rounded-xl border border-dashed border-border"
      />
    );
  }

  return (
    <div className="space-y-7">
      {refs.length > 0 && (
        <div>
          <SubHeading icon={Radar}>ATT&CK entities recognised at ingest</SubHeading>
          <ul className="flex flex-wrap gap-2">
            {refs.slice(0, 24).map((r) => (
              <li key={`${r.kind}:${r.id}`} className="inline-flex max-w-full items-center gap-1.5">
                <EntityChip kind={refKind(r)}>
                  {r.name} <span className="font-mono opacity-80">{r.id}</span>
                </EntityChip>
                <span className="truncate text-xs text-subtle">
                  {r.matched !== r.name ? `as “${r.matched}”` : ""}
                  {r.count > 0 ? `${r.matched !== r.name ? " · " : ""}${r.count}×` : r.inTitle ? "title only" : ""}
                  {r.section ? ` · ${r.section}` : ""}
                </span>
              </li>
            ))}
          </ul>
          <p className="mt-2 text-xs text-subtle">Matched against the bundled ATT&CK knowledge (names and aliases); generic words are never matched.</p>
        </div>
      )}

      {mirrors.length > 0 && (
        <div>
          <SubHeading icon={Link2}>Also seen at ({mirrors.length})</SubHeading>
          <ul className="divide-y divide-border rounded-xl border border-border bg-bg-card">
            {mirrors.map((x) => (
              <li key={x.canonicalUrl} className="flex min-w-0 flex-col gap-1 px-4 py-3 text-sm sm:flex-row sm:items-center sm:gap-3">
                <div className="min-w-0 flex-1">
                  <a href={x.url} target="_blank" rel="noreferrer noopener" className="inline-flex max-w-full items-center gap-1 text-fg hover:text-accent">
                    <span className="truncate">{x.publisher || x.sourceDomain}</span>
                    <ArrowUpRight className="size-3.5 shrink-0" />
                  </a>
                  <div className="truncate text-xs text-subtle">{x.canonicalUrl}</div>
                </div>
                <div className="flex shrink-0 items-center gap-2 text-xs text-muted">
                  <StatusChip tone="neutral">
                    {MATCH_LABEL[x.matchKind]}
                    {x.distance !== undefined ? ` · ${x.distance} bits` : ""}
                  </StatusChip>
                  <span className="tabular-nums">{formatDateTime(x.seenAt)}</span>
                </div>
              </li>
            ))}
          </ul>
        </div>
      )}

      {versions.length > 0 && (
        <div>
          <SubHeading icon={GitCommitVertical}>Content versions</SubHeading>
          <ol className="space-y-2 border-l border-border pl-4 text-sm">
            {versions.map((v) => (
              <li key={`${v.version}-${v.replacedAt}`} className="min-w-0">
                <span className="font-medium text-fg">v{v.version}</span>
                <span className="text-muted"> replaced {formatDateTime(v.replacedAt)}</span>
                {typeof v.wordCount === "number" && <span className="text-subtle"> · {v.wordCount.toLocaleString()} words</span>}
                <div className="truncate font-mono text-xs text-subtle">text {v.textHash}</div>
              </li>
            ))}
          </ol>
          <p className="mt-2 text-xs text-subtle">The collector re-checks stored pages with conditional requests and keeps the hash of every replaced version.</p>
        </div>
      )}

      {attachments.length > 0 && (
        <div>
          <SubHeading icon={FileText}>Attached documents</SubHeading>
          <ul className="space-y-2 text-sm">
            {attachments.map((a) => {
              const st = ATTACHMENT_STATUS[a.status];
              return (
                <li key={a.url} className="flex min-w-0 flex-wrap items-center gap-2">
                  <StatusChip tone={st.tone}>{st.label}</StatusChip>
                  <a href={a.url} target="_blank" rel="noreferrer noopener" className="min-w-0 truncate text-fg hover:text-accent">
                    {a.url}
                  </a>
                  <span className="text-xs text-subtle">
                    {a.pages ? `${a.pages} pages · ` : ""}
                    {a.chars ? `${a.chars.toLocaleString()} chars` : a.detail ?? ""}
                  </span>
                </li>
              );
            })}
          </ul>
        </div>
      )}

      {m?.relevance && (
        <div>
          <SubHeading icon={Radar}>Pre-fetch relevance</SubHeading>
          <div className="flex items-center gap-3">
            <Meter value={m.relevance.score} tone={m.relevance.score >= 0.6 ? "success" : m.relevance.score >= 0.3 ? "info" : "warning"} label="Relevance pre-score" className="max-w-48" />
            <span className="font-mono text-sm tabular-nums text-fg">{m.relevance.score.toFixed(2)}</span>
          </div>
          <p className="mt-1.5 text-sm text-muted">{m.relevance.reason}</p>
        </div>
      )}

      {m?.fingerprints && (
        <div>
          <SubHeading icon={Fingerprint}>Dedup fingerprints</SubHeading>
          <dl className="grid gap-x-6 gap-y-2 text-sm sm:grid-cols-[12rem_minmax(0,1fr)]">
            {(
              [
                ["Normalised text (SHA-256)", m.fingerprints.normalizedTextHash],
                ["Title + publisher (SHA-256)", m.fingerprints.titlePublisherHash ?? "— (title too short or generic)"],
                ["SimHash (64-bit)", `${m.fingerprints.simhash} · ${m.fingerprints.tokens.toLocaleString()} tokens`],
              ] as const
            ).map(([label, value]) => (
              <div key={label} className="contents">
                <dt className="text-muted">{label}</dt>
                <dd className="min-w-0 break-all font-mono text-xs text-fg">{value}</dd>
              </div>
            ))}
          </dl>
        </div>
      )}
    </div>
  );
}
