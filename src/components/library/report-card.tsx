import { ArrowUpRight, Calendar, Download, Eye, FileText, Hash, Layers, Shield, ShieldAlert, Sparkles } from "lucide-react";
import { DOC_TYPE_META, DocTypeBadge, EntityChip, EntityIcon, entityMeta, type EntityKind } from "@/components/ui/entity";
import { Meter, StatusChip } from "@/components/ui/primitives";
import { EmulationSimulationBadge } from "./emulation-simulation-badge";
import type { ReportListItem } from "@/lib/aie/types";
import { cn } from "@/lib/cn";
import { ActionMenu } from "./action-menu";
import type { ReportRowActions } from "./report-table";
import { aiReview, formatDate, qualityTone, visibilityMenuItem } from "./report-utils";
import { actorsOf, cvesOf, docTypesOf, malwareOf, publisherOf, techniquesOf, tierOf, TIER_META } from "./intel-taxonomy";

type Chip = { kind: EntityKind; label: string; title?: string };

function entityChips(r: ReportListItem): Chip[] {
  const techs = techniquesOf(r);
  return [
    ...actorsOf(r).map((a) => ({ kind: "actor" as const, label: a, title: "Threat actor" })),
    ...malwareOf(r).map((m) => ({ kind: "malware" as const, label: m, title: "Malware / tool" })),
    ...cvesOf(r).map((c) => ({ kind: "cve" as const, label: c, title: "Vulnerability" })),
    ...techs.map((t) => ({ kind: "technique" as const, label: t.id, title: t.name ? `${t.id} · ${t.name}` : t.id })),
  ];
}

function rowMenu(r: ReportListItem, actions: ReportRowActions) {
  const original = r.canonicalUrl || r.url;
  return (
    <ActionMenu
      label={`More actions for ${r.title}`}
      items={[
        { label: "Open report", icon: FileText, onSelect: () => actions.open(r) },
        { label: "View PDF", icon: Eye, onSelect: () => actions.viewPdf(r) },
        { label: "Download", icon: Download, onSelect: () => actions.download(r) },
        { label: "Evidence", icon: Shield, onSelect: () => actions.evidence(r) },
        { label: "AI review", icon: Sparkles, onSelect: () => actions.aiReview(r) },
        visibilityMenuItem(r, actions),
        "separator",
        { label: "Open original URL", icon: ArrowUpRight, href: original, disabled: !original },
      ]}
    />
  );
}

export function TierDot({ tier, withLabel }: { tier: ReturnType<typeof tierOf>; withLabel?: boolean }) {
  if (!tier) {
    return withLabel ? <span className="text-subtle">Unrated source</span> : null;
  }
  const m = TIER_META[tier];
  return (
    <span className="inline-flex items-center gap-1.5" title={m.label}>
      <span className="size-2 shrink-0 rounded-full" style={{ backgroundColor: m.color }} />
      {withLabel && <span>{m.short}</span>}
    </span>
  );
}

function SmallBtn({ onClick, icon: Icon, children, label }: { onClick: () => void; icon: typeof Eye; children?: React.ReactNode; label: string }) {
  return (
    <button
      type="button"
      onClick={(e) => {
        e.stopPropagation();
        onClick();
      }}
      title={label}
      aria-label={label}
      className={cn(
        "inline-flex h-8 shrink-0 items-center justify-center gap-1.5 rounded-lg border border-border bg-bg-elevated text-sm font-medium text-fg transition-colors hover:bg-bg-subtle",
        children ? "px-2.5" : "w-8",
      )}
    >
      <Icon className="size-4 text-muted" strokeWidth={1.75} />
      {children}
    </button>
  );
}

/** Rich feed card: the default library view. */
export function ReportFeedCard({
  r,
  actions,
  highlighted,
  showSnippet,
}: {
  r: ReportListItem;
  actions: ReportRowActions;
  highlighted: boolean;
  showSnippet?: boolean;
}) {
  const types = docTypesOf(r);
  const primary = DOC_TYPE_META[types[0]] ?? DOC_TYPE_META.OTHER;
  const tier = tierOf(r);
  const chips = entityChips(r);
  const shown = chips.slice(0, 6);
  const more = chips.length - shown.length;
  const techCount = chips.filter((c) => c.kind === "technique").length;
  const rejected = r.status === "rejected";
  const review = aiReview(r);
  const date = formatDate(r.publishedAt);
  const cleanId = r.id.toLowerCase().replace(/^(rpt_|rst[-_]|report[-_])/i, "");
  const accent = entityMeta(primary.kind).color;

  return (
    <article
      id={`report-${r.id}`}
      data-report-id={r.id}
      data-clean-id={cleanId}
      onClick={() => actions.open(r)}
      onKeyDown={(e) => {
        if (e.key === "Enter" && e.target === e.currentTarget) actions.open(r);
      }}
      tabIndex={0}
      className={cn(
        "group relative scroll-mt-24 cursor-pointer overflow-hidden rounded-xl border bg-bg-card p-4 transition-colors hover:border-border-strong focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[var(--color-primary)] sm:p-5",
        highlighted ? "border-[var(--color-primary)] ring-1 ring-[var(--color-primary)]" : "border-border",
      )}
    >
      <span aria-hidden className="absolute inset-y-0 left-0 w-[3px]" style={{ backgroundColor: rejected ? "var(--color-danger)" : accent }} />
      <div className="flex gap-4">
        <div className="hidden sm:block">
          <EntityIcon kind={primary.kind} size="lg" icon={rejected ? ShieldAlert : primary.icon} />
        </div>
        <div className="min-w-0 flex-1">
          <div className="flex flex-wrap items-center gap-x-2 gap-y-1.5 text-xs text-muted">
            {types.slice(0, 3).map((t) => (
              <DocTypeBadge key={t} type={t} />
            ))}
            <EmulationSimulationBadge value={r.emulationSimulation} />
            {rejected && <StatusChip tone="neutral">Hidden</StatusChip>}
            {r.needsReview && !rejected && (
              <span title={r.review?.reason}>
                <StatusChip tone="warning">Needs review</StatusChip>
              </span>
            )}
            <span className="inline-flex min-w-0 items-center gap-1.5">
              <TierDot tier={tier} />
              <span className="truncate font-medium text-fg/90">{publisherOf(r)}</span>
            </span>
            <span
              className="inline-flex items-center gap-1 tabular-nums text-subtle"
              title={`${date ? `Published ${date} by the source` : "The source gives no publication date"} · ingested ${formatDate(r.ingestedAt) ?? "unknown"}`}
            >
              <Calendar className="size-3.5" strokeWidth={1.75} />
              {date ?? "Undated"}
            </span>
          </div>

          <h3 className="mt-2 line-clamp-2 text-[15px] font-semibold leading-snug text-fg sm:text-base">{r.title}</h3>

          {showSnippet && r.matchedSnippet ? (
            <p className="mt-1.5 line-clamp-2 text-sm text-muted">
              <span className="text-subtle">Match: </span>“{r.matchedSnippet}”
            </p>
          ) : rejected && r.aiAuditReason ? (
            <p className="mt-1.5 line-clamp-2 text-sm text-danger/90">{r.aiAuditReason}</p>
          ) : (
            r.excerpt && <p className="mt-1.5 line-clamp-3 text-sm leading-relaxed text-muted sm:line-clamp-2 xl:line-clamp-3">{r.excerpt}</p>
          )}

          {shown.length > 0 && (
            <div className="mt-3 flex flex-wrap gap-1.5">
              {shown.map((c) => (
                <EntityChip key={`${c.kind}:${c.label}`} kind={c.kind} title={c.title}>
                  {c.label}
                </EntityChip>
              ))}
              {more > 0 && (
                <span
                  className="inline-flex items-center rounded-md bg-bg-subtle px-2 py-0.5 text-xs font-medium text-muted"
                  title={chips.slice(6).map((c) => c.label).join(", ")}
                >
                  +{more}
                </span>
              )}
            </div>
          )}

          <div className="mt-3 flex flex-wrap items-center gap-x-4 gap-y-2 border-t border-border pt-3 text-xs text-muted">
            <span className="inline-flex items-center gap-1.5" title="Indicators of compromise">
              <Hash className="size-3.5" style={{ color: "var(--color-cat-ioc)" }} strokeWidth={1.9} />
              <span className="tabular-nums text-fg">{r.iocCount || 0}</span> IOCs
            </span>
            <span className="inline-flex items-center gap-1.5" title="Distinct ATT&CK techniques">
              <Layers className="size-3.5" style={{ color: "var(--color-cat-technique)" }} strokeWidth={1.9} />
              <span className="tabular-nums text-fg">{techCount}</span> techniques
            </span>
            <span className="inline-flex items-center gap-2" title="Heuristic quality score">
              <span className="w-16">
                <Meter value={r.qualityScore} tone={qualityTone(r.qualityScore)} label="Quality score" />
              </span>
              <span className="tabular-nums text-fg">{Math.round(r.qualityScore * 100)}%</span>
            </span>
            <span className="hidden tabular-nums sm:inline">{(r.wordCount || 0).toLocaleString()} words</span>
            <span title={review.detail ? `${review.label} · ${review.detail}` : review.label}>
              <StatusChip tone={review.tone} dot>
                {review.label}
              </StatusChip>
            </span>
            <div className="ml-auto flex items-center gap-1.5 sm:hidden">
              <SmallBtn icon={Shield} onClick={() => actions.evidence(r)} label="Evidence" />
              <SmallBtn icon={Eye} onClick={() => actions.viewPdf(r)} label="View PDF" />
              {rowMenu(r, actions)}
            </div>
          </div>
        </div>

        <div className="hidden shrink-0 flex-col items-end gap-2 sm:flex">
          <div className="flex items-center gap-1.5">
            <SmallBtn icon={ArrowUpRight} onClick={() => actions.open(r)} label="View report">
              View
            </SmallBtn>
            {rowMenu(r, actions)}
          </div>
          <div className="flex items-center gap-1.5">
            <SmallBtn icon={Shield} onClick={() => actions.evidence(r)} label="Evidence" />
            <SmallBtn icon={Eye} onClick={() => actions.viewPdf(r)} label="View PDF" />
          </div>
        </div>
      </div>
    </article>
  );
}

/** Compact one-line list row. */
export function ReportListRow({
  r,
  actions,
  highlighted,
}: {
  r: ReportListItem;
  actions: ReportRowActions;
  highlighted: boolean;
}) {
  const types = docTypesOf(r);
  const primary = DOC_TYPE_META[types[0]] ?? DOC_TYPE_META.OTHER;
  const date = formatDate(r.publishedAt);
  const cleanId = r.id.toLowerCase().replace(/^(rpt_|rst[-_]|report[-_])/i, "");
  const actors = actorsOf(r);
  return (
    <li
      id={`report-${r.id}`}
      data-report-id={r.id}
      data-clean-id={cleanId}
      onClick={() => actions.open(r)}
      className={cn(
        "flex scroll-mt-24 cursor-pointer items-center gap-3 px-3 py-2.5 transition-colors hover:bg-bg-subtle sm:px-4",
        highlighted && "bg-[color-mix(in_oklab,var(--color-primary)_10%,transparent)]",
      )}
    >
      <EntityIcon kind={primary.kind} size="sm" icon={primary.icon} />
      <div className="min-w-0 flex-1">
        <p className="truncate text-sm font-medium text-fg">{r.title}</p>
        <p className="truncate text-xs text-muted">
          <span className="inline-flex items-center gap-1.5 align-middle">
            <TierDot tier={tierOf(r)} />
          </span>{" "}
          {publisherOf(r)}
          {` · ${date ?? "Undated"}`}
          {actors.length > 0 && (
            <>
              {" · "}
              <span style={{ color: "var(--color-cat-actor)" }}>{actors.slice(0, 2).join(", ")}</span>
            </>
          )}
        </p>
      </div>
      <span className="hidden md:inline-flex">
        <DocTypeBadge type={types[0]} />
      </span>
      <span className="hidden w-16 text-right text-xs tabular-nums text-muted sm:inline">{r.iocCount || 0} IOCs</span>
      <span className="hidden w-12 text-right text-xs tabular-nums text-fg lg:inline">{Math.round(r.qualityScore * 100)}%</span>
      {rowMenu(r, actions)}
    </li>
  );
}
