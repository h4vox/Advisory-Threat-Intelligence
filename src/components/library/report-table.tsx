import { useMemo, type ReactNode } from "react";
import type { ColumnDef } from "@tanstack/react-table";
import {
  ArrowDown,
  ArrowUp,
  ArrowUpDown,
  ArrowUpRight,
  Download,
  Eye,
  FileText,
  Shield,
  ShieldAlert,
  Sparkles,
} from "lucide-react";
import { DataTable, type DataTableColumnMeta } from "@/components/ui/data-table";
import { Meter, StatusChip } from "@/components/ui/primitives";
import type { ReportListItem } from "@/lib/aie/types";
import { cn } from "@/lib/cn";
import { ActionMenu } from "./action-menu";
import { DocTypeBadge } from "@/components/ui/entity";
import { docTypesOf } from "./intel-taxonomy";
import { aiReview, formatDate, qualityTone, techniqueCount, visibilityMenuItem, type ReportSort, type ReportSortKey } from "./report-utils";

function SortHeader({
  label,
  k,
  sort,
  onSort,
  align,
}: {
  label: string;
  k: ReportSortKey;
  sort: ReportSort;
  onSort: (k: ReportSortKey) => void;
  align?: "right";
}) {
  const active = sort?.key === k;
  const Icon = !active ? ArrowUpDown : sort.desc ? ArrowDown : ArrowUp;
  return (
    <button
      type="button"
      onClick={() => onSort(k)}
      aria-label={`Sort by ${label}`}
      className={cn(
        "inline-flex items-center gap-1.5 transition-colors hover:text-fg",
        active && "text-fg",
        align === "right" && "flex-row-reverse",
      )}
    >
      {label}
      <Icon className={cn("size-3.5", !active && "opacity-40")} />
    </button>
  );
}

export type ReportRowActions = {
  open: (r: ReportListItem) => void;
  viewPdf: (r: ReportListItem) => void;
  download: (r: ReportListItem) => void;
  evidence: (r: ReportListItem) => void;
  aiReview: (r: ReportListItem) => void;
  /** Hide an unrelated report from the library (reversible). */
  hide?: (r: ReportListItem) => void;
  /** Put a hidden report back; the rules will not hide it again. */
  restore?: (r: ReportListItem) => void;
};

export function ReportTable({
  rows,
  sort,
  onSort,
  actions,
  isHighlighted,
  empty,
  showSnippets,
}: {
  rows: ReportListItem[];
  sort: ReportSort;
  onSort: (k: ReportSortKey) => void;
  actions: ReportRowActions;
  isHighlighted: (r: ReportListItem) => boolean;
  empty?: ReactNode;
  showSnippets?: boolean;
}) {
  const columns = useMemo<ColumnDef<ReportListItem, any>[]>(
    () => [
      {
        id: "title",
        enableSorting: false,
        header: () => <SortHeader label="Title" k="title" sort={sort} onSort={onSort} />,
        cell: ({ row }) => {
          const r = row.original;
          const cleanId = r.id.toLowerCase().replace(/^(rpt_|rst[-_]|report[-_])/i, "");
          const rejected = r.status === "rejected";
          const hl = isHighlighted(r);
          return (
            <div
              id={`report-${r.id}`}
              data-report-id={r.id}
              data-clean-id={cleanId}
              className="flex min-w-0 items-start gap-3 scroll-mt-24"
            >
              <span
                className={cn(
                  "mt-0.5 flex size-8 shrink-0 items-center justify-center rounded-lg bg-bg-subtle",
                  rejected ? "text-danger" : hl ? "bg-accent/15 text-accent" : "text-muted",
                )}
              >
                {rejected ? (
                  <ShieldAlert className="size-4" strokeWidth={1.75} />
                ) : (
                  <FileText className="size-4" strokeWidth={1.75} />
                )}
              </span>
              <div className="min-w-0">
                <p className="line-clamp-2 font-medium leading-snug text-fg">{r.title}</p>
                <p className="mt-1 hidden md:block 2xl:hidden">
                  <DocTypeBadge type={docTypesOf(r)[0]} />
                </p>
                <p className="mt-0.5 truncate text-xs text-muted md:hidden">
                  {r.publisher || r.sourceName || "Unknown publisher"}
                  {" · "}
                  {formatDate(r.publishedAt) ?? "Unknown date"}
                </p>
                {rejected && r.aiAuditReason && (
                  <p className="mt-0.5 line-clamp-1 text-xs text-subtle">{r.aiAuditReason}</p>
                )}
                {showSnippets && r.matchedSnippet && (
                  <p className="mt-1 line-clamp-2 text-xs text-muted">
                    <span className="text-subtle">Match: </span>“{r.matchedSnippet}”
                  </p>
                )}
              </div>
            </div>
          );
        },
        meta: { className: "min-w-[220px] md:min-w-[300px]" } satisfies DataTableColumnMeta,
      },
      {
        id: "publisher",
        enableSorting: false,
        header: () => <SortHeader label="Publisher" k="publisher" sort={sort} onSort={onSort} />,
        cell: ({ row }) => (
          <span className="block text-muted">{row.original.publisher || row.original.sourceName || "Unknown"}</span>
        ),
        meta: { hideBelow: "md", className: "min-w-[120px] max-w-[170px]" } satisfies DataTableColumnMeta,
      },
      {
        id: "published",
        enableSorting: false,
        header: () => <SortHeader label="Published" k="published" sort={sort} onSort={onSort} />,
        cell: ({ row }) => {
          const d = formatDate(row.original.publishedAt);
          return d ? (
            <span className="whitespace-nowrap text-muted tabular-nums">{d}</span>
          ) : (
            <span className="text-subtle">Unknown</span>
          );
        },
        meta: { hideBelow: "lg" } satisfies DataTableColumnMeta,
      },
      {
        id: "type",
        enableSorting: false,
        header: () => <SortHeader label="Type" k="type" sort={sort} onSort={onSort} />,
        cell: ({ row }) => <DocTypeBadge type={docTypesOf(row.original)[0]} />,
        meta: { className: "hidden 2xl:table-cell", headerClassName: "hidden 2xl:table-cell" } satisfies DataTableColumnMeta,
      },
      {
        id: "quality",
        enableSorting: false,
        header: () => <SortHeader label="Quality" k="quality" sort={sort} onSort={onSort} />,
        cell: ({ row }) => {
          const q = row.original.qualityScore;
          return (
            <div className="flex w-24 items-center gap-2">
              <div className="flex-1">
                <Meter value={q} tone={qualityTone(q)} label="Quality score" />
              </div>
              <span className="w-9 text-right text-xs tabular-nums text-fg">{Math.round(q * 100)}%</span>
            </div>
          );
        },
        meta: { hideBelow: "md" } satisfies DataTableColumnMeta,
      },
      {
        id: "iocs",
        enableSorting: false,
        header: () => <SortHeader label="IOCs" k="iocs" sort={sort} onSort={onSort} align="right" />,
        cell: ({ row }) => (
          <span className={cn(!row.original.iocCount && "text-subtle")}>{row.original.iocCount || 0}</span>
        ),
        meta: { align: "right", hideBelow: "sm" } satisfies DataTableColumnMeta,
      },
      {
        id: "techniques",
        enableSorting: false,
        header: () => <SortHeader label="Techniques" k="techniques" sort={sort} onSort={onSort} align="right" />,
        cell: ({ row }) => {
          const n = techniqueCount(row.original);
          return <span className={cn(!n && "text-subtle")}>{n}</span>;
        },
        meta: { align: "right", className: "hidden 2xl:table-cell", headerClassName: "hidden 2xl:table-cell" } satisfies DataTableColumnMeta,
      },
      {
        id: "ai",
        enableSorting: false,
        header: () => <SortHeader label="AI review" k="ai" sort={sort} onSort={onSort} />,
        cell: ({ row }) => {
          const a = aiReview(row.original);
          return (
            <span title={a.detail ? `${a.label} · ${a.detail}` : a.label}>
              <StatusChip tone={a.tone} dot>
                {a.label}
              </StatusChip>
            </span>
          );
        },
        meta: { className: "hidden 2xl:table-cell", headerClassName: "hidden 2xl:table-cell" } satisfies DataTableColumnMeta,
      },
      {
        id: "actions",
        enableSorting: false,
        header: () => null,
        cell: ({ row }) => {
          const r = row.original;
          const original = r.canonicalUrl || r.url;
          return (
            <ActionMenu
              label={`Actions for ${r.title}`}
              items={[
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
        },
        meta: { className: "w-12 pl-0 pr-3", headerClassName: "w-12" } satisfies DataTableColumnMeta,
      },
    ],
    [sort, onSort, actions, showSnippets, isHighlighted],
  );

  return (
    <DataTable
      data={rows}
      columns={columns}
      getRowId={(r) => r.id}
      onRowClick={actions.open}
      isRowActive={isHighlighted}
      caption="Intelligence reports"
      empty={empty}
    />
  );
}
