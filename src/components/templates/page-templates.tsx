import type { ComponentProps, ReactNode } from "react";
import { PageHeader } from "@/components/layout/page";
import { cn } from "@/lib/cn";

/**
 * Page templates — start every new screen from one of these so the whole
 * product keeps one structure (see docs/UI_DESIGN_SYSTEM.md):
 *
 *  DashboardTemplate  Overview-style: header + KPI row + grid of SectionCards.
 *  ListPageTemplate   Library/Sources-style: header + tabs + toolbar + DataTable + pagination.
 *  DetailPageTemplate Report-style: back + title + actions, tabs, main column + Properties aside.
 */

type HeaderProps = ComponentProps<typeof PageHeader>;

export function DashboardTemplate({
  header,
  stats,
  children,
}: {
  header: HeaderProps;
  /** 2–4 StatCards. */
  stats?: ReactNode;
  /** SectionCards; use the grid helpers below for 2-up rows. */
  children: ReactNode;
}) {
  return (
    <div className="mx-auto w-full max-w-[1400px]">
      <PageHeader {...header} />
      {stats && <div className="mb-6 grid gap-4 sm:grid-cols-2 xl:grid-cols-4">{stats}</div>}
      <div className="space-y-6">{children}</div>
    </div>
  );
}

/** Two panels side by side on large screens (e.g. chart + breakdown). */
export function TwoUp({ children, ratio = "1:1" }: { children: ReactNode; ratio?: "1:1" | "7:5" | "3:2" }) {
  return (
    <div
      className={cn(
        "grid gap-6",
        ratio === "1:1" && "xl:grid-cols-2",
        ratio === "7:5" && "xl:grid-cols-12 [&>*:first-child]:xl:col-span-7 [&>*:last-child]:xl:col-span-5",
        ratio === "3:2" && "lg:grid-cols-5 [&>*:first-child]:lg:col-span-3 [&>*:last-child]:lg:col-span-2",
      )}
    >
      {children}
    </div>
  );
}

export function ListPageTemplate({
  header,
  toolbar,
  children,
  footer,
  aside,
}: {
  /** Put view tabs in header.tabs. */
  header: HeaderProps;
  toolbar?: ReactNode;
  /** Usually a <DataTable/>. */
  children: ReactNode;
  /** Pagination / result counts. */
  footer?: ReactNode;
  /** Optional filter panel or preview on the right (xl+). */
  aside?: ReactNode;
}) {
  return (
    <div className="mx-auto w-full max-w-[1400px]">
      <PageHeader {...header} />
      {toolbar}
      <div className={cn(aside && "grid gap-6 xl:grid-cols-[minmax(0,1fr)_360px]")}>
        <div className="min-w-0">
          {children}
          {footer && <div className="mt-4">{footer}</div>}
        </div>
        {aside && <aside className="min-w-0">{aside}</aside>}
      </div>
    </div>
  );
}

export function DetailPageTemplate({
  header,
  children,
  properties,
}: {
  /** Use header.backTo, header.icon, header.actions and header.tabs. */
  header: HeaderProps;
  /** Main column content for the active tab. */
  children: ReactNode;
  /** Right column: <PropertyList/>, references, related items. */
  properties?: ReactNode;
}) {
  return (
    <div className="mx-auto w-full max-w-[1320px]">
      <PageHeader {...header} />
      <div className={cn(properties && "grid gap-10 xl:grid-cols-[minmax(0,1fr)_340px]")}>
        <div className="min-w-0 space-y-8">{children}</div>
        {properties && (
          <aside className="min-w-0 space-y-8 xl:sticky xl:top-6 xl:self-start">{properties}</aside>
        )}
      </div>
    </div>
  );
}

/** Pagination footer used under tables. */
export function Pagination({
  page,
  pageCount,
  total,
  pageSize,
  onPage,
}: {
  page: number;
  pageCount: number;
  total: number;
  pageSize: number;
  onPage: (page: number) => void;
}) {
  const from = total === 0 ? 0 : (page - 1) * pageSize + 1;
  const to = Math.min(total, page * pageSize);
  return (
    <div className="flex flex-wrap items-center justify-between gap-3 text-sm text-muted">
      <span className="tabular-nums">
        {from}–{to} of {total}
      </span>
      <div className="flex items-center gap-2">
        <button
          type="button"
          disabled={page <= 1}
          onClick={() => onPage(page - 1)}
          className="h-8 rounded-lg border border-border bg-bg-elevated px-3 text-fg transition-colors hover:bg-bg-subtle disabled:opacity-40"
        >
          Previous
        </button>
        <span className="tabular-nums">
          {page} / {Math.max(1, pageCount)}
        </span>
        <button
          type="button"
          disabled={page >= pageCount}
          onClick={() => onPage(page + 1)}
          className="h-8 rounded-lg border border-border bg-bg-elevated px-3 text-fg transition-colors hover:bg-bg-subtle disabled:opacity-40"
        >
          Next
        </button>
      </div>
    </div>
  );
}
