import type { ReactNode } from "react";
import { ChevronLeft, ChevronRight, ChevronsLeft, ChevronsRight, Search, X } from "lucide-react";
import { cn } from "@/lib/cn";
import { Select, type SelectOption } from "@/components/ui/select";

/** Shared list controls for the Ingest and Sources pages (search, select filter, pager, section heading). */

export function SearchField({
  value,
  onChange,
  placeholder,
  label,
  className,
}: {
  value: string;
  onChange: (v: string) => void;
  placeholder: string;
  label?: string;
  className?: string;
}) {
  return (
    <div className={cn("relative w-full sm:w-72", className)}>
      <Search className="pointer-events-none absolute left-3 top-1/2 size-4 -translate-y-1/2 text-subtle" strokeWidth={1.75} />
      <input
        type="text"
        value={value}
        onChange={(e) => onChange(e.target.value)}
        placeholder={placeholder}
        aria-label={label ?? placeholder}
        className="h-9 w-full rounded-lg border border-border bg-bg-elevated pl-9 pr-8 text-sm text-fg placeholder:text-subtle focus:border-accent focus:outline-none"
      />
      {value && (
        <button
          type="button"
          aria-label="Clear search"
          onClick={() => onChange("")}
          className="absolute right-2 top-1/2 flex size-6 -translate-y-1/2 items-center justify-center rounded-md text-subtle hover:bg-bg-subtle hover:text-fg"
        >
          <X className="size-3.5" />
        </button>
      )}
    </div>
  );
}

export function FilterSelect({
  value,
  onChange,
  label,
  children,
  className,
}: {
  value: string | number;
  onChange: (v: string) => void;
  label: string;
  /** Native-style `<option>` / `<optgroup>` elements. */
  children: ReactNode;
  className?: string;
}) {
  return (
    <Select value={String(value)} onValueChange={onChange} aria-label={label} className={cn("max-w-[200px] px-2.5", className)}>
      {children}
    </Select>
  );
}

/** Untitled-box section heading: title + description on the left, extra controls on the right. */
export function SectionHeading({
  title,
  description,
  actions,
}: {
  title: ReactNode;
  description?: ReactNode;
  actions?: ReactNode;
}) {
  return (
    <div className="mb-4 flex flex-col gap-3 sm:flex-row sm:items-end sm:justify-between">
      <div className="min-w-0">
        <h2 className="text-base font-medium text-fg">{title}</h2>
        {description && <p className="mt-0.5 text-sm text-muted">{description}</p>}
      </div>
      {actions && <div className="flex flex-wrap items-center gap-2">{actions}</div>}
    </div>
  );
}

const PAGE_SIZE_OPTIONS: SelectOption[] = [
  ...[10, 25, 50, 100].map((n) => ({ value: String(n), label: String(n) })),
  { value: "all", label: "All" },
];

const PAGER_BTN =
  "flex size-8 items-center justify-center rounded-lg border border-border bg-bg-elevated text-muted transition-colors hover:bg-bg-subtle hover:text-fg disabled:pointer-events-none disabled:opacity-40";

/** Page-size aware pager used under every list on the Ingest page. */
export function PaginationControls({
  currentPage,
  pageSize,
  totalItems,
  onPageChange,
  onPageSizeChange,
  itemLabel = "items",
}: {
  currentPage: number;
  pageSize: number | "all";
  totalItems: number;
  onPageChange: (page: number) => void;
  onPageSizeChange: (size: number | "all") => void;
  itemLabel?: string;
}) {
  const numericSize = pageSize === "all" ? Math.max(1, totalItems) : pageSize;
  const totalPages = pageSize === "all" ? 1 : Math.max(1, Math.ceil(totalItems / numericSize));
  const safePage = Math.min(Math.max(1, currentPage), totalPages);
  const startItem = totalItems === 0 ? 0 : (safePage - 1) * numericSize + 1;
  const endItem = pageSize === "all" ? totalItems : Math.min(totalItems, safePage * numericSize);

  return (
    <div className="mt-3 flex flex-col gap-3 text-sm text-muted sm:flex-row sm:items-center sm:justify-between">
      <div className="flex flex-wrap items-center gap-3">
        <span className="tabular-nums">
          {startItem}–{endItem} of {totalItems} {itemLabel}
        </span>
        <label className="flex items-center gap-2">
          <span className="text-subtle">Rows</span>
          <Select
            size="sm"
            value={String(pageSize)}
            aria-label="Rows per page"
            onValueChange={(v) => {
              onPageSizeChange(v === "all" ? "all" : Number(v));
              onPageChange(1);
            }}
            options={PAGE_SIZE_OPTIONS}
          />
        </label>
      </div>
      {totalPages > 1 && (
        <div className="flex items-center gap-1.5">
          <button type="button" aria-label="First page" disabled={safePage <= 1} onClick={() => onPageChange(1)} className={PAGER_BTN}>
            <ChevronsLeft className="size-4" />
          </button>
          <button type="button" aria-label="Previous page" disabled={safePage <= 1} onClick={() => onPageChange(safePage - 1)} className={PAGER_BTN}>
            <ChevronLeft className="size-4" />
          </button>
          <span className="px-2 tabular-nums">
            {safePage} / {totalPages}
          </span>
          <button type="button" aria-label="Next page" disabled={safePage >= totalPages} onClick={() => onPageChange(safePage + 1)} className={PAGER_BTN}>
            <ChevronRight className="size-4" />
          </button>
          <button type="button" aria-label="Last page" disabled={safePage >= totalPages} onClick={() => onPageChange(totalPages)} className={PAGER_BTN}>
            <ChevronsRight className="size-4" />
          </button>
        </div>
      )}
    </div>
  );
}
