import { useMemo, useState, type ReactNode } from "react";
import {
  flexRender,
  getCoreRowModel,
  getSortedRowModel,
  useReactTable,
  type ColumnDef,
  type RowSelectionState,
  type SortingState,
} from "@tanstack/react-table";
import { ArrowDown, ArrowUp, ArrowUpDown } from "lucide-react";
import { cn } from "@/lib/cn";

/**
 * DataTable — the one table used for every list in AIE (Hadrian-style).
 *
 *   <DataTable
 *     data={reports}
 *     columns={columns}              // TanStack ColumnDef[]; set meta.align / meta.className / meta.headerClassName
 *     getRowId={(r) => r.id}
 *     onRowClick={(r) => open(r.id)}
 *     selectable                     // adds a checkbox column; read selection via onSelectionChange
 *     empty={<EmptyState … />}
 *   />
 *
 * Sorting is client-side on the rows given (server paging stays with the page).
 */

export type DataTableColumnMeta = {
  align?: "left" | "right" | "center";
  className?: string;
  headerClassName?: string;
  /** Hide below this breakpoint to keep mobile readable. */
  hideBelow?: "sm" | "md" | "lg" | "xl";
};

const HIDE: Record<NonNullable<DataTableColumnMeta["hideBelow"]>, string> = {
  sm: "hidden sm:table-cell",
  md: "hidden md:table-cell",
  lg: "hidden lg:table-cell",
  xl: "hidden xl:table-cell",
};

export function DataTable<T>({
  data,
  columns,
  getRowId,
  onRowClick,
  selectable,
  onSelectionChange,
  empty,
  initialSorting,
  isRowActive,
  caption,
  dense,
}: {
  data: T[];
  columns: ColumnDef<T, any>[];
  getRowId: (row: T) => string;
  onRowClick?: (row: T) => void;
  selectable?: boolean;
  onSelectionChange?: (ids: string[]) => void;
  empty?: ReactNode;
  initialSorting?: SortingState;
  isRowActive?: (row: T) => boolean;
  caption?: string;
  dense?: boolean;
}) {
  const [sorting, setSorting] = useState<SortingState>(initialSorting ?? []);
  const [rowSelection, setRowSelection] = useState<RowSelectionState>({});

  const allColumns = useMemo<ColumnDef<T, any>[]>(() => {
    if (!selectable) return columns;
    const select: ColumnDef<T, any> = {
      id: "__select",
      enableSorting: false,
      header: ({ table }) => (
        <input
          type="checkbox"
          aria-label="Select all rows"
          className="size-4 cursor-pointer accent-[var(--color-accent)]"
          checked={table.getIsAllRowsSelected()}
          ref={(el) => {
            if (el) el.indeterminate = table.getIsSomeRowsSelected();
          }}
          onChange={table.getToggleAllRowsSelectedHandler()}
        />
      ),
      cell: ({ row }) => (
        <input
          type="checkbox"
          aria-label="Select row"
          className="size-4 cursor-pointer accent-[var(--color-accent)]"
          checked={row.getIsSelected()}
          onClick={(e) => e.stopPropagation()}
          onChange={row.getToggleSelectedHandler()}
        />
      ),
      meta: { className: "w-10", headerClassName: "w-10" } satisfies DataTableColumnMeta,
    };
    return [select, ...columns];
  }, [columns, selectable]);

  const table = useReactTable({
    data,
    columns: allColumns,
    getRowId: (row) => getRowId(row),
    state: { sorting, rowSelection },
    onSortingChange: setSorting,
    onRowSelectionChange: (updater) => {
      setRowSelection((prev) => {
        const next = typeof updater === "function" ? updater(prev) : updater;
        onSelectionChange?.(Object.keys(next).filter((k) => next[k]));
        return next;
      });
    },
    enableRowSelection: Boolean(selectable),
    getCoreRowModel: getCoreRowModel(),
    getSortedRowModel: getSortedRowModel(),
  });

  const rows = table.getRowModel().rows;
  const cellPad = dense ? "px-3 py-2" : "px-4 py-3";

  return (
    <div className="overflow-hidden rounded-xl border border-border bg-bg-card">
      <div className="overflow-x-auto">
        <table className="w-full border-collapse text-sm">
          {caption && <caption className="sr-only">{caption}</caption>}
          <thead>
            {table.getHeaderGroups().map((hg) => (
              <tr key={hg.id} className="border-b border-border">
                {hg.headers.map((header) => {
                  const meta = (header.column.columnDef.meta ?? {}) as DataTableColumnMeta;
                  const canSort = header.column.getCanSort();
                  const sorted = header.column.getIsSorted();
                  const SortIcon = sorted === "asc" ? ArrowUp : sorted === "desc" ? ArrowDown : ArrowUpDown;
                  return (
                    <th
                      key={header.id}
                      scope="col"
                      aria-sort={sorted === "asc" ? "ascending" : sorted === "desc" ? "descending" : undefined}
                      className={cn(
                        cellPad,
                        "whitespace-nowrap text-left text-[13px] font-medium text-muted",
                        meta.align === "right" && "text-right",
                        meta.align === "center" && "text-center",
                        meta.hideBelow && HIDE[meta.hideBelow],
                        meta.headerClassName,
                      )}
                    >
                      {header.isPlaceholder ? null : canSort ? (
                        <button
                          type="button"
                          onClick={header.column.getToggleSortingHandler()}
                          className={cn(
                            "inline-flex items-center gap-1.5 transition-colors hover:text-fg",
                            sorted && "text-fg",
                          )}
                        >
                          {flexRender(header.column.columnDef.header, header.getContext())}
                          <SortIcon className={cn("size-3.5", !sorted && "opacity-40")} />
                        </button>
                      ) : (
                        flexRender(header.column.columnDef.header, header.getContext())
                      )}
                    </th>
                  );
                })}
              </tr>
            ))}
          </thead>
          <tbody>
            {rows.map((row) => {
              const active = isRowActive?.(row.original);
              return (
                <tr
                  key={row.id}
                  onClick={onRowClick ? () => onRowClick(row.original) : undefined}
                  onKeyDown={
                    onRowClick
                      ? (e) => {
                          if (e.key === "Enter") onRowClick(row.original);
                        }
                      : undefined
                  }
                  tabIndex={onRowClick ? 0 : undefined}
                  aria-selected={row.getIsSelected() || active || undefined}
                  className={cn(
                    "border-b border-border last:border-b-0 transition-colors",
                    onRowClick && "cursor-pointer hover:bg-bg-subtle focus-visible:bg-bg-subtle focus-visible:outline-none",
                    (row.getIsSelected() || active) && "bg-bg-subtle",
                  )}
                >
                  {row.getVisibleCells().map((cell) => {
                    const meta = (cell.column.columnDef.meta ?? {}) as DataTableColumnMeta;
                    return (
                      <td
                        key={cell.id}
                        className={cn(
                          cellPad,
                          "align-middle text-fg",
                          meta.align === "right" && "text-right tabular-nums",
                          meta.align === "center" && "text-center",
                          meta.hideBelow && HIDE[meta.hideBelow],
                          meta.className,
                        )}
                      >
                        {flexRender(cell.column.columnDef.cell, cell.getContext())}
                      </td>
                    );
                  })}
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>
      {rows.length === 0 && <div className="px-4 py-10">{empty ?? <p className="text-center text-sm text-muted">No rows.</p>}</div>}
    </div>
  );
}
