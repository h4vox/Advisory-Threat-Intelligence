import { useState, type ReactNode } from "react";
import { Check, ChevronDown, X } from "lucide-react";
import { cn } from "@/lib/cn";

export type FacetOption = { value: string; label: ReactNode; count: number; text?: string };

/** One collapsible facet with checkbox options, counts and a per-facet clear. */
export function FacetGroup({
  title,
  options,
  selected,
  onToggle,
  onClear,
  limit = 6,
  emptyText = "Nothing in the library yet",
  defaultOpen = true,
}: {
  title: string;
  options: FacetOption[];
  selected: string[];
  onToggle: (value: string) => void;
  onClear: () => void;
  limit?: number;
  emptyText?: string;
  defaultOpen?: boolean;
}) {
  const [open, setOpen] = useState(defaultOpen);
  const [all, setAll] = useState(false);
  const [filter, setFilter] = useState("");
  const f = filter.trim().toLowerCase();
  const filtered = f ? options.filter((o) => (o.text ?? String(o.value)).toLowerCase().includes(f)) : options;
  // Keep selected options visible even past the limit.
  const visible = all || f ? filtered : filtered.filter((o, i) => i < limit || selected.includes(o.value));
  const hidden = filtered.length - visible.length;

  return (
    <section className="border-b border-border px-4 py-3.5 last:border-b-0">
      <div className="flex items-center justify-between gap-2">
        <button
          type="button"
          onClick={() => setOpen(!open)}
          aria-expanded={open}
          className="flex min-w-0 flex-1 items-center gap-1.5 text-left text-sm font-medium text-fg"
        >
          <ChevronDown className={cn("size-4 shrink-0 text-subtle transition-transform", !open && "-rotate-90")} />
          <span className="truncate">{title}</span>
          {selected.length > 0 && (
            <span className="rounded bg-[var(--color-primary)] px-1.5 text-[10px] font-semibold leading-4 text-[var(--color-primary-fg)] tabular-nums">
              {selected.length}
            </span>
          )}
        </button>
        {selected.length > 0 && (
          <button type="button" onClick={onClear} className="text-xs text-muted hover:text-fg">
            Clear
          </button>
        )}
      </div>
      {open && (
        <div className="mt-2.5">
          {options.length > 10 && (
            <input
              value={filter}
              onChange={(e) => setFilter(e.target.value)}
              placeholder={`Filter ${title.toLowerCase()}…`}
              aria-label={`Filter ${title}`}
              className="mb-2 h-8 w-full rounded-md border border-border bg-bg-elevated px-2.5 text-xs text-fg placeholder:text-subtle focus:outline-none focus:ring-1 focus:ring-[var(--color-primary)]"
            />
          )}
          {options.length === 0 ? (
            <p className="py-1 text-xs text-subtle">{emptyText}</p>
          ) : (
            <ul className="space-y-0.5">
              {visible.map((o) => {
                const on = selected.includes(o.value);
                return (
                  <li key={o.value}>
                    <button
                      type="button"
                      role="checkbox"
                      aria-checked={on}
                      onClick={() => onToggle(o.value)}
                      className={cn(
                        "flex w-full items-center gap-2.5 rounded-md px-1.5 py-1 text-left text-sm transition-colors hover:bg-bg-subtle",
                        on ? "text-fg" : "text-muted",
                        o.count === 0 && !on && "opacity-50",
                      )}
                    >
                      <span
                        className={cn(
                          "flex size-4 shrink-0 items-center justify-center rounded border",
                          on ? "border-[var(--color-primary)] bg-[var(--color-primary)] text-[var(--color-primary-fg)]" : "border-border-strong",
                        )}
                      >
                        {on && <Check className="size-3" strokeWidth={3} />}
                      </span>
                      <span className="min-w-0 flex-1 truncate">{o.label}</span>
                      <span className="shrink-0 font-mono text-[11px] tabular-nums text-subtle">{o.count}</span>
                    </button>
                  </li>
                );
              })}
            </ul>
          )}
          {hidden > 0 && (
            <button type="button" onClick={() => setAll(true)} className="mt-1.5 px-1.5 text-xs font-medium text-[var(--color-primary)] hover:underline">
              Show {hidden} more
            </button>
          )}
          {all && !f && filtered.length > limit && (
            <button type="button" onClick={() => setAll(false)} className="mt-1.5 px-1.5 text-xs text-muted hover:text-fg">
              Show fewer
            </button>
          )}
        </div>
      )}
    </section>
  );
}

export function FacetToggle({ label, hint, checked, onChange, count }: { label: string; hint?: string; checked: boolean; onChange: (v: boolean) => void; count?: number }) {
  return (
    <button
      type="button"
      role="switch"
      aria-checked={checked}
      onClick={() => onChange(!checked)}
      className="flex w-full items-center gap-3 rounded-md px-1.5 py-1.5 text-left transition-colors hover:bg-bg-subtle"
    >
      <span
        className={cn(
          "relative h-[18px] w-8 shrink-0 rounded-full transition-colors",
          checked ? "bg-[var(--color-primary)]" : "bg-border-strong",
        )}
      >
        <span className={cn("absolute top-0.5 size-3.5 rounded-full bg-white shadow transition-all", checked ? "left-[16px]" : "left-0.5")} />
      </span>
      <span className="min-w-0 flex-1">
        <span className={cn("block text-sm", checked ? "text-fg" : "text-muted")}>{label}</span>
        {hint && <span className="block text-[11px] text-subtle">{hint}</span>}
      </span>
      {typeof count === "number" && <span className="font-mono text-[11px] tabular-nums text-subtle">{count}</span>}
    </button>
  );
}

export function FacetPanel({ children, activeCount, onClearAll, className }: { children: ReactNode; activeCount: number; onClearAll: () => void; className?: string }) {
  return (
    <div className={cn("overflow-hidden rounded-xl border border-border bg-bg-card", className)}>
      <div className="flex items-center justify-between gap-2 border-b border-border px-4 py-3">
        <h2 className="text-sm font-semibold text-fg">Refine</h2>
        {activeCount > 0 ? (
          <button type="button" onClick={onClearAll} className="inline-flex items-center gap-1 text-xs text-muted hover:text-fg">
            <X className="size-3.5" />
            Clear all ({activeCount})
          </button>
        ) : (
          <span className="text-xs text-subtle">No filters</span>
        )}
      </div>
      {children}
    </div>
  );
}
