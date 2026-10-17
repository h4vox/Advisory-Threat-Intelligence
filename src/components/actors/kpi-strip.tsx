import type { ComponentType, ReactNode } from "react";
import { entityMeta, type EntityKind } from "@/components/ui/entity";

type IconType = ComponentType<{ className?: string; strokeWidth?: number }>;

/** Compact KPI row for detail pages: one bordered panel, cells separated by rules. */
export function KpiStrip({
  items,
}: {
  items: Array<{
    icon: IconType;
    kind: EntityKind;
    label: string;
    value: ReactNode;
    hint?: ReactNode;
  }>;
}) {
  return (
    <section className="grid grid-cols-2 overflow-hidden rounded-xl border border-border bg-bg-card sm:grid-cols-3 2xl:grid-cols-6">
      {items.map(({ icon: Icon, kind, label, value, hint }) => {
        const color = entityMeta(kind).color;
        return (
          <div
            key={label}
            className="-mb-px -mr-px min-w-0 border-b border-r border-border px-4 py-3.5"
          >
            <div className="flex items-center gap-2 text-sm text-muted">
              <span
                className="flex size-6 shrink-0 items-center justify-center rounded-md"
                style={{ color, backgroundColor: `color-mix(in oklab, ${color} 15%, transparent)` }}
              >
                <Icon className="size-3.5" strokeWidth={2} />
              </span>
              <span className="min-w-0 leading-tight">{label}</span>
            </div>
            <div className="mt-2 flex items-baseline gap-2">
              <span className="text-2xl font-semibold leading-none tabular-nums text-fg">
                {value}
              </span>
              {hint && (
                <span className="truncate text-xs" style={{ color: "var(--color-warn)" }}>
                  {hint}
                </span>
              )}
            </div>
          </div>
        );
      })}
    </section>
  );
}
