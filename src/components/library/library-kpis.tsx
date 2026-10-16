import type { ComponentType, ReactNode } from "react";
import { EntityIcon, entityMeta, type EntityKind } from "@/components/ui/entity";
import { cn } from "@/lib/cn";

type IconType = ComponentType<{ className?: string; strokeWidth?: number }>;

export type LibraryKpi = {
  id: string;
  label: string;
  value: number | null;
  kind: EntityKind;
  icon?: IconType;
  hint?: ReactNode;
  onClick?: () => void;
  active?: boolean;
};

/** Coloured KPI strip: one hue per intelligence family, value + short provenance hint. */
export function LibraryKpiStrip({ items }: { items: LibraryKpi[] }) {
  return (
    <div className="mb-6 grid grid-cols-3 gap-2 sm:gap-3 xl:grid-cols-6">
      {items.map((k) => {
        const color = entityMeta(k.kind).color;
        const Comp = k.onClick ? "button" : "div";
        return (
          <Comp
            key={k.id}
            type={k.onClick ? "button" : undefined}
            onClick={k.onClick}
            aria-pressed={k.onClick ? Boolean(k.active) : undefined}
            className={cn(
              "relative min-w-0 overflow-hidden rounded-xl border bg-bg-card p-3 text-left transition-colors sm:p-4",
              k.onClick && "hover:border-border-strong",
              k.active ? "border-transparent" : "border-border",
            )}
            style={
              {
                backgroundImage: `linear-gradient(135deg, color-mix(in oklab, ${color} 9%, transparent), transparent 60%)`,
                ...(k.active ? { boxShadow: `inset 0 0 0 1px ${color}` } : null),
              } as React.CSSProperties
            }
          >
            <div className="flex flex-col gap-1.5 sm:flex-row sm:items-center sm:gap-2.5">
              <EntityIcon kind={k.kind} size="sm" icon={k.icon} />
              <span className="min-w-0 truncate text-xs font-medium text-muted sm:text-[13px]">{k.label}</span>
            </div>
            <div className="mt-2 text-2xl font-semibold sm:mt-3 sm:text-[28px] leading-none tracking-tight text-fg tabular-nums">
              {k.value === null ? <span className="text-subtle">—</span> : k.value.toLocaleString()}
            </div>
            {k.hint && <div className="mt-1.5 hidden truncate text-[11px] text-subtle sm:block">{k.hint}</div>}
          </Comp>
        );
      })}
    </div>
  );
}
