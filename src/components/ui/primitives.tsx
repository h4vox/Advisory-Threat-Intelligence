import type { ComponentType, ReactNode } from "react";
import { cn } from "@/lib/cn";

type IconType = ComponentType<{ className?: string; strokeWidth?: number }>;

/**
 * Small display primitives shared by every page. Rules (see docs/UI_DESIGN_SYSTEM.md):
 * - Colour carries meaning only (status/severity). One StatusChip per row at most.
 * - Sentence case everywhere; no decorative UPPERCASE mono labels.
 */

export type Tone = "neutral" | "success" | "warning" | "danger" | "info";

const TONE: Record<Tone, { chip: string; dot: string }> = {
  neutral: { chip: "border-border text-muted", dot: "bg-subtle" },
  success: { chip: "border-sage/40 text-sage", dot: "bg-sage" },
  warning: { chip: "border-warn/40 text-warn", dot: "bg-warn" },
  danger: { chip: "border-danger/50 text-danger", dot: "bg-danger" },
  info: { chip: "border-accent/40 text-accent", dot: "bg-accent" },
};

export function StatusChip({ tone = "neutral", children, dot }: { tone?: Tone; children: ReactNode; dot?: boolean }) {
  return (
    <span
      className={cn(
        "inline-flex items-center gap-1.5 whitespace-nowrap rounded-md border px-2 py-0.5 text-xs font-medium",
        TONE[tone].chip,
      )}
    >
      {dot && <span className={cn("size-1.5 rounded-full", TONE[tone].dot)} />}
      {children}
    </span>
  );
}

/** Dot + label status (e.g. "● Active"), like Hadrian's scanning badge. */
export function StatusDot({ tone = "success", children }: { tone?: Tone; children: ReactNode }) {
  return (
    <span className="inline-flex items-center gap-1.5 text-xs font-medium text-muted">
      <span className={cn("size-1.5 rounded-full", TONE[tone].dot)} />
      {children}
    </span>
  );
}

/** Key/value list for detail pages ("Properties" column). */
export function PropertyList({
  title = "Properties",
  items,
}: {
  title?: ReactNode;
  items: Array<{ label: ReactNode; value: ReactNode; hidden?: boolean }>;
}) {
  return (
    <section>
      {title && <h2 className="mb-3 text-base font-medium text-fg">{title}</h2>}
      <dl className="grid grid-cols-[minmax(0,9rem)_minmax(0,1fr)] gap-x-4 gap-y-3 text-sm">
        {items
          .filter((i) => !i.hidden)
          .map((i, idx) => (
            <div key={idx} className="contents">
              <dt className="text-muted">{i.label}</dt>
              <dd className="min-w-0 break-words text-fg">{i.value ?? <span className="text-subtle">Unknown</span>}</dd>
            </div>
          ))}
      </dl>
    </section>
  );
}

export function EmptyState({
  icon: Icon,
  title,
  description,
  action,
  className,
}: {
  icon?: IconType;
  title: ReactNode;
  description?: ReactNode;
  action?: ReactNode;
  className?: string;
}) {
  return (
    <div className={cn("flex flex-col items-center justify-center px-6 py-10 text-center", className)}>
      {Icon && (
        <span className="mb-3 flex size-10 items-center justify-center rounded-lg bg-bg-subtle text-muted">
          <Icon className="size-5" strokeWidth={1.75} />
        </span>
      )}
      <p className="text-sm font-medium text-fg">{title}</p>
      {description && <p className="mt-1 max-w-md text-sm text-muted">{description}</p>}
      {action && <div className="mt-4">{action}</div>}
    </div>
  );
}

/** Thin horizontal meter (e.g. quality score, coverage). value 0..1. */
export function Meter({ value, tone = "info", label }: { value: number; tone?: Tone; label?: string }) {
  const pct = Math.max(0, Math.min(1, value)) * 100;
  return (
    <div className="h-1.5 w-full overflow-hidden rounded-full bg-bg-subtle" role="meter" aria-valuenow={Math.round(pct)} aria-valuemin={0} aria-valuemax={100} aria-label={label}>
      <div className={cn("h-full rounded-full", TONE[tone].dot)} style={{ width: `${pct}%` }} />
    </div>
  );
}
