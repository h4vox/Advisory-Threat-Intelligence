import type { ComponentType, ReactNode } from "react";
import { cn } from "@/lib/cn";

type IconType = ComponentType<{ className?: string; strokeWidth?: number }>;

/**
 * Small display primitives shared by every page. Rules (see docs/UI_DESIGN_SYSTEM.md):
 * - Status colour carries meaning (ok / attention / critical / info). One StatusChip per row at most.
 * - Category colour (EntityIcon / EntityChip) identifies the kind of thing; primary = brand / selection.
 * - Sentence case everywhere; no decorative UPPERCASE mono labels.
 */

export type Tone = "neutral" | "success" | "warning" | "danger" | "info" | "primary";

const TONE_COLOR: Record<Tone, string> = {
  neutral: "var(--color-muted)",
  success: "var(--color-sage)",
  warning: "var(--color-warn)",
  danger: "var(--color-danger)",
  info: "var(--color-info)",
  primary: "var(--color-primary)",
};

function chipStyle(tone: Tone) {
  if (tone === "neutral") return { color: "var(--color-muted)", backgroundColor: "var(--color-bg-subtle)", borderColor: "var(--color-border)" };
  const c = TONE_COLOR[tone];
  return {
    color: c,
    backgroundColor: `color-mix(in oklab, ${c} 13%, transparent)`,
    borderColor: `color-mix(in oklab, ${c} 26%, transparent)`,
  };
}

export function StatusChip({ tone = "neutral", children, dot }: { tone?: Tone; children: ReactNode; dot?: boolean }) {
  return (
    <span
      className="inline-flex items-center gap-1.5 whitespace-nowrap rounded-md border px-2 py-0.5 text-xs font-medium"
      style={chipStyle(tone)}
    >
      {dot && <span className="size-1.5 rounded-full" style={{ backgroundColor: TONE_COLOR[tone] }} />}
      {children}
    </span>
  );
}

/** Dot + label status (e.g. "● Active"), like Hadrian's scanning badge. */
export function StatusDot({ tone = "success", children }: { tone?: Tone; children: ReactNode }) {
  return (
    <span className="inline-flex items-center gap-1.5 text-xs font-medium text-muted">
      <span className="size-1.5 rounded-full" style={{ backgroundColor: TONE_COLOR[tone] }} />
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

/**
 * Thin horizontal meter (e.g. quality score, coverage). value 0..1.
 * `tone` picks a status/primary hue; `color` overrides with any CSS colour (e.g. a category token).
 */
export function Meter({
  value,
  tone = "primary",
  color,
  label,
  className,
}: {
  value: number;
  tone?: Tone;
  color?: string;
  label?: string;
  className?: string;
}) {
  const pct = Math.max(0, Math.min(1, value)) * 100;
  return (
    <div
      className={cn("h-1.5 w-full overflow-hidden rounded-full bg-bg-subtle", className)}
      role="meter"
      aria-valuenow={Math.round(pct)}
      aria-valuemin={0}
      aria-valuemax={100}
      aria-label={label}
    >
      <div className="h-full rounded-full" style={{ width: `${pct}%`, backgroundColor: color ?? TONE_COLOR[tone] }} />
    </div>
  );
}
