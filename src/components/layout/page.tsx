import type { ComponentType, ReactNode } from "react";
import { Link } from "@tanstack/react-router";
import { ArrowLeft, ArrowRight, Info, TrendingDown, TrendingUp, Minus } from "lucide-react";
import { cn } from "@/lib/cn";
import { entityMeta, type EntityKind } from "@/components/ui/entity";

/**
 * Page structure primitives: one consistent layout for every screen.
 *   PageHeader  – title (+icon/back) on the left, actions on the right, optional tabs below.
 *   StatCard    – KPI tile: icon + label + arrow link, big value + delta chip.
 *   SectionCard – titled panel with optional info hint and right-aligned controls.
 *   SegmentedTabs / Toolbar / ActionButton – shared controls.
 */

type IconType = ComponentType<{ className?: string; strokeWidth?: number }>;

/** Tinted icon-well style for a CSS colour (same recipe as EntityIcon). */
function tint(color: string) {
  return { color, backgroundColor: `color-mix(in oklab, ${color} 15%, transparent)` };
}

/** Default category hue for a KPI, inferred from its label when no kind is given. */
function kindForLabel(label: ReactNode): EntityKind | undefined {
  if (typeof label !== "string") return undefined;
  const l = label.toLowerCase();
  if (/actor|group|campaign/.test(l)) return "actor";
  if (/malware|tool|software/.test(l)) return "malware";
  if (/technique|tactic|att&ck|ttp/.test(l)) return "technique";
  if (/cve|vuln|kev/.test(l)) return "cve";
  if (/ioc|indicator/.test(l)) return "ioc";
  if (/source|feed/.test(l)) return "source";
  if (/report|advisor|document|library/.test(l)) return "advisory";
  if (/emulat|simulat|atomic|plan|quality/.test(l)) return "emulation";
  if (/flow|chain/.test(l)) return "flow";
  return undefined;
}

export function PageHeader({
  title,
  icon: Icon,
  iconKind,
  description,
  eyebrow,
  backTo,
  actions,
  tabs,
  className,
}: {
  title: ReactNode;
  icon?: IconType;
  /** Category hue for the header icon well (defaults to primary). */
  iconKind?: EntityKind;
  description?: ReactNode;
  eyebrow?: ReactNode;
  backTo?: string;
  actions?: ReactNode;
  tabs?: ReactNode;
  className?: string;
}) {
  return (
    <header className={cn("mb-6 md:mb-8", className)}>
      <div className="flex flex-col gap-4 md:flex-row md:items-start md:justify-between">
        <div className="flex min-w-0 items-start gap-3">
          {backTo && (
            <Link
              to={backTo}
              aria-label="Back"
              className="mt-0.5 flex size-9 shrink-0 items-center justify-center rounded-lg border border-border bg-bg-elevated text-muted transition-colors hover:bg-bg-subtle hover:text-fg"
            >
              <ArrowLeft className="size-4" />
            </Link>
          )}
          {Icon && (
            <span
              className="mt-0.5 flex size-9 shrink-0 items-center justify-center rounded-lg"
              style={tint(iconKind ? entityMeta(iconKind).color : "var(--color-primary)")}
            >
              <Icon className="size-[18px]" strokeWidth={1.9} />
            </span>
          )}
          <div className="min-w-0">
            {eyebrow && (
              <div className="mb-1 font-mono text-[10px] uppercase tracking-widest text-subtle">{eyebrow}</div>
            )}
            <h1 className="truncate text-2xl font-semibold tracking-tight text-fg md:text-[28px] md:leading-9">{title}</h1>
            {description && <p className="mt-1 max-w-3xl text-sm text-muted">{description}</p>}
          </div>
        </div>
        {actions && <div className="flex flex-wrap items-center gap-2 md:shrink-0 md:justify-end md:pt-0.5">{actions}</div>}
      </div>
      {tabs && <div className="mt-5">{tabs}</div>}
    </header>
  );
}

export function ActionButton({
  children,
  icon: Icon,
  variant = "outline",
  onClick,
  to,
  disabled,
  title,
  type = "button",
}: {
  children: ReactNode;
  icon?: IconType;
  variant?: "outline" | "primary" | "ghost";
  onClick?: () => void;
  to?: string;
  disabled?: boolean;
  title?: string;
  type?: "button" | "submit";
}) {
  const cls = cn(
    "inline-flex h-9 shrink-0 items-center gap-2 whitespace-nowrap rounded-lg px-3 text-sm font-medium transition-colors disabled:cursor-not-allowed disabled:opacity-50",
    variant === "primary" && "btn-primary",
    variant === "outline" && "border border-border bg-bg-elevated text-fg hover:bg-bg-subtle",
    variant === "ghost" && "text-muted hover:bg-bg-subtle hover:text-fg",
  );
  const inner = (
    <>
      {Icon && <Icon className="size-4" strokeWidth={1.75} />}
      {children}
    </>
  );
  if (to) {
    return (
      <Link to={to} className={cls} title={title}>
        {inner}
      </Link>
    );
  }
  return (
    <button type={type} onClick={onClick} disabled={disabled} className={cls} title={title}>
      {inner}
    </button>
  );
}

export function StatCard({
  icon: Icon,
  kind,
  label,
  value,
  delta,
  hint,
  to,
  search,
}: {
  icon?: IconType;
  /** Category hue for the icon well; inferred from the label when omitted. */
  kind?: EntityKind;
  label: ReactNode;
  value: ReactNode;
  /** Signed change; rendered as a chip with a trend arrow. */
  delta?: { value: ReactNode; direction?: "up" | "down" | "flat" };
  hint?: ReactNode;
  to?: string;
  search?: Record<string, unknown>;
}) {
  const DeltaIcon = delta?.direction === "up" ? TrendingUp : delta?.direction === "down" ? TrendingDown : Minus;
  const resolved = kind ?? kindForLabel(label);
  const color = resolved ? entityMeta(resolved).color : "var(--color-primary)";
  const deltaColor =
    delta?.direction === "up" ? "var(--color-cat-ioc)" : delta?.direction === "down" ? "var(--color-cat-actor)" : "var(--color-muted)";
  return (
    <div className="rounded-xl border border-border bg-bg-card p-5">
      <div className="flex items-center justify-between gap-3">
        <div className="flex min-w-0 items-center gap-2.5">
          {Icon && (
            <span className="flex size-8 shrink-0 items-center justify-center rounded-lg" style={tint(color)}>
              <Icon className="size-4" strokeWidth={1.9} />
            </span>
          )}
          <span className="truncate text-[15px] font-medium text-fg">{label}</span>
        </div>
        {to && (
          <Link
            to={to}
            search={search as never}
            aria-label={`Open ${typeof label === "string" ? label : "details"}`}
            className="flex size-8 shrink-0 items-center justify-center rounded-md border border-border text-muted transition-colors hover:bg-bg-subtle hover:text-fg"
          >
            <ArrowRight className="size-4" />
          </Link>
        )}
      </div>
      <div className="mt-4 flex items-baseline gap-2.5">
        <span className="text-[32px] font-semibold leading-none tracking-tight text-fg tabular-nums">{value}</span>
        {delta && (
          <span
            className="inline-flex items-center gap-1 rounded-md px-1.5 py-0.5 text-xs font-medium tabular-nums"
            style={delta.direction === "flat" || !delta.direction ? { color: deltaColor, backgroundColor: "var(--color-bg-subtle)" } : tint(deltaColor)}
          >
            <DeltaIcon className="size-3.5" />
            {delta.value}
          </span>
        )}
      </div>
      {hint && <div className="mt-2 text-xs text-subtle">{hint}</div>}
    </div>
  );
}

export function SectionCard({
  title,
  icon: TitleIcon,
  iconKind,
  info,
  actions,
  children,
  className,
  bodyClassName,
}: {
  title: ReactNode;
  /** Small coloured glyph before the title. */
  icon?: IconType;
  iconKind?: EntityKind;
  info?: string;
  actions?: ReactNode;
  children: ReactNode;
  className?: string;
  bodyClassName?: string;
}) {
  return (
    <section className={cn("rounded-xl border border-border bg-bg-card", className)}>
      <div className="flex flex-wrap items-center justify-between gap-3 px-5 pt-5">
        <h2 className="flex items-center gap-2 text-base font-medium text-fg">
          {TitleIcon && (
            <span
              className="flex size-6 shrink-0 items-center justify-center rounded-md"
              style={tint(iconKind ? entityMeta(iconKind).color : "var(--color-primary)")}
            >
              <TitleIcon className="size-3.5" strokeWidth={2} />
            </span>
          )}
          {title}
          {info && (
            <span title={info} aria-label={info} className="text-subtle">
              <Info className="size-4" />
            </span>
          )}
        </h2>
        {actions && <div className="flex flex-wrap items-center gap-2">{actions}</div>}
      </div>
      <div className={cn("p-5", bodyClassName)}>{children}</div>
    </section>
  );
}

export type SegmentedItem<T extends string> = { value: T; label: ReactNode; count?: number; icon?: IconType };

export function SegmentedTabs<T extends string>({
  items,
  value,
  onChange,
  size = "md",
  ariaLabel,
}: {
  items: SegmentedItem<T>[];
  value: T;
  onChange: (value: T) => void;
  size?: "sm" | "md";
  ariaLabel?: string;
}) {
  return (
    <div
      role="tablist"
      aria-label={ariaLabel}
      className="inline-flex max-w-full overflow-x-auto rounded-lg border border-border bg-bg-elevated p-0.5"
    >
      {items.map((item) => {
        const active = item.value === value;
        const Icon = item.icon;
        return (
          <button
            key={item.value}
            type="button"
            role="tab"
            aria-selected={active}
            onClick={() => onChange(item.value)}
            className={cn(
              "inline-flex shrink-0 items-center gap-2 rounded-md font-medium transition-colors",
              size === "sm" ? "h-7 px-2.5 text-xs" : "h-9 px-3.5 text-sm",
              active ? "bg-bg-subtle text-fg shadow-xs" : "text-muted hover:text-fg",
            )}
          >
            {Icon && <Icon className="size-4" strokeWidth={1.75} />}
            {item.label}
            {typeof item.count === "number" && (
              <span className="rounded bg-bg px-1.5 py-px font-mono text-[10px] text-subtle tabular-nums">{item.count}</span>
            )}
          </button>
        );
      })}
    </div>
  );
}

/** Table/list toolbar: left = search + filters, right = bulk/export/view actions. */
export function Toolbar({ left, right, className }: { left?: ReactNode; right?: ReactNode; className?: string }) {
  return (
    <div className={cn("mb-4 flex flex-col gap-2 sm:flex-row sm:items-center sm:justify-between", className)}>
      <div className="flex flex-wrap items-center gap-2">{left}</div>
      {right && <div className="flex flex-wrap items-center gap-2">{right}</div>}
    </div>
  );
}

export function CountBadge({ value }: { value?: number | null }) {
  if (value === undefined || value === null) return null;
  return (
    <span className="ml-auto rounded bg-bg-subtle px-1.5 py-px font-mono text-[10px] text-muted tabular-nums">
      {value > 999 ? `${Math.floor(value / 1000)}k` : value}
    </span>
  );
}
