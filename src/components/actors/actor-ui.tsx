import { Link } from "@tanstack/react-router";
import { FlaskConical } from "lucide-react";
import type { ActorEmulationSummary, ActorRow } from "@/lib/aie/actors/types";
import { tacticHue } from "./actor-format";
import { cn } from "@/lib/cn";

/**
 * Small shared pieces for the threat-actor pages: tactic hues, the attributed-vs-observed technique
 * bar, the emulation cell and link helpers.
 */

export function TacticDot({ tactic }: { tactic: string | null | undefined }) {
  return (
    <span
      aria-hidden
      className="inline-block size-2 shrink-0 rounded-full"
      style={{ backgroundColor: tacticHue(tactic) }}
    />
  );
}

type IconType = React.ComponentType<{ className?: string; strokeWidth?: number }>;

/** ActionButton look for a router link with search params. */
export function LinkButton({
  link,
  icon: Icon,
  variant = "outline",
  children,
  className,
}: {
  link: { to: string; search: Record<string, string> };
  icon?: IconType;
  variant?: "outline" | "primary";
  children: React.ReactNode;
  className?: string;
}) {
  return (
    <Link
      to={link.to as never}
      search={link.search as never}
      className={cn(
        "inline-flex h-9 shrink-0 items-center gap-2 whitespace-nowrap rounded-lg px-3 text-sm font-medium transition-colors",
        variant === "primary"
          ? "btn-primary"
          : "border border-border bg-bg-elevated text-fg hover:bg-bg-subtle",
        className,
      )}
    >
      {Icon && <Icon className="size-4" strokeWidth={1.75} />}
      {children}
    </Link>
  );
}

/**
 * Attributed (ATT&CK) vs observed (library) techniques as one stacked bar:
 * shared = both, attributed-only, and new (observed, not in ATT&CK).
 */
export function TechniqueMiniBar({
  row,
  max,
  className,
}: {
  row: Pick<ActorRow, "attributedTechniques" | "observedTechniques" | "newTechniques">;
  max: number;
  className?: string;
}) {
  const observedKnown = row.observedTechniques - row.newTechniques;
  const attributedOnly = Math.max(0, row.attributedTechniques - observedKnown);
  const total = attributedOnly + row.observedTechniques;
  const scale = Math.max(1, max);
  const seg = (n: number) => `${(n / scale) * 100}%`;
  const label = `${row.attributedTechniques} ATT&CK-attributed, ${row.observedTechniques} observed in library (${row.newTechniques} new vs ATT&CK)`;
  return (
    <div className={cn("flex min-w-[120px] items-center gap-2", className)} title={label}>
      <div
        className="flex h-1.5 flex-1 overflow-hidden rounded-full bg-bg-subtle"
        role="img"
        aria-label={label}
      >
        {observedKnown > 0 && (
          <span
            style={{ width: seg(observedKnown), backgroundColor: "var(--color-cat-technique)" }}
          />
        )}
        {row.newTechniques > 0 && (
          <span style={{ width: seg(row.newTechniques), backgroundColor: "var(--color-warn)" }} />
        )}
        {attributedOnly > 0 && (
          <span
            style={{
              width: seg(attributedOnly),
              backgroundColor: "color-mix(in oklab, var(--color-cat-technique) 38%, transparent)",
            }}
          />
        )}
      </div>
      <span className="w-[68px] shrink-0 text-right text-xs tabular-nums text-muted">
        <span className="font-medium text-fg">{row.attributedTechniques}</span>
        {row.observedTechniques > 0 ? (
          <>
            {" "}
            / <span className="font-medium text-fg">{row.observedTechniques}</span>
          </>
        ) : null}
      </span>
      <span className="sr-only">{total} techniques</span>
    </div>
  );
}

export function TechniqueBarLegend() {
  const item = (color: string, label: string) => (
    <span className="inline-flex items-center gap-1.5">
      <span className="size-2 rounded-sm" style={{ backgroundColor: color }} />
      {label}
    </span>
  );
  return (
    <div className="flex flex-wrap items-center gap-x-4 gap-y-1 text-xs text-muted">
      <span className="text-subtle">Techniques (ATT&CK / observed):</span>
      {item("var(--color-cat-technique)", "Observed, in ATT&CK")}
      {item("var(--color-warn)", "Observed, new vs ATT&CK")}
      {item("color-mix(in oklab, var(--color-cat-technique) 38%, transparent)", "ATT&CK only")}
    </div>
  );
}

export function EmulationCell({ emu }: { emu: ActorEmulationSummary }) {
  if (!emu.synced) return <span className="text-xs text-subtle">Not synced</span>;
  const pct = emu.techniqueTotal ? Math.round((emu.atomicCovered / emu.techniqueTotal) * 100) : 0;
  return (
    <span className="inline-flex items-center gap-2 text-xs">
      {emu.ctidPlans > 0 && (
        <span
          className="inline-flex items-center gap-1 font-medium"
          style={{ color: "var(--color-cat-emulation)" }}
        >
          <FlaskConical className="size-3.5" strokeWidth={1.9} />
          CTID plan
        </span>
      )}
      <span
        className="tabular-nums text-muted"
        title={`${emu.atomicCovered} of ${emu.techniqueTotal} techniques have an Atomic test`}
      >
        Atomic {pct}%
      </span>
    </span>
  );
}

export function ExternalA({
  href,
  children,
  className,
}: {
  href: string;
  children: React.ReactNode;
  className?: string;
}) {
  return (
    <a
      href={href}
      target="_blank"
      rel="noreferrer"
      className={cn("text-accent hover:underline", className)}
      onClick={(e) => e.stopPropagation()}
    >
      {children}
    </a>
  );
}

export function ActorLink({
  id,
  children,
  className,
}: {
  id: string;
  children: React.ReactNode;
  className?: string;
}) {
  return (
    <Link
      to="/actors/$actorId"
      params={{ actorId: id }}
      className={cn("hover:underline", className)}
    >
      {children}
    </Link>
  );
}
