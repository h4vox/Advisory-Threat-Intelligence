import { Link } from "@tanstack/react-router";
import type { ActorRow } from "@/lib/aie/actors/types";
import { EntityIcon } from "@/components/ui/entity";
import { StatusChip } from "@/components/ui/primitives";
import { EmulationCell, TacticDot } from "./actor-ui";
import { formatDay, shortTactic } from "./actor-format";

function Count({ label, value }: { label: string; value: number }) {
  return (
    <div className="min-w-0">
      <div className="text-lg font-semibold leading-none tabular-nums text-fg">{value}</div>
      <div className="mt-1 truncate text-xs text-muted">{label}</div>
    </div>
  );
}

/** Card view of one actor: identity, aliases, top tactics and counts. */
export function ActorCard({ row }: { row: ActorRow }) {
  const aliases = row.aliases.slice(0, 4);
  const more = row.aliases.length - aliases.length;
  return (
    <Link
      to="/actors/$actorId"
      params={{ actorId: row.id }}
      className="group flex min-w-0 flex-col rounded-xl border border-border bg-bg-card p-5 transition-colors hover:bg-bg-subtle/60 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[var(--color-primary)]"
      style={
        row.observed
          ? { borderColor: "color-mix(in oklab, var(--color-cat-actor) 32%, var(--color-border))" }
          : undefined
      }
    >
      <div className="flex items-start gap-3">
        <EntityIcon kind="actor" />
        <div className="min-w-0 flex-1">
          <div className="flex items-center gap-2">
            <span className="truncate text-[15px] font-medium text-fg group-hover:underline">
              {row.name}
            </span>
          </div>
          <div className="mt-0.5 font-mono text-xs text-subtle">
            {row.attackId ?? "Not in ATT&CK"}
          </div>
        </div>
        {row.observed && (
          <StatusChip tone="info" dot>
            In library
          </StatusChip>
        )}
      </div>

      <p className="mt-3 line-clamp-2 min-h-[2.5rem] text-sm text-muted">
        {aliases.length ? (
          <>
            <span className="text-subtle">Also: </span>
            {aliases.join(", ")}
            {more > 0 && <span className="text-subtle"> +{more}</span>}
          </>
        ) : (
          <span className="text-subtle">No aliases recorded</span>
        )}
      </p>

      <div className="mt-3 flex min-h-[1.5rem] flex-wrap gap-x-3 gap-y-1">
        {row.topTactics.length ? (
          row.topTactics.map((t) => (
            <span key={t.tactic} className="inline-flex items-center gap-1.5 text-xs text-muted">
              <TacticDot tactic={t.tactic} />
              {shortTactic(t.tactic)}
              <span className="tabular-nums text-subtle">{t.count}</span>
            </span>
          ))
        ) : (
          <span className="text-xs text-subtle">No techniques mapped</span>
        )}
      </div>

      <div className="mt-4 grid grid-cols-4 gap-3 border-t border-border pt-4">
        <Count label="Reports" value={row.reportCount} />
        <Count label="Techniques" value={row.attributedTechniques + row.newTechniques} />
        <Count label="Software" value={row.software} />
        <Count label="Campaigns" value={row.campaigns} />
      </div>

      <div className="mt-4 flex items-center justify-between gap-2 text-xs text-subtle">
        <span>{row.lastSeen ? `Last seen ${formatDay(row.lastSeen)}` : "Not seen in library"}</span>
        <EmulationCell emu={row.emulation} />
      </div>
    </Link>
  );
}
