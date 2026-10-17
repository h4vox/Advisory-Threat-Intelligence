import { AlertTriangle, Sparkles, X } from "lucide-react";
import type { InterpretedChip, InterpretedQuery } from "@/lib/aie/search/types";
import { entityMeta, type EntityKind } from "@/components/ui/entity";

const CHIP_COLOR: Partial<Record<InterpretedChip["kind"], EntityKind>> = {
  actor: "actor",
  campaign: "actor",
  software: "malware",
  technique: "technique",
  tactic: "technique",
  cve: "cve",
  type: "advisory",
  tier: "source",
  publisher: "source",
};

function Chip({ chip, onRemove }: { chip: InterpretedChip; onRemove: () => void }) {
  const kind = CHIP_COLOR[chip.kind];
  const color = kind ? entityMeta(kind).color : "var(--color-muted)";
  const style = kind
    ? { color, backgroundColor: `color-mix(in oklab, ${color} 13%, transparent)`, borderColor: `color-mix(in oklab, ${color} 28%, transparent)` }
    : { color: "var(--color-fg)", backgroundColor: "var(--color-bg-subtle)", borderColor: "var(--color-border)" };
  const title = chip.implicit
    ? `Recognised automatically${chip.detail ? `: ${chip.detail}` : ""}. Remove to search the words literally.`
    : chip.detail ?? chip.label;
  return (
    <span
      title={title}
      className={`inline-flex max-w-full items-center gap-1.5 rounded-md border py-0.5 pl-2 pr-0.5 text-xs font-medium ${chip.implicit ? "border-dashed" : ""}`}
      style={style}
    >
      <span className="truncate">{chip.label}</span>
      {chip.detail && <span className="hidden truncate font-normal opacity-75 sm:inline">{chip.detail}</span>}
      <button
        type="button"
        onClick={onRemove}
        aria-label={`Remove ${chip.label}`}
        className="flex size-5 shrink-0 items-center justify-center rounded opacity-70 hover:bg-[color-mix(in_oklab,currentColor_14%,transparent)] hover:opacity-100"
      >
        <X className="size-3" />
      </button>
    </span>
  );
}

/** "Interpreted as" row: one removable chip per recognised clause, plus parser warnings. */
export function InterpretedChips({ interpreted, onQuery }: { interpreted: InterpretedQuery; onQuery: (q: string) => void }) {
  if (interpreted.chips.length === 0 && interpreted.warnings.length === 0) {
    return interpreted.terms.length ? (
      <p className="text-xs text-subtle">
        Keyword search for <span className="text-muted">{interpreted.terms.join(" ")}</span>. No actor, technique or field was recognised.
      </p>
    ) : null;
  }
  return (
    <div className="space-y-2">
      {interpreted.chips.length > 0 && (
        <div className="flex flex-wrap items-center gap-1.5">
          <span className="mr-1 inline-flex items-center gap-1 text-xs text-muted">
            <Sparkles className="size-3.5 text-[var(--color-primary)]" strokeWidth={1.9} />
            Interpreted as
          </span>
          {interpreted.chips.map((c) => (
            <Chip key={c.key} chip={c} onRemove={() => onQuery(c.without)} />
          ))}
        </div>
      )}
      {interpreted.warnings.map((w) => (
        <p key={w} className="flex items-center gap-1.5 text-xs text-warn">
          <AlertTriangle className="size-3.5 shrink-0" />
          {w}
        </p>
      ))}
    </div>
  );
}
