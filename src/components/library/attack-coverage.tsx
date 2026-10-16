import { TACTIC_ORDER, normalizeTactic, type TechniqueRef } from "./intel-taxonomy";
import { cn } from "@/lib/cn";

const SHORT: Record<string, string> = {
  Reconnaissance: "Recon",
  "Resource Development": "Resource dev",
  "Initial Access": "Initial access",
  Execution: "Execution",
  Persistence: "Persistence",
  "Privilege Escalation": "Priv. escalation",
  "Defense Evasion": "Defense evasion",
  "Credential Access": "Credential access",
  Discovery: "Discovery",
  "Lateral Movement": "Lateral movement",
  Collection: "Collection",
  "Command and Control": "C2",
  Exfiltration: "Exfiltration",
  Impact: "Impact",
};

/** ATT&CK coverage strip: one cell per enterprise tactic, tinted by technique count. */
export function AttackCoverageStrip({ techniques, onSelectTactic }: { techniques: TechniqueRef[]; onSelectTactic?: (tactic: string) => void }) {
  const by = new Map<string, TechniqueRef[]>();
  for (const t of techniques) {
    const n = normalizeTactic(t.tactic);
    if (n) by.set(n, [...(by.get(n) ?? []), t]);
  }
  const max = Math.max(1, ...Array.from(by.values()).map((v) => v.length));
  const unmapped = techniques.filter((t) => !normalizeTactic(t.tactic)).length;
  const covered = by.size;

  return (
    <div>
      <div className="mb-3 flex flex-wrap items-baseline gap-x-4 gap-y-1 text-sm text-muted">
        <span>
          <span className="font-semibold tabular-nums text-fg">{covered}</span> of 14 tactics
        </span>
        <span>
          <span className="font-semibold tabular-nums text-fg">{techniques.length}</span> techniques
        </span>
        {unmapped > 0 && <span className="text-subtle">{unmapped} without a tactic in the bundled ATT&CK data</span>}
      </div>
      <div className="grid grid-cols-3 gap-1.5 sm:grid-cols-4 lg:grid-cols-7">
        {TACTIC_ORDER.map((tactic) => {
          const list = by.get(tactic) ?? [];
          const n = list.length;
          const pct = n ? 18 + Math.round((n / max) * 42) : 0;
          return (
            <button
              key={tactic}
              type="button"
              disabled={!n || !onSelectTactic}
              onClick={() => onSelectTactic?.(tactic)}
              title={n ? `${tactic}: ${list.map((t) => t.id + (t.name ? ` ${t.name}` : "")).join(", ")}` : `${tactic}: not observed`}
              className={cn(
                "flex min-h-[64px] flex-col justify-between rounded-lg border px-2.5 py-2 text-left transition-colors",
                n ? "border-transparent" : "border-dashed border-border",
                n && onSelectTactic && "hover:brightness-110",
              )}
              style={
                n
                  ? {
                      backgroundColor: `color-mix(in oklab, var(--color-cat-technique) ${pct}%, transparent)`,
                    }
                  : undefined
              }
            >
              <span className={cn("text-[11px] font-medium leading-tight", n ? "text-fg" : "text-subtle")}>{SHORT[tactic]}</span>
              <span className={cn("text-lg font-semibold leading-none tabular-nums", n ? "text-fg" : "text-subtle/60")}>{n || "–"}</span>
            </button>
          );
        })}
      </div>
    </div>
  );
}
