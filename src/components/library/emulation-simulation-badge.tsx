import { Route } from "lucide-react";
import { StatusChip, type Tone } from "@/components/ui/primitives";
import { EMULATION_SIMULATION_GRADE_META, type EmulationSimulationGrade, type EmulationSimulationSummary } from "@/lib/aie/emulation-simulation";

export const EMULATION_SIMULATION_TONE: Record<EmulationSimulationGrade, Tone> = { chain: "success", procedures: "info", context: "neutral", news: "warning" };

/** Emulation & simulation value of a report ("Attack chain", "Procedures" …), with its reasons on hover. */
export function EmulationSimulationBadge({ value, compact }: { value?: EmulationSimulationSummary | null; compact?: boolean }) {
  if (!value) return null;
  const meta = EMULATION_SIMULATION_GRADE_META[value.grade];
  const title = [`Emulation & simulation value: ${meta.label} (${value.score}/100)`, meta.description, ...value.signals.map((s) => `• ${s}`)].join("\n");
  return (
    <span title={title}>
      <StatusChip tone={EMULATION_SIMULATION_TONE[value.grade]}>
        <Route className="size-3" aria-hidden />
        {compact ? meta.short : meta.label}
      </StatusChip>
    </span>
  );
}
