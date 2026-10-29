import { Route } from "lucide-react";
import { StatusChip, type Tone } from "@/components/ui/primitives";
import { EMULATION_GRADE_META, type EmulationGrade, type EmulationSummary } from "@/lib/aie/emulation-value";

export const EMULATION_TONE: Record<EmulationGrade, Tone> = { chain: "success", procedures: "info", context: "neutral", news: "warning" };

/** Emulation value of a report ("Attack chain", "Procedures" …), with its reasons on hover. */
export function EmulationBadge({ value, compact }: { value?: EmulationSummary | null; compact?: boolean }) {
  if (!value) return null;
  const meta = EMULATION_GRADE_META[value.grade];
  const title = [`Emulation value: ${meta.label} (${value.score}/100)`, meta.description, ...value.signals.map((s) => `• ${s}`)].join("\n");
  return (
    <span title={title}>
      <StatusChip tone={EMULATION_TONE[value.grade]}>
        <Route className="size-3" aria-hidden />
        {compact ? meta.short : meta.label}
      </StatusChip>
    </span>
  );
}
