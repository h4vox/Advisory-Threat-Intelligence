import { useQuery } from "@tanstack/react-query";
import { Link } from "@tanstack/react-router";
import { Telescope } from "lucide-react";
import { SectionCard } from "@/components/layout/page";
import { RESEARCH_CATEGORIES, type ResearchCategory } from "@/lib/aie/research-taxonomy";
import { getResearchCoverage } from "@/lib/aie/server-library";
import { cn } from "@/lib/cn";

/** Fewer reports than this marks a category as thin. */
const THIN = 3;

function Row({ c, n, max }: { c: ResearchCategory; n: number; max: number }) {
  const state = n === 0 ? "none" : n < THIN ? "thin" : "ok";
  return (
    <li>
      <Link
        to="/library"
        search={{ research: c.id }}
        title={`${c.label}: ${c.types.join(", ")}`}
        className="group grid grid-cols-[minmax(0,12rem)_minmax(0,1fr)_2.5rem] items-center gap-3 rounded-md px-2 py-1.5 transition-colors hover:bg-bg-subtle/60"
      >
        <span className="truncate text-sm text-fg group-hover:underline">{c.short}</span>
        <span className="h-1.5 overflow-hidden rounded-full bg-bg-subtle" aria-hidden>
          <span
            className={cn("block h-full rounded-full", state === "ok" ? "bg-accent" : "bg-warn")}
            style={{ width: `${max ? Math.max(n ? 4 : 0, Math.round((n / max) * 100)) : 0}%` }}
          />
        </span>
        <span className={cn("text-right text-xs tabular-nums", state === "ok" ? "text-muted" : "text-warn")}>
          {n}
          <span className="sr-only">{state === "none" ? " reports, none yet" : state === "thin" ? " reports, thin" : " reports"}</span>
        </span>
      </Link>
    </li>
  );
}

/**
 * How much of each kind of attack research the library holds (./research-taxonomy). The crawler
 * searches the thinnest categories first; each row opens the Library filtered to that category.
 */
export function ResearchCoverageCard() {
  const q = useQuery({ queryKey: ["research-coverage"], queryFn: () => getResearchCoverage(), staleTime: 60_000 });
  const data = q.data;
  const counts = data?.counts;
  const max = counts ? Math.max(1, ...Object.values(counts)) : 1;
  const core = RESEARCH_CATEGORIES.filter((c) => c.scope === "core");
  const bas = RESEARCH_CATEGORIES.filter((c) => c.scope === "bas");
  // Lessons and trends are thin by nature and searched in rotation only, so they are not called out.
  const gaps = counts ? core.filter((c) => !c.noGapBoost && (counts[c.id] ?? 0) < THIN).map((c) => c.short) : [];

  return (
    <SectionCard
      icon={Telescope}
      title="Research coverage"
      actions={
        data ? (
          <span className="text-xs text-subtle">
            {data.labelled.toLocaleString()} of {data.total.toLocaleString()} reports labelled
            {data.pending > 0 ? ` · ${data.pending.toLocaleString()} waiting (open the Library to label them)` : ""}
          </span>
        ) : undefined
      }
      className="mb-6"
    >
      <p className="mb-4 max-w-3xl text-sm text-muted">
        The kinds of attack research the library holds, from campaigns and attack chains to detection material. The crawler searches the thinnest
        categories first, so coverage evens out over time.
        {gaps.length > 0 && <span className="text-warn"> Thin now: {gaps.join(", ")}.</span>}
      </p>
      {q.isError ? (
        <p className="text-sm text-danger">Coverage could not be loaded: {q.error instanceof Error ? q.error.message : "unknown error"}</p>
      ) : !counts ? (
        <p className="text-sm text-subtle">Loading coverage…</p>
      ) : (
        <div className="grid gap-x-8 gap-y-4 lg:grid-cols-[minmax(0,2fr)_minmax(0,1fr)]">
          <div>
            <h3 className="mb-1 px-2 text-[11px] font-medium uppercase tracking-wide text-subtle">Threat behaviour</h3>
            <ul className="grid gap-x-6 md:grid-cols-2">
              {core.map((c) => (
                <Row key={c.id} c={c} n={counts[c.id] ?? 0} max={max} />
              ))}
            </ul>
          </div>
          <div>
            <h3 className="mb-1 px-2 text-[11px] font-medium uppercase tracking-wide text-subtle">Detection and emulation (optional BAS)</h3>
            <ul>
              {bas.map((c) => (
                <Row key={c.id} c={c} n={counts[c.id] ?? 0} max={max} />
              ))}
            </ul>
            <p className="mt-2 px-2 text-xs text-subtle">
              Searched for only when chosen in{" "}
              <Link to="/settings" className="text-accent hover:underline">
                Settings
              </Link>
              . Labelled whenever a report carries such material.
            </p>
          </div>
        </div>
      )}
    </SectionCard>
  );
}
