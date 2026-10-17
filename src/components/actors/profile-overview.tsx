import { Link } from "@tanstack/react-router";
import { Bug, CalendarRange, Layers, ShieldAlert } from "lucide-react";
import type { ActorProfile } from "@/lib/aie/actors/types";
import { SectionCard } from "@/components/layout/page";
import { TwoUp } from "@/components/templates/page-templates";
import { EntityChip } from "@/components/ui/entity";
import { EmptyState } from "@/components/ui/primitives";
import { AttackCoverageStrip } from "@/components/library/attack-coverage";
import type { TechniqueRef } from "@/components/library/intel-taxonomy";
import { TacticDot } from "./actor-ui";
import { attackTechniqueUrl, formatDay, shortTactic, tacticHue } from "./actor-format";

/** Report timeline: one row per library report, newest first, on a vertical rule. */
function ReportTimeline({ profile }: { profile: ActorProfile }) {
  const reports = profile.reports.slice(0, 8);
  if (!reports.length) {
    return (
      <EmptyState
        icon={CalendarRange}
        title="No library reports name this actor yet"
        description={
          profile.row.inAttack
            ? "Everything on this page comes from the bundled ATT&CK knowledge. Reports that mention the group or one of its aliases will appear here once ingested."
            : "This actor is not in ATT&CK."
        }
      />
    );
  }
  return (
    <ol className="relative ml-1.5 space-y-5 border-l border-border pl-5">
      {reports.map((r) => (
        <li key={r.id} className="relative">
          <span
            aria-hidden
            className="absolute -left-[26px] top-1 size-2.5 rounded-full ring-4 ring-[var(--color-bg-card)]"
            style={{ backgroundColor: "var(--color-cat-advisory)" }}
          />
          <div className="text-xs tabular-nums text-subtle">
            {formatDay(r.publishedAt ?? r.ingestedAt) ?? "Undated"}
          </div>
          <Link
            to="/library/$reportId"
            params={{ reportId: r.id }}
            className="mt-0.5 block text-sm font-medium text-fg hover:underline"
          >
            {r.title}
          </Link>
          <div className="mt-1 flex flex-wrap items-center gap-x-3 gap-y-1 text-xs text-muted">
            {r.publisher && <span>{r.publisher}</span>}
            <span>{r.techniqueCount} techniques</span>
            <span className="text-subtle">
              Linked by {r.matchedBy === "analysis" ? "extracted actor" : "name in text"} “
              {r.matched}”
            </span>
          </div>
        </li>
      ))}
      {profile.reports.length > reports.length && (
        <li className="text-xs text-subtle">
          +{profile.reports.length - reports.length} older reports in the Reports tab
        </li>
      )}
    </ol>
  );
}

/** Top observed techniques as bars coloured by tactic; falls back to ATT&CK-attributed ones. */
function TopTechniques({ profile }: { profile: ActorProfile }) {
  const observed = profile.techniques.filter((t) => t.source !== "attack");
  const list = (observed.length ? observed : profile.techniques).slice(0, 10);
  if (!list.length) return <EmptyState icon={Layers} title="No techniques recorded" />;
  // Weight = reports, then evidence quotes; bars only when the weights actually differ.
  const weight = (t: (typeof list)[number]) => t.observedReports * 100 + t.evidenceCount;
  const weights = list.map(weight);
  const max = Math.max(1, ...weights);
  const showBars = observed.length > 0 && Math.min(...weights) !== max;
  return (
    <div>
      {!observed.length && (
        <p className="mb-3 text-xs text-subtle">
          No observed techniques in the library; showing ATT&CK-attributed techniques.
        </p>
      )}
      <ul className="divide-y divide-border">
        {list.map((t) => (
          <li key={t.id} className="py-2 first:pt-0 last:pb-0">
            <div className="flex min-w-0 items-center gap-2 text-sm">
              <TacticDot tactic={t.tactic} />
              <a
                href={attackTechniqueUrl(t.id)}
                target="_blank"
                rel="noreferrer"
                className="shrink-0 font-mono text-xs text-muted hover:underline"
              >
                {t.id}
              </a>
              <span className="min-w-0 flex-1 truncate text-fg" title={t.name}>
                {t.name}
              </span>
              {t.isNew && (
                <span
                  className="shrink-0 text-xs font-medium"
                  style={{ color: "var(--color-warn)" }}
                  title="Observed but not attributed by ATT&CK"
                >
                  New
                </span>
              )}
            </div>
            <div className="mt-1 flex items-center gap-3 pl-4">
              {showBars ? (
                <div className="h-1 flex-1 overflow-hidden rounded-full bg-bg-subtle">
                  <div
                    className="h-full rounded-full"
                    style={{
                      width: `${Math.max(6, (weight(t) / max) * 100)}%`,
                      backgroundColor: tacticHue(t.tactic),
                    }}
                  />
                </div>
              ) : (
                <span className="flex-1 truncate text-xs text-subtle">
                  {t.tactic ? shortTactic(t.tactic) : "No tactic"}
                </span>
              )}
              {observed.length > 0 && (
                <span className="shrink-0 text-xs tabular-nums text-subtle">
                  {t.observedReports} report{t.observedReports === 1 ? "" : "s"} · {t.evidenceCount}{" "}
                  quote{t.evidenceCount === 1 ? "" : "s"}
                </span>
              )}
            </div>
          </li>
        ))}
      </ul>
    </div>
  );
}

export function ProfileOverview({
  profile,
  onTab,
}: {
  profile: ActorProfile;
  onTab: (tab: "techniques" | "software") => void;
}) {
  const refs: TechniqueRef[] = profile.techniques.map((t) => ({
    id: t.id,
    name: t.name,
    tactic: t.tactic,
    label:
      t.source === "attack" ? "mapped" : t.labels.includes("observed") ? "observed" : "inferred",
  }));
  const observedRefs = refs.filter((_, i) => profile.techniques[i].source !== "attack");
  const malware = profile.software.filter((s) => s.observedReports > 0 || s.attributed);
  const shown = malware.slice(0, 16);

  return (
    <>
      <TwoUp>
        <SectionCard
          title="Report timeline"
          icon={CalendarRange}
          iconKind="advisory"
          className="min-w-0 xl:self-start"
        >
          <ReportTimeline profile={profile} />
        </SectionCard>
        <SectionCard
          title={
            profile.techniques.some((t) => t.source !== "attack")
              ? "Top observed techniques"
              : "ATT&CK techniques"
          }
          icon={Layers}
          iconKind="technique"
          className="min-w-0"
          actions={
            <button
              type="button"
              onClick={() => onTab("techniques")}
              className="text-sm text-accent hover:underline"
            >
              All techniques →
            </button>
          }
        >
          <TopTechniques profile={profile} />
        </SectionCard>
      </TwoUp>

      <SectionCard
        title="Tactic coverage"
        icon={Layers}
        iconKind="technique"
        info="Attributed (ATT&CK) and observed (library) techniques, counted under their primary tactic."
      >
        <AttackCoverageStrip techniques={refs} />
        {observedRefs.length > 0 && observedRefs.length < refs.length && (
          <div className="mt-4 flex flex-wrap gap-x-4 gap-y-1.5 text-xs text-muted">
            {profile.tacticCoverage.map((c) => (
              <span key={c.tactic} className="inline-flex items-center gap-1.5">
                <span
                  className="size-2 rounded-full"
                  style={{ backgroundColor: tacticHue(c.tactic) }}
                />
                {shortTactic(c.tactic)}
                <span className="tabular-nums text-subtle">
                  {c.attributed} ATT&CK · {c.observed} observed
                </span>
              </span>
            ))}
          </div>
        )}
      </SectionCard>

      <TwoUp>
        <SectionCard
          title="Malware and tools"
          icon={Bug}
          iconKind="malware"
          className="min-w-0"
          actions={
            malware.length > shown.length ? (
              <button
                type="button"
                onClick={() => onTab("software")}
                className="text-sm text-accent hover:underline"
              >
                All {malware.length} →
              </button>
            ) : undefined
          }
        >
          {shown.length ? (
            <div className="flex flex-wrap gap-1.5">
              {shown.map((s) => (
                <EntityChip
                  key={s.id ?? s.name}
                  kind="malware"
                  title={`${s.name}${s.id ? ` (${s.id})` : ""}: ${s.attributed ? "ATT&CK-attributed" : "not attributed in ATT&CK"}${s.observedReports ? `, in ${s.observedReports} library report(s)` : ""}`}
                >
                  {s.name}
                  {s.observedReports > 0 && !s.attributed ? " · new" : ""}
                </EntityChip>
              ))}
            </div>
          ) : (
            <EmptyState icon={Bug} title="No software recorded for this actor" />
          )}
        </SectionCard>
        <SectionCard title="Vulnerabilities" icon={ShieldAlert} iconKind="cve" className="min-w-0">
          {profile.cves.length ? (
            <div className="flex flex-wrap gap-1.5">
              {profile.cves.map((c) => (
                <EntityChip
                  key={c.id}
                  kind="cve"
                  title={`${c.id}: in ${c.reports} library report(s)`}
                >
                  {c.id}
                </EntityChip>
              ))}
            </div>
          ) : (
            <EmptyState
              icon={ShieldAlert}
              title="No CVEs in this actor's library reports"
              description={
                profile.reports.length
                  ? "None of the linked reports cite a CVE."
                  : "CVEs come from library reports; none are linked yet."
              }
            />
          )}
        </SectionCard>
      </TwoUp>
    </>
  );
}
