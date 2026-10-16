import { useMemo, useState, type ReactNode } from "react";
import { ArrowRight, ChevronRight, Info } from "lucide-react";
import type {
  EntityRef,
  Evidence,
  EvidencedValue,
  IntelAnalysis,
  IntelEvidence,
  IocHit,
  TargetingFact,
} from "@/lib/aie/types";
import { cn } from "@/lib/cn";
import {
  ConfidenceText,
  EvidenceQuote,
  EvidenceQuotes,
  LabelChip,
  MethodBadge,
  StatusChip,
} from "./evidence-chips";
import { SourceTextDialog } from "./source-text-dialog";
import { LABEL_HINT, MAPPED_BY_TEXT, PREDICATE_TEXT, QuoteOpenContext, TARGET_KIND_TEXT } from "./evidence-utils";

type SectionKey = "techniques" | "entities" | "targeting" | "relationships" | "chain" | "iocs";

const SECTION_TITLES: Record<SectionKey, string> = {
  techniques: "Techniques",
  entities: "Actors & malware",
  targeting: "Targeting",
  relationships: "Relationships",
  chain: "Attack chain",
  iocs: "IOCs",
};

export function EvidencePanel({
  analysis,
  iocs,
  extractedText,
}: {
  analysis: IntelAnalysis | null | undefined;
  iocs: IocHit[];
  extractedText: string;
}) {
  const evidence = analysis?.evidence;
  const [active, setActive] = useState<Evidence | null>(null);
  const [section, setSection] = useState<SectionKey>(evidence ? "techniques" : "iocs");

  const counts: Record<SectionKey, number> = {
    techniques: evidence?.techniques.length ?? 0,
    entities: (evidence?.actors.length ?? 0) + (evidence?.malware.length ?? 0),
    targeting: evidence?.targeting.length ?? 0,
    relationships: evidence?.relationships.length ?? 0,
    chain: evidence?.chain.steps.length ?? 0,
    iocs: iocs.length,
  };
  const sections: SectionKey[] = evidence
    ? ["techniques", "entities", "targeting", "relationships", "chain", "iocs"]
    : ["iocs"];

  return (
    <QuoteOpenContext.Provider value={setActive}>
      <div className="mt-6 min-w-0 space-y-4">
        <div className="rounded-xl border border-border bg-bg-card p-5">
          <div className="flex flex-col gap-3 sm:flex-row sm:items-start sm:justify-between">
            <div className="min-w-0">
              <div className="text-base font-medium text-fg">Evidence</div>
              <p className="mt-1 text-sm text-muted">
                Every extracted fact with the passage that supports it. Select a quote to see it in the full
                extracted text.
              </p>
            </div>
          </div>
          <div className="mt-3 border-t border-border pt-3">
            <MethodBadge analysis={analysis} />
          </div>
        </div>

        {!evidence ? (
          <div
            role="note"
            className="flex gap-3 rounded-xl border border-warn/30 bg-warn/5 p-4 text-sm text-muted"
          >
            <Info className="mt-0.5 size-4 shrink-0 text-warn" aria-hidden />
            <p>
              This report was analysed before evidence tracking; re-run analysis to see supporting passages.
            </p>
          </div>
        ) : null}

        <div role="tablist" aria-label="Evidence sections" className="inline-flex max-w-full flex-wrap gap-0.5 rounded-lg border border-border bg-bg-elevated p-0.5">
          {sections.map((key) => (
            <button
              key={key}
              type="button"
              role="tab"
              aria-selected={section === key}
              onClick={() => setSection(key)}
              className={cn(
                "inline-flex h-8 items-center gap-2 rounded-md px-3 text-sm font-medium transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring/70",
                section === key ? "bg-bg-subtle text-fg" : "text-muted hover:text-fg",
              )}
            >
              {SECTION_TITLES[key]}
              <span className="rounded bg-bg px-1.5 py-px text-[11px] text-subtle tabular-nums">{counts[key]}</span>
            </button>
          ))}
        </div>

        <div role="tabpanel" aria-label={SECTION_TITLES[section]} className="min-w-0">
          {evidence && section === "techniques" && <TechniquesSection evidence={evidence} />}
          {evidence && section === "entities" && <EntitiesSection evidence={evidence} />}
          {evidence && section === "targeting" && <TargetingSection evidence={evidence} />}
          {evidence && section === "relationships" && <RelationshipsSection evidence={evidence} />}
          {evidence && section === "chain" && <ChainSection evidence={evidence} />}
          {section === "iocs" && <IocSection iocs={iocs} />}
        </div>

        {evidence ? <ExcludedSection excluded={evidence.excluded} /> : null}
      </div>

      <SourceTextDialog text={extractedText} evidence={active} onClose={() => setActive(null)} />
    </QuoteOpenContext.Provider>
  );
}

// ---------------------------------------------------------------------------

function Card({ children, className }: { children: ReactNode; className?: string }) {
  return (
    <div className={cn("min-w-0 rounded-xl border border-border bg-bg-card p-4", className)}>{children}</div>
  );
}

function Empty({ children }: { children: ReactNode }) {
  return (
    <div className="rounded-xl border border-border bg-bg-card p-8 text-center text-sm text-muted">
      {children}
    </div>
  );
}

function SubHeading({ children, hint }: { children: ReactNode; hint?: ReactNode }) {
  return (
    <div className="mb-2">
      <h3 className="text-sm font-medium text-fg">{children}</h3>
      {hint ? <p className="mt-0.5 text-[11px] text-subtle">{hint}</p> : null}
    </div>
  );
}

const labelRank = (label: string) => (label === "observed" ? 0 : label === "inferred" ? 1 : 2);

function TechniquesSection({ evidence }: { evidence: IntelEvidence }) {
  const techniques = useMemo(
    () =>
      [...evidence.techniques].sort(
        (a, b) => labelRank(a.label) - labelRank(b.label) || a.id.localeCompare(b.id),
      ),
    [evidence.techniques],
  );
  if (techniques.length === 0) return <Empty>No techniques were extracted from this report.</Empty>;

  return (
    <div className="space-y-3">
      <p className="flex flex-wrap items-center gap-x-2 gap-y-1 text-[11px] text-subtle">
        <LabelChip label="observed" /> reported in the source
        <span aria-hidden>·</span>
        <LabelChip label="inferred" /> mapped from a behaviour keyword
      </p>
      {techniques.map((t, idx) => (
        <Card key={`${t.id}-${idx}`}>
          <div className="flex flex-wrap items-center gap-2">
            <span className="font-mono text-xs text-muted">{t.id}</span>
            <span className="min-w-0 text-sm font-medium text-fg [overflow-wrap:anywhere]">{t.name}</span>
            <LabelChip label={t.label} />
          </div>
          <div className="mt-1 flex flex-wrap items-center gap-x-3 gap-y-1 text-[11px] text-muted">
            <span>
              Tactic: <span className="text-fg">{t.tactic || "—"}</span>
            </span>
            <span>
              Mapped by: <span className="text-fg">{MAPPED_BY_TEXT[t.mappedBy] ?? t.mappedBy}</span>
            </span>
            <ConfidenceText value={t.confidence} />
          </div>
          {t.label === "inferred" ? (
            <p className="mt-1 text-[11px] italic text-subtle">{LABEL_HINT.inferred}</p>
          ) : null}
          <div className="mt-3">
            <EvidenceQuotes evidence={t.evidence} />
          </div>
        </Card>
      ))}
    </div>
  );
}

function EvidencedValueRow({ item }: { item: EvidencedValue }) {
  return (
    <div className="min-w-0 border-t border-border pt-3 first:border-t-0 first:pt-0">
      <div className="flex flex-wrap items-center gap-2">
        <span className="text-sm font-medium text-fg [overflow-wrap:anywhere]">{item.value}</span>
        <LabelChip label={item.label} />
        <ConfidenceText value={item.confidence} />
      </div>
      <div className="mt-2">
        <EvidenceQuotes evidence={item.evidence} max={2} />
      </div>
    </div>
  );
}

function EntityGroup({ title, items, emptyText }: { title: string; items: EvidencedValue[]; emptyText: string }) {
  const attributed = items.filter((i) => i.label === "observed");
  const mentioned = items.filter((i) => i.label !== "observed");
  return (
    <Card>
      <SubHeading>{title}</SubHeading>
      {attributed.length > 0 ? (
        <div className="space-y-3">
          {attributed.map((i, idx) => (
            <EvidencedValueRow key={`${i.value}-${idx}`} item={i} />
          ))}
        </div>
      ) : (
        <p className="text-xs text-muted">{emptyText}</p>
      )}
      {mentioned.length > 0 ? (
        <div className="mt-4 rounded-lg border border-dashed border-border p-3">
          <SubHeading hint="Named in the text, e.g. as defensive guidance or background reference — not attributed to this activity.">
            Mentioned but not attributed
          </SubHeading>
          <div className="space-y-3">
            {mentioned.map((i, idx) => (
              <EvidencedValueRow key={`${i.value}-m-${idx}`} item={i} />
            ))}
          </div>
        </div>
      ) : null}
    </Card>
  );
}

function EntitiesSection({ evidence }: { evidence: IntelEvidence }) {
  return (
    <div className="grid gap-3 lg:grid-cols-2">
      <EntityGroup title="Threat actors" items={evidence.actors} emptyText="No actor attributed in the source." />
      <EntityGroup title="Malware & tools" items={evidence.malware} emptyText="No malware observed in the source." />
    </div>
  );
}

const STATUS_RANK: Record<TargetingFact["status"], number> = {
  compromised: 0,
  targeted: 1,
  at_risk: 2,
  mentioned: 3,
};

function TargetingSection({ evidence }: { evidence: IntelEvidence }) {
  const groups = useMemo(() => {
    const map = new Map<TargetingFact["kind"], TargetingFact[]>();
    for (const t of evidence.targeting) {
      const list = map.get(t.kind) ?? [];
      list.push(t);
      map.set(t.kind, list);
    }
    for (const list of map.values()) list.sort((a, b) => STATUS_RANK[a.status] - STATUS_RANK[b.status]);
    return [...map.entries()];
  }, [evidence.targeting]);

  if (groups.length === 0) return <Empty>No targeting information was extracted.</Empty>;

  return (
    <div className="space-y-3">
      <p className="text-[11px] text-subtle">
        Targeted / compromised = the source reports it happened · At risk = exposure or advisory audience ·
        Mentioned = named without a claim.
      </p>
      {groups.map(([kind, facts]) => (
        <Card key={kind}>
          <SubHeading>{TARGET_KIND_TEXT[kind] ?? kind}</SubHeading>
          <div className="space-y-3">
            {facts.map((f, idx) => (
              <div
                key={`${f.value}-${idx}`}
                className="min-w-0 border-t border-border pt-3 first:border-t-0 first:pt-0"
              >
                <div className="flex flex-wrap items-center gap-2">
                  <span className="text-sm font-medium text-fg [overflow-wrap:anywhere]">{f.value}</span>
                  <StatusChip status={f.status} />
                  <ConfidenceText value={f.confidence} />
                </div>
                <div className="mt-2">
                  <EvidenceQuotes evidence={f.evidence} max={2} />
                </div>
              </div>
            ))}
          </div>
        </Card>
      ))}
    </div>
  );
}

function EntityText({ entity }: { entity: EntityRef }) {
  return (
    <span className="inline-flex min-w-0 items-baseline gap-1">
      <span className="text-sm font-medium text-fg [overflow-wrap:anywhere]">{entity.value}</span>
      <span className="text-[11px] text-subtle">{entity.type}</span>
    </span>
  );
}

function RelationshipsSection({ evidence }: { evidence: IntelEvidence }) {
  if (evidence.relationships.length === 0) {
    return <Empty>No relationships were found with both entities in the same sentence.</Empty>;
  }
  return (
    <div className="space-y-3">
      <p className="text-[11px] text-subtle">
        Relationships are only recorded when both entities appear in the same sentence.
      </p>
      {evidence.relationships.map((r, idx) => (
        <Card key={`${r.subject.value}-${r.predicate}-${r.object.value}-${idx}`}>
          <div className="flex flex-wrap items-center gap-x-2 gap-y-1">
            <EntityText entity={r.subject} />
            <ArrowRight className="size-3.5 shrink-0 text-subtle" aria-hidden />
            <span className="text-xs text-muted">{PREDICATE_TEXT[r.predicate] ?? r.predicate}</span>
            <ArrowRight className="size-3.5 shrink-0 text-subtle" aria-hidden />
            <EntityText entity={r.object} />
            <LabelChip label={r.label} />
            <ConfidenceText value={r.confidence} />
          </div>
          <div className="mt-2">
            <EvidenceQuotes evidence={r.evidence} max={1} />
          </div>
        </Card>
      ))}
    </div>
  );
}

function ChainSection({ evidence }: { evidence: IntelEvidence }) {
  const { steps, orderBasis } = evidence.chain;
  const ordered = useMemo(() => [...steps].sort((a, b) => a.order - b.order), [steps]);
  const reported = orderBasis === "reported";

  return (
    <div className="space-y-3">
      <div className="flex gap-2 rounded-lg border border-border bg-bg-subtle/60 px-3 py-2 text-xs text-muted">
        <Info className="mt-0.5 size-3.5 shrink-0 text-subtle" aria-hidden />
        <p>
          <span className="text-fg">
            {reported ? "Order as reported in the source" : "Order unknown — fewer than two observed steps"}
          </span>
          {reported
            ? ". Steps follow where each observed behaviour first appears in the text; this is not a standard tactic order."
            : ". Steps are listed without implying any sequence."}
        </p>
      </div>
      {ordered.length === 0 ? (
        <Empty>No observed attack-chain steps.</Empty>
      ) : (
        <ol className="space-y-3">
          {ordered.map((step, idx) => (
            <li key={`${step.order}-${idx}`} className="flex min-w-0 gap-3 rounded-xl border border-border bg-bg-card p-4">
              <div
                className="flex size-7 shrink-0 items-center justify-center rounded-full bg-bg-subtle text-xs font-medium text-muted tabular-nums"
                aria-label={reported ? `Step ${idx + 1}` : "Unordered step"}
              >
                {reported ? idx + 1 : "•"}
              </div>
              <div className="min-w-0 flex-1">
                <div className="text-sm font-medium text-fg">{step.tactic}</div>
                {step.techniques.length > 0 ? (
                  <div className="mt-1.5 flex flex-wrap gap-1.5">
                    {step.techniques.map((tech) => (
                      <span
                        key={tech}
                        className="rounded-md border border-border px-1.5 py-0.5 font-mono text-[11px] text-muted"
                      >
                        {tech}
                      </span>
                    ))}
                  </div>
                ) : null}
                <div className="mt-2.5">
                  <EvidenceQuotes evidence={step.evidence} max={2} />
                </div>
              </div>
            </li>
          ))}
        </ol>
      )}
    </div>
  );
}

function IocSection({ iocs }: { iocs: IocHit[] }) {
  const [showAll, setShowAll] = useState(false);
  if (iocs.length === 0) return <Empty>No indicators were found in this document.</Empty>;
  const LIMIT = 50;
  const shown = showAll ? iocs : iocs.slice(0, LIMIT);
  return (
    <div className="space-y-2">
      {shown.map((ioc, idx) => (
        <Card key={`${ioc.kind}-${ioc.value}-${idx}`} className="p-3">
          <div className="flex flex-wrap items-center gap-2">
            <span className="rounded-md border border-border px-2 py-0.5 text-xs text-muted">
              {ioc.kind}
            </span>
            {ioc.role ? (
              <span className="text-xs text-muted">
                Role: {ioc.role}
              </span>
            ) : null}
          </div>
          <div className="mt-1.5 break-all font-mono text-xs text-fg">{ioc.value}</div>
          {ioc.defanged && ioc.original && ioc.original !== ioc.value ? (
            <div className="mt-1 text-[11px] text-subtle">
              Defanged in source: <span className="break-all font-mono text-muted">{ioc.original}</span>
            </div>
          ) : null}
          {ioc.evidence ? (
            <div className="mt-2">
              <EvidenceQuote evidence={ioc.evidence} />
            </div>
          ) : null}
        </Card>
      ))}
      {iocs.length > LIMIT ? (
        <button
          type="button"
          onClick={() => setShowAll((v) => !v)}
          className="text-xs text-muted underline-offset-2 hover:text-fg hover:underline"
        >
          {showAll ? "Show fewer" : `Show all ${iocs.length} indicators`}
        </button>
      ) : null}
    </div>
  );
}

function ExcludedSection({ excluded }: { excluded: IntelEvidence["excluded"] }) {
  return (
    <details className="group rounded-xl border border-border bg-bg-card">
      <summary className="flex cursor-pointer list-none items-center gap-2 p-4 text-sm font-medium [&::-webkit-details-marker]:hidden">
        <ChevronRight className="size-4 shrink-0 text-subtle transition-transform group-open:rotate-90" aria-hidden />
        <span className="min-w-0 flex-1">Not counted as adversary activity</span>
        <span className="text-xs text-subtle tabular-nums">{excluded.length}</span>
      </summary>
      <div className="space-y-3 border-t border-border p-4">
        <p className="text-[11px] text-subtle">
          Statements that name a technique but were excluded because they are defensive advice, negated,
          hypothetical or background reference.
        </p>
        {excluded.length === 0 ? (
          <p className="text-xs text-muted">Nothing was excluded.</p>
        ) : (
          excluded.map((x, idx) => (
            <div key={`${x.techniqueId}-${idx}`} className="min-w-0 border-t border-border pt-3 first:border-t-0 first:pt-0">
              <div className="flex flex-wrap items-center gap-2">
                <span className="font-mono text-xs text-muted">{x.techniqueId}</span>
                <LabelChip label={x.label} />
              </div>
              <div className="mt-2">
                <EvidenceQuote evidence={x.evidence} />
              </div>
            </div>
          ))
        )}
      </div>
    </details>
  );
}
