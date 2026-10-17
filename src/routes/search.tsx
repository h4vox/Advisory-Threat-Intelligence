import { useEffect, useMemo, useState } from "react";
import { createFileRoute, useNavigate } from "@tanstack/react-router";
import { keepPreviousData, useQuery } from "@tanstack/react-query";
import { z } from "zod";
import { Bookmark, BookmarkCheck, Clock, Database, History, Lightbulb, Search as SearchIcon, SearchX, SlidersHorizontal, Trash2, X } from "lucide-react";
import { AppShell } from "@/components/app-shell";
import { ActionButton, PageHeader, SectionCard, SegmentedTabs } from "@/components/layout/page";
import { EmptyState } from "@/components/ui/primitives";
import { ActivitySpinner } from "@/components/ui/activity-spinner";
import { FacetGroup, FacetPanel, type FacetOption } from "@/components/library/facet-sidebar";
import { SearchBar } from "@/components/search/search-bar";
import { SYNTAX_HINTS } from "@/components/search/search-syntax";
import { InterpretedChips } from "@/components/search/interpreted-chips";
import { ResultCard } from "@/components/search/result-card";
import { clearRecent, loadRecent, loadSaved, pushRecent, removeSaved, toggleSaved, type SavedSearch } from "@/components/search/search-storage";
import { searchIntel } from "@/lib/aie/server-search";
import type { SearchFacets, SearchFilters, SearchGroupKey } from "@/lib/aie/search/types";
import { cn } from "@/lib/cn";

const GROUPS = ["all", "reports", "actors", "techniques", "software", "campaigns", "emulation", "vulnerabilities"] as const;

const searchSchema = z.object({
  q: z.string().optional(),
  tab: z.enum(GROUPS).optional(),
});

export const Route = createFileRoute("/search")({
  validateSearch: (s) => searchSchema.parse(s),
  component: SearchPage,
});

const GROUP_LABEL: Record<SearchGroupKey, string> = {
  all: "All",
  reports: "Reports",
  actors: "Threat actors",
  techniques: "Techniques",
  software: "Software",
  campaigns: "Campaigns",
  emulation: "Emulation",
  vulnerabilities: "Vulnerabilities",
};

const EXAMPLES: Array<{ q: string; note: string }> = [
  { q: "Octo Tempest", note: "Alias → Scattered Spider (G1015), incl. UNC3944" },
  { q: "Cozy Bear since:2024", note: "Alias → APT29 (G0016), date filter" },
  { q: "lsass dumping", note: "Technique name → T1003.001" },
  { q: "pass the hash lateral movement", note: "Technique + tactic" },
  { q: 'actor:"Volt Typhoon" type:advisory', note: "Field syntax" },
  { q: "CVE-2024-3400", note: "Exact id → vulnerability and campaign" },
  { q: "ransomware rdp -akira", note: "Exclusion" },
  { q: "technique:T1505.003 has:iocs", note: "Reports with web shells and IOCs" },
];

const FACET_KEYS: Array<{ key: keyof SearchFacets; filter: keyof SearchFilters; title: string }> = [
  { key: "docType", filter: "docTypes", title: "Document type" },
  { key: "tier", filter: "tiers", title: "Source tier" },
  { key: "publisher", filter: "publishers", title: "Publisher" },
  { key: "actor", filter: "actors", title: "Threat actor" },
  { key: "year", filter: "years", title: "Published" },
];

function SearchPage() {
  const params = Route.useSearch();
  const navigate = useNavigate({ from: "/search" });
  const q = params.q ?? "";
  const tab: SearchGroupKey = params.tab ?? "all";
  const [draft, setDraft] = useState(q);
  const [filters, setFilters] = useState<SearchFilters>({});
  const [limit, setLimit] = useState(20);
  const [showFacets, setShowFacets] = useState(false);
  const [recent, setRecent] = useState<string[]>([]);
  const [saved, setSaved] = useState<SavedSearch[]>([]);

  useEffect(() => {
    setRecent(loadRecent());
    setSaved(loadSaved());
  }, []);
  useEffect(() => setDraft(q), [q]);
  useEffect(() => {
    setFilters({});
    setLimit(20);
    if (q.trim()) setRecent(pushRecent(q));
  }, [q]);
  useEffect(() => setLimit(20), [tab, filters]);

  const run = (next: string, nextTab?: SearchGroupKey) => {
    void navigate({ search: (prev) => ({ ...prev, q: next.trim() || undefined, tab: nextTab ?? prev.tab }), replace: false });
  };
  const setTab = (t: SearchGroupKey) => void navigate({ search: (prev) => ({ ...prev, tab: t === "all" ? undefined : t }), replace: true });

  const query = useQuery({
    queryKey: ["search-intel", q, tab, filters, limit],
    queryFn: () => searchIntel({ data: { q, group: tab, filters, limit, offset: 0 } }),
    placeholderData: keepPreviousData,
    staleTime: 30_000,
  });
  const data = query.data;
  const hasQuery = q.trim().length > 0;
  const isSaved = saved.some((s) => s.q === q.trim());
  const activeFacetCount = Object.values(filters).reduce((n, v) => n + (v?.length ?? 0), 0);

  const facetGroups = useMemo(() => {
    if (!data) return null;
    return FACET_KEYS.map(({ key, filter, title }) => {
      const opts: FacetOption[] = data.facets[key].map((b) => ({ value: b.value, label: b.label, count: b.count, text: b.label }));
      const sel = filters[filter] ?? [];
      return (
        <FacetGroup
          key={key}
          title={title}
          options={opts}
          selected={sel}
          emptyText="No matching reports"
          onToggle={(v) => setFilters((f) => ({ ...f, [filter]: sel.includes(v) ? sel.filter((x) => x !== v) : [...sel, v] }))}
          onClear={() => setFilters((f) => ({ ...f, [filter]: [] }))}
        />
      );
    });
  }, [data, filters]);

  const sidebar = facetGroups && (
    <FacetPanel activeCount={activeFacetCount} onClearAll={() => setFilters({})}>
      {data && data.counts.reports === 0 && activeFacetCount === 0 ? (
        <p className="px-4 py-4 text-sm text-subtle">No library reports matched this query, so there is nothing to refine. ATT&CK cards are listed on the right.</p>
      ) : (
        facetGroups
      )}
      <p className="border-t border-border px-4 py-3 text-[11px] leading-relaxed text-subtle">Facets count matching library reports. ATT&CK cards are not filtered by them.</p>
    </FacetPanel>
  );

  return (
    <AppShell>
      <PageHeader
        title="Search"
        icon={SearchIcon}
        description="One search across library reports and the bundled ATT&CK knowledge. Aliases, technique names, CVE ids and field syntax are understood, and every result explains why it matched."
        actions={
          hasQuery ? (
            <ActionButton icon={isSaved ? BookmarkCheck : Bookmark} onClick={() => setSaved(toggleSaved(q))}>
              {isSaved ? "Saved" : "Save search"}
            </ActionButton>
          ) : undefined
        }
      />

      <div className="space-y-4">
        <SearchBar value={draft} onChange={setDraft} onSubmit={(v) => run(v)} autoFocus={!hasQuery} />
        {hasQuery && data && data.interpreted.raw === q && <InterpretedChips interpreted={data.interpreted} onQuery={(nq) => run(nq)} />}
      </div>

      {!hasQuery ? (
        <EmptyLanding
          recent={recent}
          saved={saved}
          knowledge={data?.sources.knowledge}
          onPick={(v) => run(v)}
          onClearRecent={() => setRecent(clearRecent())}
          onRemoveSaved={(v) => setSaved(removeSaved(v))}
        />
      ) : (
        <div className="mt-6">
          <div className="flex flex-col gap-3">
            <SegmentedTabs<SearchGroupKey>
              ariaLabel="Result groups"
              items={GROUPS.map((g) => ({ value: g, label: GROUP_LABEL[g], count: data?.counts[g] }))}
              value={tab}
              onChange={setTab}
            />
            <div className="flex flex-wrap items-center gap-3 text-xs text-subtle">
              {query.isFetching && <ActivitySpinner />}
              {data && (
                <span>
                  {data.sources.reportsSearched} reports {data.sources.persistence === "mongodb" ? "retrieved" : "searched"} · ATT&CK {data.sources.knowledge.version ?? ""} · {data.tookMs} ms
                </span>
              )}
              <button
                type="button"
                onClick={() => setShowFacets((v) => !v)}
                aria-expanded={showFacets}
                className={cn(
                  "inline-flex h-8 items-center gap-1.5 rounded-lg border border-border bg-bg-elevated px-2.5 text-xs font-medium text-fg hover:bg-bg-subtle xl:hidden",
                  showFacets && "bg-bg-subtle",
                )}
              >
                <SlidersHorizontal className="size-3.5" /> Filters
                {activeFacetCount > 0 && <span className="rounded bg-[var(--color-primary)] px-1 text-[10px] text-[var(--color-primary-fg)]">{activeFacetCount}</span>}
              </button>
            </div>
          </div>

          <div className="mt-4 grid gap-6 xl:grid-cols-[260px_minmax(0,1fr)]">
            <aside className={cn("min-w-0", showFacets ? "block" : "hidden xl:block")}>
              <div className="xl:sticky xl:top-6">{sidebar}</div>
            </aside>
            <section aria-label="Results" className="min-w-0 space-y-3">
              {query.isError && (
                <EmptyState icon={SearchX} title="Search failed" description={(query.error as Error)?.message ?? "The search service returned an error."} />
              )}
              {!data && query.isLoading && (
                <div className="space-y-3">
                  {[0, 1, 2].map((i) => (
                    <div key={i} className="h-28 animate-pulse rounded-xl border border-border bg-bg-card" />
                  ))}
                </div>
              )}
              {data && data.results.length === 0 && <NoResults tab={tab} data={data} onPick={(v) => run(v, "all")} />}
              {data?.results.map((r) => (
                <ResultCard key={`${r.kind}:${r.id}`} r={r} onPivot={(nq) => run(nq, "reports")} />
              ))}
              {data && data.total > data.results.length && (
                <div className="flex justify-center pt-1">
                  <ActionButton onClick={() => setLimit((l) => Math.min(100, l + 20))} disabled={limit >= 100}>
                    {limit >= 100 ? `Showing the first 100 of ${data.total}` : `Show more (${data.total - data.results.length} more)`}
                  </ActionButton>
                </div>
              )}
            </section>
          </div>
        </div>
      )}
    </AppShell>
  );
}

function NoResults({ tab, data, onPick }: { tab: SearchGroupKey; data: NonNullable<Awaited<ReturnType<typeof searchIntel>>>; onPick: (q: string) => void }) {
  if (tab === "emulation" && data.sources.emulation !== "synced") {
    return (
      <EmptyState
        icon={Database}
        title={data.sources.emulation === "unavailable" ? "Emulation options need structured sync" : "No synced emulation options for this query"}
        description={
          data.sources.emulation === "unavailable"
            ? "Atomic Red Team, CTID and CALDERA procedures are indexed by the structured connectors, which store into MongoDB. Library reports typed as emulation plans still appear here."
            : "Sync Atomic Red Team or the CTID emulation library from Sources, then search again."
        }
      />
    );
  }
  if (tab === "vulnerabilities") {
    return (
      <EmptyState
        icon={Database}
        title="No vulnerabilities in the matching reports"
        description={`Vulnerabilities come from CVE ids named in the query or in matching reports.${data.sources.kev === "synced" ? "" : " CISA KEV details appear once the KEV source has synced."}`}
      />
    );
  }
  const otherTabs = (Object.entries(data.counts) as Array<[SearchGroupKey, number]>).filter(([k, n]) => k !== "all" && k !== tab && n > 0);
  return (
    <EmptyState
      icon={SearchX}
      title={tab === "all" ? "Nothing matched" : `No ${GROUP_LABEL[tab].toLowerCase()} matched`}
      description={
        otherTabs.length
          ? `There are matches in ${otherTabs.map(([k, n]) => `${GROUP_LABEL[k].toLowerCase()} (${n})`).join(", ")}.`
          : "Try fewer words, remove a filter chip, or search an alias or technique name. Only stored library reports and the bundled ATT&CK knowledge are searched."
      }
      action={
        tab === "all" ? (
          <button type="button" onClick={() => onPick("ransomware rdp")} className="text-sm text-accent hover:underline">
            Try “ransomware rdp”
          </button>
        ) : undefined
      }
    />
  );
}

function QueryChip({ q, onPick, onRemove, icon: Icon }: { q: string; onPick: () => void; onRemove?: () => void; icon: typeof Clock }) {
  return (
    <span className="inline-flex max-w-full items-center rounded-md border border-border bg-bg-elevated text-sm text-fg">
      <button type="button" onClick={onPick} className="inline-flex min-w-0 items-center gap-1.5 px-2.5 py-1 hover:text-accent">
        <Icon className="size-3.5 shrink-0 text-subtle" />
        <span className="truncate font-mono text-xs">{q}</span>
      </button>
      {onRemove && (
        <button type="button" onClick={onRemove} aria-label={`Remove ${q}`} className="flex size-6 items-center justify-center text-subtle hover:text-fg">
          <X className="size-3" />
        </button>
      )}
    </span>
  );
}

function EmptyLanding({
  recent,
  saved,
  knowledge,
  onPick,
  onClearRecent,
  onRemoveSaved,
}: {
  recent: string[];
  saved: SavedSearch[];
  knowledge?: { version: string | null; groups: number; software: number; campaigns: number; techniques: number };
  onPick: (q: string) => void;
  onClearRecent: () => void;
  onRemoveSaved: (q: string) => void;
}) {
  return (
    <div className="mt-6 grid gap-6 lg:grid-cols-[minmax(0,1fr)_340px]">
      <div className="space-y-6">
        <SectionCard title="Try a query" icon={Lightbulb} iconKind="emulation">
          <ul className="grid gap-2 sm:grid-cols-2">
            {EXAMPLES.map((e) => (
              <li key={e.q}>
                <button
                  type="button"
                  onClick={() => onPick(e.q)}
                  className="flex w-full min-w-0 flex-col items-start rounded-lg border border-border bg-bg-elevated px-3 py-2.5 text-left transition-colors hover:border-[color-mix(in_oklab,var(--color-primary)_40%,var(--color-border))] hover:bg-bg-subtle"
                >
                  <code className="max-w-full truncate font-mono text-[13px] text-fg">{e.q}</code>
                  <span className="mt-0.5 max-w-full truncate text-xs text-muted">{e.note}</span>
                </button>
              </li>
            ))}
          </ul>
        </SectionCard>
        <SectionCard title="Query syntax" icon={SearchIcon} iconKind="technique" info="Field clauses filter; free text ranks. Quote a phrase to stop it being interpreted.">
          <dl className="grid gap-x-6 gap-y-2 text-sm sm:grid-cols-2">
            {SYNTAX_HINTS.map((h) => (
              <div key={h.field} className="flex min-w-0 items-baseline gap-2">
                <dt className="shrink-0">
                  <code className="font-mono text-xs text-accent">{h.example}</code>
                </dt>
                <dd className="truncate text-xs text-muted">{h.help}</dd>
              </div>
            ))}
          </dl>
        </SectionCard>
      </div>
      <div className="space-y-6">
        <SectionCard
          title="Recent searches"
          icon={History}
          iconKind="source"
          actions={
            recent.length > 0 ? (
              <button type="button" onClick={onClearRecent} className="inline-flex items-center gap-1 text-xs text-muted hover:text-fg">
                <Trash2 className="size-3.5" /> Clear
              </button>
            ) : undefined
          }
        >
          {recent.length === 0 ? (
            <p className="text-sm text-subtle">Searches you run appear here, in this browser only.</p>
          ) : (
            <div className="flex flex-wrap gap-2">
              {recent.map((r) => (
                <QueryChip key={r} q={r} icon={Clock} onPick={() => onPick(r)} />
              ))}
            </div>
          )}
        </SectionCard>
        <SectionCard title="Saved searches" icon={Bookmark} iconKind="advisory">
          {saved.length === 0 ? (
            <p className="text-sm text-subtle">Run a search and choose “Save search” to keep it here.</p>
          ) : (
            <div className="flex flex-wrap gap-2">
              {saved.map((s) => (
                <QueryChip key={s.q} q={s.q} icon={Bookmark} onPick={() => onPick(s.q)} onRemove={() => onRemoveSaved(s.q)} />
              ))}
            </div>
          )}
        </SectionCard>
        <SectionCard title="What is searched" icon={Database} iconKind="technique">
          <ul className="space-y-2 text-sm text-muted">
            <li>Every stored library report: narrative reports, advisories and synced structured documents.</li>
            <li>
              Bundled ATT&CK{knowledge?.version ? ` v${knowledge.version}` : ""}
              {knowledge ? (
                <span className="text-fg">
                  {": "}
                  {knowledge.groups} groups, {knowledge.software} software, {knowledge.campaigns} campaigns, {knowledge.techniques} techniques
                </span>
              ) : null}
              , available offline.
            </li>
            <li>Emulation options and CISA KEV rows once their structured sources have synced.</li>
          </ul>
        </SectionCard>
      </div>
    </div>
  );
}
