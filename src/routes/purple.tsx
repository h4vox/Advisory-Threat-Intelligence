import { useEffect, useMemo, useState } from "react";
import { createFileRoute, Link, useNavigate } from "@tanstack/react-router";
import { useQuery } from "@tanstack/react-query";
import { z } from "zod";
import { AlertTriangle, ArrowRight, Clock, ExternalLink, FileText, FlaskConical, Gauge, History, Info, Layers, Radar, Swords, Trash2, Users } from "lucide-react";
import { AppShell } from "@/components/app-shell";
import { PageHeader, SectionCard } from "@/components/layout/page";
import { EmptyState, StatusChip } from "@/components/ui/primitives";
import { EntityChip, EntityIcon } from "@/components/ui/entity";
import { ActivitySpinner } from "@/components/ui/activity-spinner";
import { buildPurplePath, suggestPurpleSeeds, type PurpleBuildResult, type PurpleSuggestion } from "@/lib/aie/server-emulation";
import { PURPLE_PLATFORMS, type PurplePlatform } from "@/lib/aie/purple/types";
import { PurpleBuilder, type BuilderKind, type BuilderState } from "@/components/purple/purple-builder";
import { PurpleExportButtons, PurpleKpis, PurplePathView } from "@/components/purple/purple-path-view";
import { loadRecentPlans, planKey, removeRecentPlan, saveRecentPlan, type SavedPlan } from "@/components/purple/purple-utils";

const PLATFORM_IDS = PURPLE_PLATFORMS.map((p) => p.id);

const searchSchema = z.object({
  actor: z.coerce.string().max(200).optional().catch(undefined),
  report: z.coerce.string().max(200).optional().catch(undefined),
  campaign: z.coerce.string().max(200).optional().catch(undefined),
  techniques: z.coerce.string().max(1200).optional().catch(undefined),
  platforms: z.coerce.string().max(200).optional().catch(undefined),
  max: z.coerce.number().int().min(1).max(40).optional().catch(undefined),
  nohigh: z.union([z.boolean(), z.string(), z.number()]).optional().catch(undefined),
});
type PurpleSearch = z.infer<typeof searchSchema>;

export const Route = createFileRoute("/purple")({
  validateSearch: (search) => searchSchema.parse(search),
  component: PurplePage,
});

type Request = { kind: BuilderKind; value: string; techniques: string[]; platforms: PurplePlatform[]; excludeHighRisk: boolean; maxSteps: number };

function requestFromSearch(s: PurpleSearch): Request | null {
  const platforms = (s.platforms ?? "")
    .split(",")
    .map((x) => x.trim().toLowerCase())
    .filter((x): x is PurplePlatform => (PLATFORM_IDS as string[]).includes(x));
  const base = { platforms, excludeHighRisk: s.nohigh === true || s.nohigh === 1 || s.nohigh === "1" || s.nohigh === "true", maxSteps: s.max ?? 12 };
  if (s.actor) return { kind: "actor", value: s.actor, techniques: [], ...base };
  if (s.report) return { kind: "report", value: s.report, techniques: [], ...base };
  if (s.campaign) return { kind: "campaign", value: s.campaign, techniques: [], ...base };
  if (s.techniques) {
    const ids = s.techniques
      .split(/[\s,;]+/)
      .map((x) => x.trim().toUpperCase())
      .filter(Boolean);
    return ids.length ? { kind: "custom", value: "", techniques: ids, ...base } : null;
  }
  return null;
}

function searchFromState(st: BuilderState): PurpleSearch {
  const out: PurpleSearch = {};
  if (st.kind === "actor") out.actor = st.value;
  else if (st.kind === "report") out.report = st.value;
  else if (st.kind === "campaign") out.campaign = st.value;
  else out.techniques = st.techniques.join(",");
  if (st.platforms.length) out.platforms = st.platforms.join(",");
  if (st.maxSteps !== 12) out.max = st.maxSteps;
  if (st.excludeHighRisk) out.nohigh = true;
  return out;
}

const KIND_LABEL: Record<BuilderKind, string> = { actor: "Threat actor", report: "Report", campaign: "Campaign", custom: "Technique list" };

function PurplePage() {
  const search = Route.useSearch();
  const navigate = useNavigate({ from: "/purple" });
  const request = useMemo(() => requestFromSearch(search), [search]);

  const [state, setState] = useState<BuilderState>(() => ({
    kind: request?.kind ?? "actor",
    value: request?.value ?? "",
    label: request?.value ?? "",
    techniques: request?.techniques ?? [],
    platforms: request?.platforms ?? [],
    excludeHighRisk: request?.excludeHighRisk ?? false,
    maxSteps: request?.maxSteps ?? 12,
  }));
  const [recent, setRecent] = useState<SavedPlan[]>([]);
  useEffect(() => setRecent(loadRecentPlans()), []);

  // Keep the builder in sync when the URL changes (deep links, recent plans, back/forward).
  useEffect(() => {
    if (!request) return;
    setState((s) => ({
      ...s,
      kind: request.kind,
      value: request.value,
      label: s.value === request.value ? s.label : request.value,
      techniques: request.techniques,
      platforms: request.platforms,
      excludeHighRisk: request.excludeHighRisk,
      maxSteps: request.maxSteps,
    }));
  }, [request]);

  const query = useQuery({
    queryKey: ["purple-path", request],
    queryFn: () =>
      buildPurplePath({
        data: {
          kind: request!.kind,
          value: request!.value,
          techniques: request!.techniques,
          options: { platforms: request!.platforms, excludeHighRisk: request!.excludeHighRisk, maxSteps: request!.maxSteps },
        },
      }),
    enabled: Boolean(request),
    staleTime: 5 * 60_000,
  });
  const result = query.data && "path" in query.data ? (query.data as PurpleBuildResult) : null;
  const error = query.data && "error" in query.data ? query.data.error : query.error ? String((query.error as Error).message ?? query.error) : null;

  // Remember successful plans.
  useEffect(() => {
    if (!result || !request) return;
    const input = { kind: request.kind, value: request.kind === "custom" ? request.techniques.join(",") : request.value, platforms: request.platforms, excludeHighRisk: request.excludeHighRisk, maxSteps: request.maxSteps };
    setRecent(
      saveRecentPlan({
        key: planKey(input),
        name: result.seed.name,
        savedAt: new Date().toISOString(),
        steps: result.path.steps.length,
        tactics: result.path.phases.length,
        input,
      }),
    );
    if (result.seed.name && request.kind !== "custom") setState((s) => (s.value === request.value ? { ...s, label: result.seed.name } : s));
  }, [result, request]);

  const generate = (st: BuilderState) => {
    if (st.kind === "custom" ? st.techniques.length === 0 : !st.value.trim()) return;
    void navigate({ search: searchFromState(st) });
  };

  const openSaved = (p: SavedPlan) => {
    const st: BuilderState = {
      kind: p.input.kind,
      value: p.input.kind === "custom" ? "" : p.input.value,
      label: p.name,
      techniques: p.input.kind === "custom" ? p.input.value.split(",").filter(Boolean) : [],
      platforms: p.input.platforms.filter((x): x is PurplePlatform => (PLATFORM_IDS as string[]).includes(x)),
      excludeHighRisk: p.input.excludeHighRisk,
      maxSteps: p.input.maxSteps,
    };
    setState(st);
    generate(st);
  };

  return (
    <AppShell>
      <PageHeader
        title="Purple paths"
        icon={Swords}
        iconKind="emulation"
        description="Turn a threat actor, report, campaign or technique list into an ordered purple-team plan: prioritised steps, simulation objects and hunting hypotheses."
        actions={result ? <PurpleExportButtons path={result.path} /> : undefined}
      />

      <div className="space-y-6">
        <div className="flex items-start gap-2.5 rounded-lg border border-border bg-bg-card px-4 py-2.5 text-sm text-muted">
          <Info className="mt-0.5 size-4 shrink-0" style={{ color: "var(--color-cat-emulation)" }} />
          <p>
            <span className="font-medium text-fg">Planning only; AIE never executes procedures.</span> Every step is a draft for review. Run tests
            only in an authorised, isolated lab.
          </p>
        </div>

        <div className="grid gap-6 xl:grid-cols-12">
          <div className="min-w-0 xl:col-span-8">
            <PurpleBuilder state={state} onChange={setState} onGenerate={generate} busy={query.isFetching} />
          </div>
          <div className="min-w-0 xl:col-span-4">
            <RecentPlans
              plans={recent}
              onOpen={openSaved}
              onRemove={(k) => setRecent(removeRecentPlan(k))}
              activeKey={
                request
                  ? planKey({ kind: request.kind, value: request.kind === "custom" ? request.techniques.join(",") : request.value, platforms: request.platforms, excludeHighRisk: request.excludeHighRisk, maxSteps: request.maxSteps })
                  : null
              }
            />
          </div>
        </div>

        {!request && <StartHere onPick={(it) => openExample(it, state, setState, generate)} />}

        {request && query.isLoading && (
          <div className="flex items-center justify-center gap-3 rounded-xl border border-border bg-bg-card px-6 py-16 text-sm text-muted">
            <ActivitySpinner size="sm" /> Building the path from ATT&CK and the library…
          </div>
        )}

        {request && !query.isLoading && error && (
          <div className="rounded-xl border border-border bg-bg-card">
            <EmptyState icon={AlertTriangle} title="Could not build this path" description={error} />
          </div>
        )}

        {result && <PurpleResult result={result} kind={request!.kind} />}
      </div>
    </AppShell>
  );
}

function openExample(it: PurpleSuggestion, state: BuilderState, setState: (s: BuilderState) => void, generate: (s: BuilderState) => void) {
  const kind: BuilderKind = it.kind === "technique" ? "custom" : it.kind;
  const st: BuilderState = { ...state, kind, value: kind === "custom" ? "" : it.id, label: it.name, techniques: kind === "custom" ? [it.id] : [] };
  setState(st);
  generate(st);
}

function PurpleResult({ result, kind }: { result: PurpleBuildResult; kind: BuilderKind }) {
  const { path, seed, coverage } = result;
  return (
    <div className="space-y-6">
      <section className="rounded-xl border border-border bg-bg-card p-5">
        <div className="flex flex-col gap-4 md:flex-row md:items-start md:justify-between">
          <div className="flex min-w-0 items-start gap-3">
            <EntityIcon kind={kind === "report" ? "advisory" : kind === "custom" ? "technique" : "actor"} size="lg" icon={kind === "report" ? FileText : kind === "custom" ? Layers : Users} />
            <div className="min-w-0">
              <p className="text-xs text-muted">{KIND_LABEL[kind]}</p>
              <h2 className="text-lg font-semibold tracking-tight text-fg">{seed.name}</h2>
              <div className="mt-1.5 flex flex-wrap items-center gap-1.5">
                {seed.attackId && seed.attackUrl && (
                  <a href={seed.attackUrl} target="_blank" rel="noreferrer" className="inline-flex items-center gap-1 text-xs text-accent hover:underline">
                    {seed.attackId} on ATT&CK <ExternalLink className="size-3" />
                  </a>
                )}
                {seed.aliases.slice(0, 6).map((a) => (
                  <EntityChip key={a} kind="actor" title="Alias">
                    {a}
                  </EntityChip>
                ))}
                {seed.aliases.length > 6 && <span className="text-xs text-subtle">+{seed.aliases.length - 6} aliases</span>}
              </div>
              {seed.description && <p className="mt-2 line-clamp-2 max-w-3xl text-sm text-muted">{seed.description}</p>}
            </div>
          </div>
          <div className="flex shrink-0 flex-wrap gap-2 md:justify-end">
            {kind === "actor" && seed.attackId && (
              <Link
                to="/actors/$actorId"
                params={{ actorId: seed.attackId }}
                className="inline-flex h-9 items-center gap-2 rounded-lg border border-border bg-bg-elevated px-3 text-sm font-medium text-fg hover:bg-bg-subtle"
              >
                Actor profile <ArrowRight className="size-4" />
              </Link>
            )}
            {kind === "report" && (
              <Link
                to="/library/$reportId"
                params={{ reportId: seed.id }}
                className="inline-flex h-9 items-center gap-2 rounded-lg border border-border bg-bg-elevated px-3 text-sm font-medium text-fg hover:bg-bg-subtle"
              >
                Open report <ArrowRight className="size-4" />
              </Link>
            )}
          </div>
        </div>
        <div className="mt-4 grid gap-3 border-t border-border pt-4 text-sm md:grid-cols-2">
          <div className="min-w-0">
            <p className="text-xs text-muted">Library evidence</p>
            {seed.reports.length ? (
              <ul className="mt-1 space-y-0.5">
                {seed.reports.slice(0, 4).map((r) => (
                  <li key={r.id} className="truncate">
                    <Link to="/library/$reportId" params={{ reportId: r.id }} className="text-fg hover:text-accent hover:underline">
                      {r.title}
                    </Link>
                    {r.publishedAt && <span className="text-xs text-subtle"> · {r.publishedAt.slice(0, 10)}</span>}
                  </li>
                ))}
                {seed.reports.length > 4 && <li className="text-xs text-subtle">+{seed.reports.length - 4} more reports</li>}
              </ul>
            ) : (
              <p className="mt-1 text-muted">No library report mentions this {kind === "campaign" ? "campaign" : kind === "custom" ? "technique set" : "actor"} yet; steps rely on ATT&CK attribution.</p>
            )}
          </div>
          <div className="min-w-0 space-y-1.5">
            <p className="text-xs text-muted">Sources used</p>
            <div className="flex flex-wrap gap-1.5">
              {seed.attackId && <StatusChip tone="info">ATT&CK attribution</StatusChip>}
              <StatusChip tone={seed.reports.length ? "success" : "neutral"}>
                {seed.reports.length} of {coverage.libraryReports} library report{coverage.libraryReports === 1 ? "" : "s"}
              </StatusChip>
              <StatusChip tone={coverage.emulationSynced ? "success" : "warning"}>
                {coverage.emulationSynced ? `Emulation index: ${coverage.atomicTechniques} Atomic techniques` : "Emulation library not synced"}
              </StatusChip>
            </div>
            {seed.notes.map((n) => (
              <p key={n} className="text-xs text-muted">
                {n}
              </p>
            ))}
            {!coverage.emulationSynced && (
              <p className="text-xs text-subtle">
                Execution methods read "custom procedure" until Atomic Red Team or CTID plans are synced from{" "}
                <Link to="/sources" className="text-accent hover:underline">
                  Sources
                </Link>
                .
              </p>
            )}
          </div>
        </div>
      </section>

      <PurpleKpis path={path} />

      <SectionCard
        title="Purple path"
        icon={Gauge}
        iconKind="emulation"
        info="Steps are grouped by tactic phase. Each card shows its priority score (library frequency and recency, source confidence, ATT&CK attribution, emulation availability, platform fit) and risk. Open a card for the full simulation object."
        actions={<span className="text-xs text-muted">{path.steps.length} steps · {path.phases.length} phases</span>}
      >
        {path.steps.length ? (
          <PurplePathView path={path} />
        ) : (
          <EmptyState
            icon={Radar}
            title="No steps left after filtering"
            description={path.candidateCount ? "Every candidate technique was removed by the platform or risk options. Widen the platforms or allow high-risk steps." : "No ATT&CK techniques are attributed to or observed for this seed yet."}
          />
        )}
      </SectionCard>
    </div>
  );
}

function RecentPlans({ plans, onOpen, onRemove, activeKey }: { plans: SavedPlan[]; onOpen: (p: SavedPlan) => void; onRemove: (k: string) => void; activeKey: string | null }) {
  return (
    <SectionCard title="Recent plans" icon={History} iconKind="emulation" bodyClassName="px-2 pb-2 pt-3">
      {plans.length === 0 ? (
        <p className="px-3 pb-3 text-sm text-muted">Plans you generate are kept here on this device.</p>
      ) : (
        <ul className="max-h-[248px] space-y-0.5 overflow-y-auto">
          {plans.slice(0, 8).map((p) => (
            <li key={p.key} className="group flex items-center gap-1">
              <button
                type="button"
                onClick={() => onOpen(p)}
                className={`flex min-w-0 flex-1 items-center gap-2.5 rounded-md px-3 py-2 text-left hover:bg-bg-subtle ${activeKey === p.key ? "bg-bg-subtle" : ""}`}
              >
                <Clock className="size-3.5 shrink-0 text-subtle" />
                <span className="min-w-0 flex-1">
                  <span className="block truncate text-sm text-fg">{p.name}</span>
                  <span className="block truncate text-xs text-subtle">
                    {KIND_LABEL[p.input.kind]} · {p.steps} steps · {p.tactics} phases
                    {p.input.platforms.length ? ` · ${p.input.platforms.length} platform${p.input.platforms.length === 1 ? "" : "s"}` : ""}
                  </span>
                </span>
              </button>
              <button
                type="button"
                aria-label={`Remove ${p.name} from recent plans`}
                onClick={() => onRemove(p.key)}
                className="flex size-8 shrink-0 items-center justify-center rounded-md text-subtle opacity-70 hover:bg-bg-subtle hover:text-fg group-hover:opacity-100"
              >
                <Trash2 className="size-3.5" />
              </button>
            </li>
          ))}
        </ul>
      )}
    </SectionCard>
  );
}

function StartHere({ onPick }: { onPick: (it: PurpleSuggestion) => void }) {
  const { data, isLoading } = useQuery({
    queryKey: ["purple-examples"],
    queryFn: () => suggestPurpleSeeds({ data: { q: "" } }),
    staleTime: 5 * 60_000,
  });
  const examples = data?.examples ?? [];
  const steps = [
    { icon: Users, kind: "actor" as const, title: "Technique set", body: "ATT&CK-attributed techniques plus techniques observed in library reports that name the actor (aliases resolved)." },
    { icon: Gauge, kind: "emulation" as const, title: "Priority and order", body: "Scored on library frequency and recency, source confidence, attribution, emulation availability and platform fit, then ordered as a kill chain." },
    { icon: FlaskConical, kind: "ioc" as const, title: "Simulation and hunting", body: "Each step gets a simulation object, required telemetry, a hunting hypothesis with a query template, and its detection status." },
  ];
  return (
    <SectionCard title="Start from an example" icon={Swords} iconKind="emulation">
      <div className="grid gap-6 lg:grid-cols-5">
        <div className="lg:col-span-2">
          <p className="text-sm text-muted">Pick a seed to see a full path, or use the builder above.</p>
          {isLoading ? (
            <div className="mt-4 flex items-center gap-2 text-sm text-muted">
              <ActivitySpinner size="sm" /> Loading examples…
            </div>
          ) : (
            <ul className="mt-3 divide-y divide-border">
              {examples.map((it) => (
                <li key={`${it.kind}-${it.id}`}>
                  <button type="button" onClick={() => onPick(it)} className="group flex w-full items-center gap-3 py-2.5 text-left">
                    <EntityIcon kind={it.kind === "report" ? "advisory" : "actor"} size="sm" icon={it.kind === "report" ? FileText : it.kind === "campaign" ? Swords : Users} />
                    <span className="min-w-0 flex-1">
                      <span className="block truncate text-sm font-medium text-fg group-hover:text-accent">{it.name}</span>
                      <span className="block truncate text-xs text-subtle">{it.hint}</span>
                    </span>
                    <ArrowRight className="size-4 shrink-0 text-subtle group-hover:text-fg" />
                  </button>
                </li>
              ))}
              <li>
                <button
                  type="button"
                  onClick={() => onPick({ kind: "technique", id: "T1059.001", name: "PowerShell", hint: "" })}
                  className="group flex w-full items-center gap-3 py-2.5 text-left"
                >
                  <EntityIcon kind="technique" size="sm" />
                  <span className="min-w-0 flex-1">
                    <span className="block truncate text-sm font-medium text-fg group-hover:text-accent">Technique list</span>
                    <span className="block truncate text-xs text-subtle">T1059.001 · start from one technique and add more</span>
                  </span>
                  <ArrowRight className="size-4 shrink-0 text-subtle group-hover:text-fg" />
                </button>
              </li>
            </ul>
          )}
        </div>
        <ol className="grid gap-4 sm:grid-cols-3 lg:col-span-3 lg:grid-cols-1 xl:grid-cols-3">
          {steps.map((s, i) => (
            <li key={s.title} className="rounded-lg bg-bg-subtle p-4">
              <div className="flex items-center gap-2">
                <EntityIcon kind={s.kind} size="sm" icon={s.icon} />
                <span className="text-xs tabular-nums text-subtle">{i + 1}</span>
              </div>
              <p className="mt-2.5 text-sm font-medium text-fg">{s.title}</p>
              <p className="mt-1 text-sm text-muted">{s.body}</p>
            </li>
          ))}
        </ol>
      </div>
    </SectionCard>
  );
}
