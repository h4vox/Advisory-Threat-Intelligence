import { useMemo, useState, type ReactNode } from "react";
import { Link } from "@tanstack/react-router";
import { useMutation } from "@tanstack/react-query";
import { ArrowRight, Bot, ChevronDown, Crosshair, ExternalLink, FileText, GripVertical, Loader2, PanelRightOpen, Quote, Search, Sparkles, X } from "lucide-react";
import { connections, edgeStrength, graphInsights, searchNodes, similarEntities, type GraphFilter, type GraphIndex } from "@/lib/aie/graph/analyze";
import { GRAPH_NODE_TYPES, NODE_TYPE_LABEL, PREDICATE_LABEL, type GraphEdge, type GraphNode, type GraphNodeType } from "@/lib/aie/graph/types";
import { explainGraphNode } from "@/lib/aie/server-graph";
import { entityContext } from "@/lib/aie/graph/correlate";
import { askAgentAbout, entityDragProps, openEntityContext } from "@/components/agent-handoff";
import { BriefView, handoffFor } from "@/components/intel/entity-context-sheet";
import { cn } from "@/lib/cn";
import type { GraphTheme } from "./graph-style";

// ---------------------------------------------------------------------------
// Small pieces
// ---------------------------------------------------------------------------

export function TypeDot({ type, theme, size = 8 }: { type: GraphNodeType; theme: GraphTheme; size?: number }) {
  return <span aria-hidden className="inline-block shrink-0 rounded-full" style={{ width: size, height: size, backgroundColor: theme.type[type] }} />;
}

function NodeChip({ node, theme, onClick }: { node: GraphNode; theme: GraphTheme; onClick: () => void }) {
  return (
    <button
      type="button"
      onClick={onClick}
      title={`${NODE_TYPE_LABEL[node.type].one}: ${node.label}`}
      className="inline-flex max-w-full items-center gap-1.5 rounded-md border border-border bg-bg-elevated px-2 py-0.5 text-[11px] text-fg transition-colors hover:border-border-strong"
    >
      <TypeDot type={node.type} theme={theme} size={6} />
      <span className="truncate">{node.label}</span>
    </button>
  );
}

function ConfidenceBar({ value, color }: { value: number; color: string }) {
  return (
    <span className="inline-flex h-1.5 w-12 shrink-0 overflow-hidden rounded-full bg-bg-subtle" title={`Confidence ${Math.round(value * 100)}%`}>
      <span className="h-full rounded-full" style={{ width: `${Math.max(6, value * 100)}%`, backgroundColor: color }} />
    </span>
  );
}

function Section({ title, count, children, defaultOpen = true, hint }: { title: string; count?: number; children: ReactNode; defaultOpen?: boolean; hint?: string }) {
  return (
    <details open={defaultOpen} className="group border-t border-border">
      <summary className="flex cursor-pointer list-none items-center justify-between gap-2 px-4 py-3 text-xs font-semibold uppercase tracking-wider text-muted hover:text-fg">
        <span className="flex items-center gap-2">
          {title}
          {typeof count === "number" && <span className="rounded bg-bg-subtle px-1.5 py-px font-mono text-[10px] font-normal text-subtle">{count}</span>}
        </span>
        <ChevronDown className="size-3.5 transition-transform group-open:rotate-180" />
      </summary>
      <div className="px-4 pb-4">
        {hint && <p className="mb-2 text-[11px] leading-snug text-subtle">{hint}</p>}
        {children}
      </div>
    </details>
  );
}

const fmtDay = (d: string | null | undefined) => (d ? new Date(d).toLocaleDateString(undefined, { year: "numeric", month: "short", day: "numeric" }) : "—");

// ---------------------------------------------------------------------------
// Left: search, view and filters
// ---------------------------------------------------------------------------

/** Preset selections of entity types, by what the analyst wants to look into. */
export const LENSES: Array<{ id: string; label: string; hint: string; types: GraphNodeType[] }> = [
  { id: "adversary", label: "Adversaries", hint: "Who, with what, and how: actors, campaigns, malware, tools, techniques", types: ["actor", "campaign", "malware", "tool", "technique"] },
  { id: "targeting", label: "Targeting", hint: "Who targets which sectors, regions and platforms", types: ["actor", "campaign", "malware", "sector", "geography", "platform"] },
  { id: "exploitation", label: "Exploitation", hint: "Vulnerabilities, who exploits them and what they hit", types: ["actor", "campaign", "malware", "vulnerability", "sector"] },
  { id: "infrastructure", label: "Infrastructure", hint: "Indicators and the malware / actors they belong to", types: ["actor", "campaign", "malware", "tool", "indicator"] },
  { id: "everything", label: "Everything", hint: "All entity types except indicators", types: ["actor", "campaign", "malware", "tool", "technique", "vulnerability", "sector", "geography"] },
];

export type GraphDetail = "key" | "standard" | "wide";
export const GRAPH_DETAILS: Array<{ id: GraphDetail; label: string; nodes: number }> = [
  { id: "key", label: "Key", nodes: 80 },
  { id: "standard", label: "More", nodes: 160 },
  { id: "wide", label: "Wide", nodes: 320 },
];

export const TIME_WINDOWS = [
  { value: "all", label: "All time", days: 0 },
  { value: "30", label: "Last 30 days", days: 30 },
  { value: "90", label: "Last 90 days", days: 90 },
  { value: "365", label: "Last 12 months", days: 365 },
] as const;
export type TimeWindow = (typeof TIME_WINDOWS)[number]["value"];

export function FilterPanel({
  ix,
  theme,
  filter,
  onFilter,
  windowValue,
  onWindow,
  onPick,
  detail,
  onDetail,
}: {
  ix: GraphIndex;
  theme: GraphTheme;
  filter: GraphFilter;
  onFilter: (f: GraphFilter) => void;
  windowValue: TimeWindow;
  onWindow: (w: TimeWindow) => void;
  onPick: (id: string) => void;
  detail: GraphDetail;
  onDetail: (d: GraphDetail) => void;
}) {
  const [q, setQ] = useState("");
  const results = useMemo(() => searchNodes(ix, q, 10), [ix, q]);
  const counts = useMemo(() => {
    const m = new Map<GraphNodeType, number>();
    for (const n of ix.graph.nodes) m.set(n.type, (m.get(n.type) ?? 0) + 1);
    return m;
  }, [ix]);
  const tactics = useMemo(() => {
    const m = new Map<string, number>();
    for (const n of ix.graph.nodes) if (n.type === "technique") for (const t of n.tactics ?? []) m.set(t, (m.get(t) ?? 0) + 1);
    const order = ["Reconnaissance", "Resource Development", "Initial Access", "Execution", "Persistence", "Privilege Escalation", "Defense Evasion", "Stealth", "Defense Impairment", "Credential Access", "Discovery", "Lateral Movement", "Collection", "Command and Control", "Exfiltration", "Impact"];
    return [...m.entries()].sort((a, b) => (order.indexOf(a[0]) + 100) % 100 - (order.indexOf(b[0]) + 100) % 100);
  }, [ix]);
  const toggle = (t: GraphNodeType) => onFilter({ ...filter, types: filter.types.includes(t) ? filter.types.filter((x) => x !== t) : [...filter.types, t] });

  return (
    <div className="flex flex-col">
      <div className="relative p-4">
        <label htmlFor="graph-search" className="sr-only">
          Find an entity
        </label>
        <Search className="pointer-events-none absolute left-7 top-1/2 size-4 -translate-y-1/2 text-subtle" />
        <input
          id="graph-search"
          value={q}
          onChange={(e) => setQ(e.target.value)}
          placeholder="Find actor, malware, T1059, CVE…"
          className="h-9 w-full rounded-lg border border-border bg-bg-elevated pl-9 pr-8 text-sm text-fg placeholder:text-subtle focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring/60"
        />
        {q && (
          <button type="button" aria-label="Clear search" onClick={() => setQ("")} className="absolute right-6 top-1/2 -translate-y-1/2 text-subtle hover:text-fg">
            <X className="size-3.5" />
          </button>
        )}
        {q && (
          <div className="absolute inset-x-4 top-full z-20 -mt-2 max-h-80 overflow-y-auto rounded-lg border border-border bg-bg-elevated p-1 shadow-xl">
            {results.length ? (
              results.map((n) => (
                <button
                  key={n.id}
                  type="button"
                  onClick={() => {
                    onPick(n.id);
                    setQ("");
                  }}
                  className="flex w-full items-center gap-2 rounded-md px-2 py-1.5 text-left text-sm hover:bg-bg-subtle"
                >
                  <TypeDot type={n.type} theme={theme} />
                  <span className="min-w-0 flex-1 truncate">{n.label}</span>
                  <span className="shrink-0 text-[11px] text-subtle">{NODE_TYPE_LABEL[n.type].one}</span>
                </button>
              ))
            ) : (
              <p className="px-2 py-2 text-xs text-subtle">No entity matches “{q}”.</p>
            )}
          </div>
        )}
      </div>

      <Section title="Lens" hint="What you want to look into; fine-tune the entity types below.">
        <div className="grid grid-cols-2 gap-1">
          {LENSES.map((l) => {
            const on = l.types.length === filter.types.length && l.types.every((t) => filter.types.includes(t));
            return (
              <button
                key={l.id}
                type="button"
                title={l.hint}
                onClick={() => onFilter({ ...filter, types: [...l.types] })}
                className={cn("h-8 rounded-md border px-2 text-left text-xs", on ? "border-primary bg-primary/10 font-semibold text-fg" : "border-border text-muted hover:text-fg")}
              >
                {l.label}
              </button>
            );
          })}
        </div>
        <div className="mt-3">
          <div className="mb-1.5 text-xs text-muted">Detail</div>
          <div className="grid grid-cols-3 gap-1">
            {GRAPH_DETAILS.map((d) => (
              <button
                key={d.id}
                type="button"
                title={`Up to ${d.nodes} entities in the overview`}
                onClick={() => onDetail(d.id)}
                className={cn("h-7 rounded-md border text-xs", detail === d.id ? "border-primary bg-primary/10 font-semibold text-fg" : "border-border text-muted hover:text-fg")}
              >
                {d.label}
              </button>
            ))}
          </div>
        </div>
      </Section>

      <Section title="Entity types">
        <ul className="space-y-0.5">
          {GRAPH_NODE_TYPES.map((t) => {
            const on = filter.types.includes(t);
            const count = counts.get(t) ?? 0;
            return (
              <li key={t}>
                <label className={cn("flex cursor-pointer items-center gap-2.5 rounded-md px-1.5 py-1 text-sm hover:bg-bg-subtle", !count && "opacity-50")}>
                  <input type="checkbox" checked={on} onChange={() => toggle(t)} className="size-3.5 cursor-pointer" style={{ accentColor: theme.type[t] }} />
                  <TypeDot type={t} theme={theme} />
                  <span className={cn("flex-1", on ? "text-fg" : "text-muted")}>{NODE_TYPE_LABEL[t].many}</span>
                  <span className="font-mono text-[11px] text-subtle tabular-nums">{count}</span>
                </label>
              </li>
            );
          })}
        </ul>
      </Section>

      {filter.types.includes("technique") && (
        <Section title="ATT&CK tactics" defaultOpen={false} hint="Show only techniques of these tactics (none selected = all).">
          <div className="flex flex-wrap gap-1">
            {tactics.map(([t, count]) => {
              const on = filter.tactics?.includes(t) ?? false;
              return (
                <button
                  key={t}
                  type="button"
                  onClick={() => onFilter({ ...filter, tactics: on ? (filter.tactics ?? []).filter((x) => x !== t) : [...(filter.tactics ?? []), t] })}
                  className={cn("rounded-md border px-2 py-0.5 text-[11px]", on ? "border-primary bg-primary/10 font-semibold text-fg" : "border-border text-muted hover:text-fg")}
                >
                  {t} <span className="text-subtle">{count}</span>
                </button>
              );
            })}
          </div>
        </Section>
      )}

      <Section title="Evidence">
        <div className="space-y-4">
          <div>
            <div className="mb-1.5 flex items-center justify-between text-xs text-muted">
              <label htmlFor="graph-confidence">Link confidence at least</label>
              <span className="font-mono text-fg">{Math.round(filter.minConfidence * 100)}%</span>
            </div>
            <input
              id="graph-confidence"
              type="range"
              min={0}
              max={90}
              step={5}
              value={Math.round(filter.minConfidence * 100)}
              onChange={(e) => onFilter({ ...filter, minConfidence: Number(e.target.value) / 100 })}
              className="w-full"
              style={{ accentColor: "var(--color-primary)" }}
            />
          </div>
          <label className="flex cursor-pointer items-start gap-2.5 text-sm">
            <input type="checkbox" checked={filter.minReports > 1} onChange={(e) => onFilter({ ...filter, minReports: e.target.checked ? 2 : 1 })} className="mt-0.5 size-3.5 cursor-pointer" />
            <span>
              Corroborated only
              <span className="block text-[11px] text-subtle">Entities and links backed by more than one report.</span>
            </span>
          </label>
          <label className="flex cursor-pointer items-start gap-2.5 text-sm">
            <input type="checkbox" checked={filter.statedOnly} onChange={(e) => onFilter({ ...filter, statedOnly: e.target.checked })} className="mt-0.5 size-3.5 cursor-pointer" />
            <span>
              Stated links only
              <span className="block text-[11px] text-subtle">A report links the two in one sentence.</span>
            </span>
          </label>
          <div>
            <div className="mb-1.5 text-xs text-muted">Activity</div>
            <div className="grid grid-cols-2 gap-1">
              {TIME_WINDOWS.map((w) => (
                <button
                  key={w.value}
                  type="button"
                  onClick={() => onWindow(w.value)}
                  className={cn("h-7 rounded-md border text-xs", windowValue === w.value ? "border-primary bg-primary/10 font-semibold text-fg" : "border-border text-muted hover:text-fg")}
                >
                  {w.label}
                </button>
              ))}
            </div>
          </div>
        </div>
      </Section>

      <Section title="How to read it" defaultOpen={false}>
        <ul className="space-y-2 text-xs text-muted">
          <li>
            <b className="font-medium text-fg">Dot size</b>: how many reports mention the entity.
          </li>
          <li>
            <b className="font-medium text-fg">Thick line</b>: a report states the link in one sentence. <b className="font-medium text-fg">Thin line</b>: both appear in the same
            report.
          </li>
          <li>
            <b className="font-medium text-fg">Brighter line</b>: higher confidence; it grows with each report that supports the link.
          </li>
          <li>
            <b className="font-medium text-fg">Overview</b> shows the most-reported entities of each type. <b className="font-medium text-fg">Focus</b> puts one entity in the centre
            with its links on the rings.
          </li>
          <li>Click to inspect · double-click to centre · drag to move · scroll to zoom.</li>
        </ul>
      </Section>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Right: inspector
// ---------------------------------------------------------------------------

type InspectorProps = {
  ix: GraphIndex;
  theme: GraphTheme;
  filter: GraphFilter;
  selectedNode: string | null;
  selectedEdge: string | null;
  centerId: string | null;
  onSelectNode: (id: string) => void;
  onSelectEdge: (id: string) => void;
  onFocus: (id: string) => void;
  onClear: () => void;
};

export function Inspector(p: InspectorProps) {
  const edge = p.selectedEdge ? p.ix.graph.edges.find((e) => e.id === p.selectedEdge) : undefined;
  if (edge) return <EdgeInspector {...p} edge={edge} />;
  const node = p.selectedNode ? p.ix.node.get(p.selectedNode) : undefined;
  if (node) return <NodeInspector key={node.id} {...p} node={node} />;
  return <OverviewInsights {...p} />;
}

function PanelHeader({ children, onClose }: { children: ReactNode; onClose?: () => void }) {
  return (
    <div className="flex items-start justify-between gap-3 px-4 pb-4 pt-4">
      <div className="min-w-0 flex-1">{children}</div>
      {onClose && (
        <button type="button" aria-label="Close details" onClick={onClose} className="inline-flex size-7 shrink-0 items-center justify-center rounded-md text-muted hover:bg-bg-subtle hover:text-fg">
          <X className="size-4" />
        </button>
      )}
    </div>
  );
}

function OverviewInsights({ ix, theme, filter, onSelectNode, onSelectEdge, onFocus }: InspectorProps) {
  const ins = useMemo(() => graphInsights(ix, filter), [ix, filter]);
  const row = (n: GraphNode, meta: string) => (
    <li key={n.id}>
      <button type="button" onClick={() => onSelectNode(n.id)} onDoubleClick={() => onFocus(n.id)} className="flex w-full items-center gap-2 rounded-md px-1.5 py-1.5 text-left text-sm hover:bg-bg-subtle">
        <TypeDot type={n.type} theme={theme} />
        <span className="min-w-0 flex-1 truncate">{n.label}</span>
        <span className="shrink-0 text-[11px] text-subtle">{meta}</span>
      </button>
    </li>
  );
  return (
    <div>
      <PanelHeader>
        <div className="text-xs font-semibold uppercase tracking-wider text-subtle">Insights</div>
        <p className="mt-1 text-sm text-muted">Select any entity or link to see what connects it. Double-click to put it in the centre.</p>
      </PanelHeader>
      <Section title="Most active" hint="Actors, campaigns and malware ranked by reports, reach and recent activity.">
        <ul>{ins.mostActive.map((n) => row(n, `${n.reportCount} rep.`))}</ul>
      </Section>
      <Section title="Strongest stated links" hint="Relationships reports state in one sentence, most supported first.">
        <ul className="space-y-1">
          {ins.strongestStated.length ? (
            ins.strongestStated.map((e) => {
              const a = ix.node.get(e.source);
              const b = ix.node.get(e.target);
              if (!a || !b) return null;
              return (
                <li key={e.id}>
                  <button type="button" onClick={() => onSelectEdge(e.id)} className="w-full rounded-md px-1.5 py-1.5 text-left text-sm hover:bg-bg-subtle">
                    <span className="font-medium">{a.label}</span> <span className="text-subtle">{PREDICATE_LABEL[e.predicate]}</span> <span className="font-medium">{b.label}</span>
                    <span className="ml-1 text-[11px] text-subtle">· {e.weight} rep.</span>
                  </button>
                </li>
              );
            })
          ) : (
            <li className="text-xs text-subtle">No stated links match the filters.</li>
          )}
        </ul>
      </Section>
      <Section title="Newest entities" hint="First seen most recently in the library.">
        <ul>{ins.newest.map((n) => row(n, fmtDay(n.firstSeen)))}</ul>
      </Section>
      <Section title="Most reported techniques">
        <ul>{ins.topTechniques.map((n) => row(n, `${n.attackId} · ${n.reportCount}`))}</ul>
      </Section>
    </div>
  );
}

function profileLink(n: GraphNode): ReactNode {
  if (n.type === "actor" && n.attackId) return <Link to="/actors/$actorId" params={{ actorId: n.attackId }} className="inline-flex items-center gap-1 text-xs text-primary hover:underline">Actor profile <ArrowRight className="size-3" /></Link>;
  if (n.attackId) {
    const path = n.attackId.startsWith("T") ? `techniques/${n.attackId.replace(".", "/")}` : n.attackId.startsWith("S") ? `software/${n.attackId}` : n.attackId.startsWith("G") ? `groups/${n.attackId}` : `campaigns/${n.attackId}`;
    return (
      <a href={`https://attack.mitre.org/${path}/`} target="_blank" rel="noreferrer" className="inline-flex items-center gap-1 text-xs text-primary hover:underline">
        ATT&CK {n.attackId} <ExternalLink className="size-3" />
      </a>
    );
  }
  if (n.type === "vulnerability")
    return (
      <a href={`https://nvd.nist.gov/vuln/detail/${n.label}`} target="_blank" rel="noreferrer" className="inline-flex items-center gap-1 text-xs text-primary hover:underline">
        NVD entry <ExternalLink className="size-3" />
      </a>
    );
  return null;
}

function NodeInspector({ ix, theme, filter, node, centerId, onSelectNode, onSelectEdge, onFocus, onClear }: InspectorProps & { node: GraphNode }) {
  const links = useMemo(() => connections(ix, node.id, filter), [ix, node.id, filter]);
  // Grouped in a fixed reading order (who → with what → how → against whom → indicators); types
  // switched off in the filter are counted but not listed.
  const { groups, hiddenLinks } = useMemo(() => {
    const m = new Map<GraphNodeType, typeof links>();
    let hidden = 0;
    for (const l of links) {
      if (!filter.types.includes(l.other.type)) {
        hidden++;
        continue;
      }
      (m.get(l.other.type) ?? m.set(l.other.type, []).get(l.other.type)!).push(l);
    }
    return { groups: GRAPH_NODE_TYPES.filter((t) => m.has(t)).map((t) => [t, m.get(t)!] as const), hiddenLinks: hidden };
  }, [links, filter.types]);
  const similar = useMemo(() => similarEntities(ix, node.id, 6), [ix, node.id]);
  const ctx = useMemo(() => entityContext(ix, node.id), [ix, node.id]);
  const [expanded, setExpanded] = useState<Set<GraphNodeType>>(new Set());
  const color = theme.type[node.type];

  return (
    <div>
      <PanelHeader onClose={onClear}>
        <div className="flex items-center gap-2 text-xs font-medium" style={{ color }}>
          <TypeDot type={node.type} theme={theme} />
          {NODE_TYPE_LABEL[node.type].one}
          {node.subtype && <span className="text-subtle">· {node.subtype}</span>}
        </div>
        <h2 className="mt-1 break-words text-lg font-semibold leading-snug">{node.label}</h2>
        {node.aliases?.length ? <p className="mt-0.5 text-xs text-subtle">Also: {node.aliases.join(", ")}</p> : null}
        {node.tactics?.length ? <p className="mt-0.5 text-xs text-subtle">{node.tactics.join(" · ")}</p> : null}
        <div className="mt-3 grid grid-cols-3 gap-2 text-center">
          {[
            [node.reportCount, "reports"],
            [links.length, "links"],
            [similar.length, "similar"],
          ].map(([v, l]) => (
            <div key={l as string} className="rounded-lg border border-border bg-bg-elevated px-2 py-1.5">
              <div className="font-mono text-base font-semibold tabular-nums">{v}</div>
              <div className="text-[10px] uppercase tracking-wider text-subtle">{l}</div>
            </div>
          ))}
        </div>
        <p className="mt-2 text-[11px] text-subtle">
          First seen {fmtDay(node.firstSeen)} · last seen {fmtDay(node.lastSeen)}
        </p>
        <div className="mt-3 flex flex-wrap items-center gap-2">
          {centerId !== node.id && (
            <button type="button" onClick={() => onFocus(node.id)} className="btn-primary inline-flex h-8 items-center gap-1.5 rounded-lg px-3 text-xs font-semibold">
              <Crosshair className="size-3.5" /> Focus on this
            </button>
          )}
          <button
            type="button"
            onClick={() => askAgentAbout(handoffFor(node))}
            {...entityDragProps(handoffFor(node))}
            title="Investigate with the AI Agent (or drag this onto the AI Agent button)"
            className="inline-flex h-8 cursor-grab items-center gap-1.5 rounded-lg border border-border px-2.5 text-xs hover:bg-bg-subtle active:cursor-grabbing"
          >
            <GripVertical className="size-3.5 text-subtle" />
            <Bot className="size-3.5 text-primary" /> Ask the agent
          </button>
          <button type="button" onClick={() => openEntityContext(node.id)} title="Everything correlated with it, and how it connects to anything else" className="inline-flex h-8 items-center gap-1.5 rounded-lg border border-border px-2.5 text-xs hover:bg-bg-subtle">
            <PanelRightOpen className="size-3.5" /> Full context
          </button>
          {profileLink(node)}
        </div>
      </PanelHeader>

      <AiBrief node={node} ix={ix} theme={theme} onSelectNode={onSelectNode} />

      {ctx && ctx.findings.length > 0 && (
        <Section title="Findings" count={ctx.findings.length} hint="Worked out by the engine from the library's links (no AI).">
          <ul className="space-y-2.5">
            {ctx.findings.map((f, i) => (
              <li key={i} className="text-sm leading-snug">
                {f.text}
                {f.refs.some((r) => ix.node.has(r)) && (
                  <div className="mt-1 flex flex-wrap gap-1">
                    {f.refs.filter((r) => ix.node.has(r)).map((r) => (
                      <NodeChip key={r} node={ix.node.get(r)!} theme={theme} onClick={() => onSelectNode(r)} />
                    ))}
                  </div>
                )}
              </li>
            ))}
          </ul>
        </Section>
      )}

      {ctx && ctx.related.length > 0 && (
        <Section title="Related through shared links" count={ctx.related.length} defaultOpen={false} hint="Not linked directly, but connected through the entities after “via”; common hubs count less.">
          <ul className="space-y-2">
            {ctx.related.slice(0, 8).map((r) => (
              <li key={r.node.id} className="flex flex-wrap items-center gap-1 text-xs">
                <NodeChip node={r.node} theme={theme} onClick={() => onSelectNode(r.node.id)} />
                <span className="text-subtle">via</span>
                {r.via.map((v) => (
                  <NodeChip key={v.id} node={v} theme={theme} onClick={() => onSelectNode(v.id)} />
                ))}
              </li>
            ))}
          </ul>
        </Section>
      )}

      <Section title="Connections" count={links.length - hiddenLinks}>
        {groups.length ? (
          <div className="space-y-3">
            {groups.map(([type, list]) => {
              const open = expanded.has(type);
              return (
                <div key={type}>
                  <div className="mb-1 flex items-center gap-2 text-xs font-medium text-muted">
                    <TypeDot type={type} theme={theme} size={6} />
                    {NODE_TYPE_LABEL[type].many}
                    <span className="text-subtle">{list.length}</span>
                  </div>
                  <ul className="space-y-0.5">
                    {(open ? list : list.slice(0, 6)).map(({ edge, other, outgoing }) => (
                      <li key={edge.id} className="group flex items-center gap-2 rounded-md px-1.5 py-1 hover:bg-bg-subtle">
                        <button type="button" onClick={() => onSelectEdge(edge.id)} className="min-w-0 flex-1 text-left" title={`${outgoing ? PREDICATE_LABEL[edge.predicate] : `${PREDICATE_LABEL[edge.predicate]} by`} ${other.label}`}>
                          <span className="block text-[10px] leading-tight text-subtle">{outgoing ? PREDICATE_LABEL[edge.predicate] : `${PREDICATE_LABEL[edge.predicate]} by`}</span>
                          <span className="block truncate text-sm">{other.label}</span>
                        </button>
                        {edge.basis === "stated" && (
                          <span className="shrink-0 rounded px-1 text-[10px] font-medium" style={{ color, backgroundColor: `${color}22` }} title="Stated in one sentence">
                            stated
                          </span>
                        )}
                        <span className="shrink-0 font-mono text-[10px] text-subtle" title="Reports">
                          {edge.weight}
                        </span>
                        <ConfidenceBar value={edge.confidence} color={theme.type[other.type]} />
                        <button type="button" aria-label={`Focus on ${other.label}`} onClick={() => onFocus(other.id)} className="shrink-0 text-subtle opacity-0 hover:text-fg group-hover:opacity-100 focus:opacity-100">
                          <Crosshair className="size-3.5" />
                        </button>
                      </li>
                    ))}
                  </ul>
                  {list.length > 6 && (
                    <button
                      type="button"
                      onClick={() => setExpanded((s) => new Set(open ? [...s].filter((x) => x !== type) : [...s, type]))}
                      className="mt-1 px-1.5 text-[11px] text-primary hover:underline"
                    >
                      {open ? "Show fewer" : `Show all ${list.length}`}
                    </button>
                  )}
                </div>
              );
            })}
          </div>
        ) : (
          <p className="text-xs text-subtle">No links pass the current filters.</p>
        )}
        {hiddenLinks > 0 && <p className="mt-3 text-[11px] text-subtle">{hiddenLinks} more link{hiddenLinks === 1 ? "" : "s"} to entity types switched off in the filters.</p>}
      </Section>

      {similar.length > 0 && (
        <Section title="Possible hidden links" count={similar.length} hint="Not stated by any report: these share unusually much behaviour, tooling, targets or infrastructure (rarer shared items count more). Worth checking.">
          <ul className="space-y-3">
            {similar.map((s) => (
              <li key={s.node.id} className="rounded-lg border border-border bg-bg-elevated p-2.5">
                <div className="flex items-center gap-2">
                  <button type="button" onClick={() => onSelectNode(s.node.id)} className="min-w-0 flex-1 truncate text-left text-sm font-medium hover:underline">
                    {s.node.label}
                  </button>
                  <span className="shrink-0 font-mono text-[11px]" style={{ color }}>
                    {Math.round(s.score * 100)}% overlap
                  </span>
                </div>
                {s.linked && <div className="mt-0.5 text-[10px] text-subtle">Already linked in a report</div>}
                <div className="mt-1.5 flex flex-wrap gap-1">
                  {s.shared.map((x) => (
                    <NodeChip key={x.id} node={x} theme={theme} onClick={() => onSelectNode(x.id)} />
                  ))}
                </div>
              </li>
            ))}
          </ul>
        </Section>
      )}

      <Section title="Reports" count={node.reportCount} defaultOpen={false}>
        <ReportList ids={node.reports} ix={ix} />
      </Section>
    </div>
  );
}

function ReportList({ ids, ix }: { ids: string[]; ix: GraphIndex }) {
  return (
    <ul className="space-y-1">
      {ids.slice(0, 30).map((id) => {
        const r = ix.graph.reports[id];
        if (!r) return null;
        return (
          <li key={id}>
            <Link to="/library/$reportId" params={{ reportId: id }} className="flex items-start gap-2 rounded-md px-1.5 py-1.5 text-sm hover:bg-bg-subtle">
              <FileText className="mt-0.5 size-3.5 shrink-0 text-subtle" />
              <span className="min-w-0">
                <span className="line-clamp-2">{r.title}</span>
                <span className="block text-[11px] text-subtle">
                  {r.publisher || "Unknown publisher"} · {fmtDay(r.publishedAt)}
                </span>
              </span>
            </Link>
          </li>
        );
      })}
    </ul>
  );
}

function EdgeInspector({ ix, theme, edge, onSelectNode, onFocus, onClear }: InspectorProps & { edge: GraphEdge }) {
  const a = ix.node.get(edge.source);
  const b = ix.node.get(edge.target);
  if (!a || !b) return null;
  return (
    <div>
      <PanelHeader onClose={onClear}>
        <div className="text-xs font-semibold uppercase tracking-wider text-subtle">Relationship</div>
        <div className="mt-2 space-y-1.5">
          <NodeChip node={a} theme={theme} onClick={() => onSelectNode(a.id)} />
          <div className="pl-2 text-sm font-medium text-muted">{PREDICATE_LABEL[edge.predicate]}</div>
          <NodeChip node={b} theme={theme} onClick={() => onSelectNode(b.id)} />
        </div>
        <div className="mt-3 grid grid-cols-3 gap-2 text-center">
          <div className="rounded-lg border border-border bg-bg-elevated px-2 py-1.5">
            <div className="font-mono text-base font-semibold">{edge.weight}</div>
            <div className="text-[10px] uppercase tracking-wider text-subtle">reports</div>
          </div>
          <div className="rounded-lg border border-border bg-bg-elevated px-2 py-1.5">
            <div className="font-mono text-base font-semibold">{Math.round(edge.confidence * 100)}%</div>
            <div className="text-[10px] uppercase tracking-wider text-subtle">confidence</div>
          </div>
          <div className="rounded-lg border border-border bg-bg-elevated px-2 py-1.5">
            <div className="font-mono text-base font-semibold">{edge.stated}</div>
            <div className="text-[10px] uppercase tracking-wider text-subtle">stated</div>
          </div>
        </div>
        <p className="mt-2 text-[11px] leading-snug text-subtle">
          {edge.basis === "stated"
            ? "At least one report states this link in a single sentence."
            : "No report states it directly: both appear as observed facts in the same report(s). Treat it as an association."}{" "}
          Last seen {fmtDay(edge.lastSeen)}. Strength {edgeStrength(edge).toFixed(1)}.
        </p>
        <div className="mt-3 flex gap-2">
          {[a, b].map((n) => (
            <button key={n.id} type="button" onClick={() => onFocus(n.id)} title={`Focus on ${n.label}`} className="inline-flex h-8 min-w-0 flex-1 items-center gap-1.5 rounded-lg border border-border px-2.5 text-xs hover:bg-bg-subtle">
              <Crosshair className="size-3.5 shrink-0" />
              <span className="truncate">Focus {n.label}</span>
            </button>
          ))}
        </div>
        <button
          type="button"
          onClick={() => askAgentAbout({ ref: a.id, label: a.label, relation: { from: a.label, predicate: PREDICATE_LABEL[edge.predicate], to: b.label } })}
          {...entityDragProps({ ref: a.id, label: `${a.label} ${PREDICATE_LABEL[edge.predicate]} ${b.label}`, relation: { from: a.label, predicate: PREDICATE_LABEL[edge.predicate], to: b.label } })}
          title="Ask the AI Agent to explain this link (or drag it onto the AI Agent button)"
          className="mt-2 inline-flex h-8 w-full cursor-grab items-center justify-center gap-1.5 rounded-lg border border-border text-xs hover:bg-bg-subtle active:cursor-grabbing"
        >
          <GripVertical className="size-3.5 text-subtle" />
          <Bot className="size-3.5 text-primary" /> Ask the agent about this link
        </button>
      </PanelHeader>
      {edge.quote && (
        <Section title="Stated in">
          <blockquote className="flex gap-2 rounded-lg border border-border bg-bg-elevated p-3 text-sm leading-relaxed">
            <Quote className="mt-0.5 size-3.5 shrink-0 text-subtle" />
            <span>
              {edge.quote.text}
              {ix.graph.reports[edge.quote.reportId] && (
                <Link to="/library/$reportId" params={{ reportId: edge.quote.reportId }} className="mt-1 block text-[11px] text-primary hover:underline">
                  {ix.graph.reports[edge.quote.reportId].title}
                </Link>
              )}
            </span>
          </blockquote>
        </Section>
      )}
      <Section title="Supporting reports" count={edge.weight}>
        <ReportList ids={edge.reports} ix={ix} />
      </Section>
    </div>
  );
}

function AiBrief({ node, ix, theme, onSelectNode }: { node: GraphNode; ix: GraphIndex; theme: GraphTheme; onSelectNode: (id: string) => void }) {
  const brief = useMutation({ mutationFn: (refresh: boolean) => explainGraphNode({ data: { nodeId: node.id, refresh } }) });
  // Models sometimes write IDs ("technique:T1003.001") in prose; show the entity names instead.
  const readable = (text: string) =>
    text.replace(/\[?((?:actor|campaign|malware|tool|technique|vulnerability|sector|geography|platform|indicator):[^\s\],;)]+)\]?/g, (m, raw: string) => {
      const id = ix.node.has(raw) ? raw : raw.replace(/\.+$/, "");
      const n = ix.node.get(id);
      return n ? n.label + raw.slice(id.length) : m;
    });
  const ref = (id: string) => {
    if (id.startsWith("report:")) {
      const rid = id.slice(7);
      const r = ix.graph.reports[rid];
      return r ? (
        <Link key={id} to="/library/$reportId" params={{ reportId: rid }} className="inline-flex max-w-[14rem] items-center gap-1 rounded-md border border-border px-1.5 py-0.5 text-[11px] hover:border-border-strong">
          <FileText className="size-3 shrink-0 text-subtle" />
          <span className="truncate">{r.title}</span>
        </Link>
      ) : null;
    }
    const n = ix.node.get(id);
    return n ? <NodeChip key={id} node={n} theme={theme} onClick={() => onSelectNode(id)} /> : null;
  };
  const data = brief.data
    ? { ...brief.data, summary: readable(brief.data.summary), points: brief.data.points.map((p) => ({ ...p, text: readable(p.text) })), hiddenLinks: brief.data.hiddenLinks.map((p) => ({ ...p, text: readable(p.text) })) }
    : null;
  return (
    <div className="border-t border-border px-4 py-3">
      {!data ? (
        <button
          type="button"
          onClick={() => brief.mutate(false)}
          disabled={brief.isPending}
          className="inline-flex h-8 w-full items-center justify-center gap-2 rounded-lg border border-border bg-bg-elevated text-xs font-medium hover:bg-bg-subtle disabled:opacity-70"
        >
          {brief.isPending ? <Loader2 className="size-3.5 motion-safe:animate-spin" /> : <Sparkles className="size-3.5 text-primary" />}
          {brief.isPending ? "Writing the assessment…" : "Assessment (AI when available)"}
        </button>
      ) : (
        <BriefView brief={data} render={ref} onRegenerate={() => brief.mutate(true)} busy={brief.isPending} />
      )}
      {brief.error && <p className="mt-2 text-xs text-danger">{brief.error instanceof Error ? brief.error.message : "The assessment failed."}</p>}
    </div>
  );
}
