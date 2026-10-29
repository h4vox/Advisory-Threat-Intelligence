import { useEffect, useMemo, useState, type ReactNode } from "react";
import * as Dialog from "@radix-ui/react-dialog";
import { Link } from "@tanstack/react-router";
import { useMutation, useQuery } from "@tanstack/react-query";
import { ArrowLeft, Bot, ChevronDown, FileText, GripVertical, Lightbulb, Loader2, Route as RouteIcon, Search, Sparkles, Waypoints, X } from "lucide-react";
import { askAgentAbout, entityDragProps, type EntityHandoff } from "@/components/agent-handoff";
import { graphTheme, isDarkTheme, type GraphTheme } from "@/components/graph/graph-style";
import { explainGraphNode, findConnection, getEntityContext } from "@/lib/aie/server-graph";
import type { EntityContext } from "@/lib/aie/graph/correlate";
import type { GraphBrief } from "@/lib/aie/graph/brief";
import { NODE_TYPE_LABEL, PREDICATE_LABEL, type GraphNode, type GraphReportRef } from "@/lib/aie/graph/types";
import { cn } from "@/lib/cn";

const TREND_LABEL: Record<EntityContext["trend"], string> = {
  new: "New",
  rising: "Rising",
  steady: "Steady",
  falling: "Falling",
  dormant: "Dormant",
  unknown: "Undated",
};

export function handoffFor(n: GraphNode): EntityHandoff {
  return { ref: n.id, label: n.label, kind: NODE_TYPE_LABEL[n.type].one.toLowerCase() };
}

function Dot({ color, size = 8 }: { color: string; size?: number }) {
  return <span aria-hidden className="inline-block shrink-0 rounded-full" style={{ width: size, height: size, backgroundColor: color }} />;
}

function Block({ title, hint, children, open = true }: { title: string; hint?: string; children: ReactNode; open?: boolean }) {
  return (
    <details open={open} className="group border-t border-border">
      <summary className="flex cursor-pointer list-none items-center justify-between px-5 py-3 text-xs font-semibold uppercase tracking-wider text-muted hover:text-fg">
        {title}
        <ChevronDown className="size-3.5 transition-transform group-open:rotate-180" />
      </summary>
      <div className="px-5 pb-4">
        {hint && <p className="mb-2 text-[11px] leading-snug text-subtle">{hint}</p>}
        {children}
      </div>
    </details>
  );
}

/** Entity body used by the sheet (and anywhere else that shows one entity's correlation). */
export function EntityContextBody({
  ctx,
  reports,
  theme,
  onRef,
}: {
  ctx: EntityContext;
  reports: Record<string, GraphReportRef>;
  theme: GraphTheme;
  onRef: (ref: string) => void;
}) {
  const n = ctx.node;
  const known = useMemo(() => {
    const m = new Map<string, GraphNode>([[n.id, n]]);
    for (const g of ctx.links) for (const l of g.items) m.set(l.node.id, l.node);
    for (const r of ctx.related) [r.node, ...r.via].forEach((x) => m.set(x.id, x));
    for (const s of ctx.similar) [s.node, ...s.shared].forEach((x) => m.set(x.id, x));
    return m;
  }, [ctx, n]);
  const chip = (x: GraphNode) => (
    <button
      key={x.id}
      type="button"
      onClick={() => onRef(x.id)}
      {...entityDragProps(handoffFor(x))}
      title={`${NODE_TYPE_LABEL[x.type].one}: ${x.label} — click for context, drag to the AI Agent`}
      className="inline-flex max-w-full items-center gap-1.5 rounded-md border border-border bg-bg-elevated px-2 py-0.5 text-[11px] text-fg hover:border-border-strong"
    >
      <Dot color={theme.type[x.type]} size={6} />
      <span className="truncate">{x.label}</span>
    </button>
  );
  const ref = (id: string) => {
    if (id.startsWith("report:")) {
      const r = reports[id.slice(7)];
      return r ? (
        <Link key={id} to="/library/$reportId" params={{ reportId: r.id }} className="inline-flex max-w-[14rem] items-center gap-1 rounded-md border border-border px-1.5 py-0.5 text-[11px] hover:border-border-strong">
          <FileText className="size-3 shrink-0 text-subtle" />
          <span className="truncate">{r.title}</span>
        </Link>
      ) : null;
    }
    const x = known.get(id);
    return x ? chip(x) : null;
  };
  const maxMonth = Math.max(1, ...ctx.activity.map((a) => a.reports));

  return (
    <>
      <div className="px-5 pb-4">
        <p className="text-sm leading-relaxed text-fg">{ctx.summary}</p>
        {ctx.activity.length > 1 && (
          <div className="mt-3">
            <div className="mb-1 flex items-center justify-between text-[11px] text-subtle">
              <span>Reports by month</span>
              <span className="font-medium" style={{ color: theme.type[n.type] }}>
                {TREND_LABEL[ctx.trend]}
              </span>
            </div>
            <div className="flex h-10 items-end gap-0.5" aria-label="Reports by month">
              {ctx.activity.map((a) => (
                <span key={a.month} title={`${a.month}: ${a.reports} report(s)`} className="flex-1 rounded-sm" style={{ height: `${Math.max(8, (a.reports / maxMonth) * 100)}%`, backgroundColor: theme.type[n.type], opacity: 0.75 }} />
              ))}
            </div>
          </div>
        )}
      </div>

      {ctx.findings.length > 0 && (
        <Block title="Findings" hint="Worked out by the engine from the library's links (no AI).">
          <ul className="space-y-2.5">
            {ctx.findings.map((f, i) => (
              <li key={i} className="text-sm leading-snug">
                {f.text}
                {f.refs.length > 0 && <div className="mt-1 flex flex-wrap gap-1">{f.refs.map(ref)}</div>}
              </li>
            ))}
          </ul>
        </Block>
      )}

      <AiBriefBlock nodeId={n.id} render={ref} />

      <Block title="Connections">
        <div className="space-y-3">
          {ctx.links.map((g) => (
            <div key={g.type}>
              <div className="mb-1 flex items-center gap-2 text-xs font-medium text-muted">
                <Dot color={theme.type[g.type]} size={6} />
                {NODE_TYPE_LABEL[g.type].many}
                <span className="text-subtle">{g.total}</span>
              </div>
              <div className="flex flex-wrap gap-1">
                {g.items.map((l) => (
                  <span key={l.edge.id} className="inline-flex items-center gap-1" title={`${l.outgoing ? PREDICATE_LABEL[l.edge.predicate] : `${PREDICATE_LABEL[l.edge.predicate]} by`} · ${l.edge.weight} report(s) · ${Math.round(l.edge.confidence * 100)}%${l.edge.basis === "stated" ? " · stated" : ""}`}>
                    {chip(l.node)}
                  </span>
                ))}
              </div>
            </div>
          ))}
          {!ctx.links.length && <p className="text-xs text-subtle">No links yet.</p>}
        </div>
      </Block>

      {ctx.related.length > 0 && (
        <Block title="Related through shared links" hint="Not directly linked, but connected through the entities shown after “via”; common hubs count less.">
          <ul className="space-y-2">
            {ctx.related.slice(0, 8).map((r) => (
              <li key={r.node.id} className="flex flex-wrap items-center gap-1.5 text-xs">
                {chip(r.node)}
                <span className="text-subtle">via</span>
                {r.via.map(chip)}
              </li>
            ))}
          </ul>
        </Block>
      )}

      {ctx.similar.length > 0 && (
        <Block title="Possible hidden links" hint="Share unusually much behaviour, tooling, targets or infrastructure; no report states a link." open={false}>
          <ul className="space-y-2">
            {ctx.similar.map((s) => (
              <li key={s.node.id} className="text-xs">
                <div className="flex items-center gap-2">
                  {chip(s.node)}
                  <span className="font-mono text-subtle">{Math.round(s.score * 100)}% overlap</span>
                </div>
                <div className="mt-1 flex flex-wrap gap-1 pl-2">{s.shared.slice(0, 6).map(chip)}</div>
              </li>
            ))}
          </ul>
        </Block>
      )}

      {ctx.attack && (
        <Block title={`ATT&CK ${ctx.attack.id}`} open={false}>
          {ctx.attack.description && <p className="mb-2 line-clamp-4 text-xs leading-relaxed text-muted">{ctx.attack.description.replace(/\(Citation:[^)]*\)/g, "")}</p>}
          {ctx.attack.tactics && <p className="text-xs text-muted">Tactics: {ctx.attack.tactics.join(", ")}</p>}
          {ctx.attack.platforms?.length ? <p className="text-xs text-muted">Platforms: {ctx.attack.platforms.join(", ")}</p> : null}
          {ctx.attack.mitigations?.length ? <p className="mt-1 text-xs text-muted">Mitigations: {ctx.attack.mitigations.map((m) => `${m.id} ${m.name}`).join("; ")}</p> : null}
          {ctx.attack.shared && (
            <p className="text-xs text-muted">
              {ctx.attack.shared.length} observed technique(s) match ATT&CK; {ctx.attack.newInLibrary?.length ?? 0} are not in ATT&CK's entry; {ctx.attack.notSeen ?? 0} ATT&CK technique(s) not seen in the library.
            </p>
          )}
          {ctx.attack.newInLibrary?.length ? <div className="mt-1.5 flex flex-wrap gap-1">{ctx.attack.newInLibrary.map((t) => ref(`technique:${t}`))}</div> : null}
        </Block>
      )}

      <Block title="Reports" open={false}>
        <ul className="space-y-1">
          {n.reports.slice(0, 20).map((id) => {
            const r = reports[id];
            return r ? (
              <li key={id}>
                <Link to="/library/$reportId" params={{ reportId: id }} className="flex items-start gap-2 rounded-md px-1.5 py-1 text-sm hover:bg-bg-subtle">
                  <FileText className="mt-0.5 size-3.5 shrink-0 text-subtle" />
                  <span className="min-w-0">
                    <span className="line-clamp-2">{r.title}</span>
                    <span className="block text-[11px] text-subtle">
                      {r.publisher || "Unknown publisher"} · {r.publishedAt?.slice(0, 10) ?? "undated"}
                    </span>
                  </span>
                </Link>
              </li>
            ) : null;
          })}
        </ul>
      </Block>
    </>
  );
}

function AiBriefBlock({ nodeId, render }: { nodeId: string; render: (id: string) => ReactNode }) {
  const brief = useMutation({ mutationFn: (refresh: boolean) => explainGraphNode({ data: { nodeId, refresh } }) });
  return (
    <div className="border-t border-border px-5 py-3">
      {!brief.data ? (
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
        <BriefView brief={brief.data} render={render} onRegenerate={() => brief.mutate(true)} busy={brief.isPending} />
      )}
      {brief.error && <p className="mt-2 text-xs text-danger">{brief.error instanceof Error ? brief.error.message : "The assessment failed."}</p>}
    </div>
  );
}

export function BriefView({ brief, render, onRegenerate, busy }: { brief: GraphBrief; render: (id: string) => ReactNode; onRegenerate: () => void; busy: boolean }) {
  const points = (title: string, list: GraphBrief["points"], icon?: ReactNode) =>
    list.length ? (
      <div>
        <div className="mb-1.5 flex items-center gap-1.5 text-[11px] font-semibold uppercase tracking-wider text-subtle">
          {icon}
          {title}
        </div>
        <ul className="space-y-2">
          {list.map((p, i) => (
            <li key={i} className="text-sm leading-snug">
              {p.text}
              <div className="mt-1 flex flex-wrap gap-1">{p.refs.map(render)}</div>
            </li>
          ))}
        </ul>
      </div>
    ) : null;
  return (
    <div className="space-y-3">
      <div className="flex items-center justify-between gap-2">
        <span className="inline-flex items-center gap-1.5 text-[11px] font-semibold uppercase tracking-wider text-subtle">
          <Sparkles className="size-3.5 text-primary" /> {brief.source === "ai" ? "AI assessment" : "Engine assessment"}
        </span>
        <button type="button" onClick={onRegenerate} disabled={busy} className="text-[11px] text-primary hover:underline disabled:opacity-60">
          {busy ? "Working…" : brief.source === "ai" ? "Regenerate" : "Try the AI again"}
        </button>
      </div>
      {brief.note && <p className="rounded-md border border-border bg-bg-elevated px-2.5 py-1.5 text-[11px] text-muted">{brief.note}</p>}
      {brief.summary && <p className="text-sm leading-relaxed">{brief.summary}</p>}
      {points("Key points", brief.points)}
      {points("Worth checking", brief.hiddenLinks, <Lightbulb className="size-3.5" />)}
      {brief.gaps.length > 0 && (
        <div>
          <div className="mb-1 text-[11px] font-semibold uppercase tracking-wider text-subtle">Gaps</div>
          <ul className="list-disc space-y-1 pl-4 text-xs text-muted">
            {brief.gaps.map((g, i) => (
              <li key={i}>{g}</li>
            ))}
          </ul>
        </div>
      )}
      <p className="text-[10px] text-subtle">
        {brief.source === "ai"
          ? `Written by ${brief.provider} from the library's facts only; every point cites them.${brief.dropped ? ` ${brief.dropped} uncited point(s) removed.` : ""}`
          : "Computed by the AIE engine from the library's links."}
      </p>
    </div>
  );
}

function ConnectBox({ from, theme, onRef }: { from: GraphNode; theme: GraphTheme; onRef: (ref: string) => void }) {
  const [to, setTo] = useState("");
  const [asked, setAsked] = useState<string | null>(null);
  const q = useQuery({ queryKey: ["intel-connection", from.id, asked], queryFn: () => findConnection({ data: { from: from.id, to: asked! } }), enabled: Boolean(asked) });
  return (
    <Block title="How is it connected to…" open={false} hint="Any actor, malware, technique, CVE, sector or indicator: the engine traces the strongest short paths.">
      <form
        className="flex gap-2"
        onSubmit={(e) => {
          e.preventDefault();
          if (to.trim()) setAsked(to.trim());
        }}
      >
        <input
          value={to}
          onChange={(e) => setTo(e.target.value)}
          placeholder="e.g. Cobalt Strike, T1190, Finance"
          className="h-8 min-w-0 flex-1 rounded-lg border border-border bg-bg-elevated px-2.5 text-sm placeholder:text-subtle focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring/60"
        />
        <button type="submit" className="inline-flex h-8 items-center gap-1.5 rounded-lg border border-border px-2.5 text-xs hover:bg-bg-subtle">
          <RouteIcon className="size-3.5" /> Trace
        </button>
      </form>
      {q.isFetching && <p className="mt-2 text-xs text-muted">Tracing…</p>}
      {q.data && !q.isFetching && (
        <div className="mt-3 space-y-2">
          {!q.data.to ? (
            <p className="text-xs text-subtle">Nothing in the library matches “{asked}”.</p>
          ) : !q.data.paths.length ? (
            <p className="text-xs text-subtle">No path of up to 4 links connects them.</p>
          ) : (
            q.data.paths.map((p, i) => (
              <div key={i} className="flex flex-wrap items-center gap-1 rounded-lg border border-border bg-bg-elevated p-2 text-[11px]">
                {p.nodes.map((x, j) => (
                  <span key={x.id + j} className="inline-flex items-center gap-1">
                    {j > 0 && <span className="text-subtle">{PREDICATE_LABEL[p.edges[j - 1].predicate]} →</span>}
                    <button type="button" onClick={() => onRef(x.id)} className="inline-flex items-center gap-1 rounded px-1 hover:bg-bg-subtle">
                      <Dot color={theme.type[x.type]} size={6} />
                      {x.label}
                    </button>
                  </span>
                ))}
              </div>
            ))
          )}
        </div>
      )}
    </Block>
  );
}

/**
 * Side panel with everything the engine correlates with one entity. Opened from anywhere
 * (openEntityContext in ./agent-handoff); clicking an entity inside it moves to that entity
 * (Back returns).
 */
export function EntityContextSheet({ refValue, onOpenChange, onRef }: { refValue: string | null; onOpenChange: (open: boolean) => void; onRef: (ref: string) => void }) {
  const [history, setHistory] = useState<string[]>([]);
  const [dark, setDark] = useState(true);
  useEffect(() => setDark(isDarkTheme()), [refValue]);
  const theme = useMemo(() => graphTheme(dark), [dark]);
  useEffect(() => {
    if (!refValue) setHistory([]);
  }, [refValue]);
  const q = useQuery({ queryKey: ["entity-context", refValue], queryFn: () => getEntityContext({ data: { ref: refValue! } }), enabled: Boolean(refValue), staleTime: 60_000 });
  const go = (ref: string) => {
    if (refValue) setHistory((h) => [...h, refValue].slice(-20));
    onRef(ref);
  };
  const back = () => {
    const prev = history[history.length - 1];
    if (!prev) return;
    setHistory((h) => h.slice(0, -1));
    onRef(prev);
  };
  const ctx = q.data?.context;
  const n = ctx?.node;

  return (
    <Dialog.Root open={Boolean(refValue)} onOpenChange={onOpenChange}>
      <Dialog.Portal>
        <Dialog.Overlay className="fixed inset-0 z-50 bg-black/30" />
        <Dialog.Content className="dropdown-liquid-glass fixed inset-y-0 right-0 z-50 flex w-[min(30rem,100vw)] flex-col overflow-hidden border-l border-border focus:outline-none">
          <div className="flex items-start gap-2 px-5 pb-3 pt-4">
            {history.length > 0 && (
              <button type="button" aria-label="Back" onClick={back} className="mt-0.5 inline-flex size-7 shrink-0 items-center justify-center rounded-md text-muted hover:bg-bg-subtle hover:text-fg">
                <ArrowLeft className="size-4" />
              </button>
            )}
            <div className="min-w-0 flex-1">
              <div className="flex items-center gap-2 text-xs font-medium" style={{ color: n ? theme.type[n.type] : undefined }}>
                {n && <Dot color={theme.type[n.type]} />}
                {n ? NODE_TYPE_LABEL[n.type].one : "Intelligence context"}
                {n?.attackId && <span className="text-subtle">· {n.attackId}</span>}
              </div>
              <Dialog.Title className="mt-0.5 break-words text-lg font-semibold leading-snug text-fg">{n?.label ?? refValue}</Dialog.Title>
              <Dialog.Description className="text-xs text-subtle">
                {n ? `${n.reportCount} report(s) · first seen ${n.firstSeen?.slice(0, 10) ?? "—"} · last seen ${n.lastSeen?.slice(0, 10) ?? "—"}` : "Everything the library correlates with this entity."}
              </Dialog.Description>
            </div>
            <Dialog.Close aria-label="Close" className="inline-flex size-7 shrink-0 items-center justify-center rounded-md text-muted hover:bg-bg-subtle hover:text-fg">
              <X className="size-4" />
            </Dialog.Close>
          </div>
          {n && (
            <div className="flex flex-wrap items-center gap-2 px-5 pb-3">
              <button
                type="button"
                onClick={() => {
                  askAgentAbout(handoffFor(n));
                  onOpenChange(false);
                }}
                {...entityDragProps(handoffFor(n))}
                title="Send to the AI Agent (or drag this onto the AI Agent button)"
                className="btn-primary inline-flex h-8 cursor-grab items-center gap-1.5 rounded-lg px-3 text-xs font-semibold active:cursor-grabbing"
              >
                <GripVertical className="size-3.5 opacity-70" />
                <Bot className="size-3.5" /> Ask the agent
              </button>
              <Link
                to="/graph"
                search={{ focus: n.id }}
                onClick={() => onOpenChange(false)}
                className="inline-flex h-8 items-center gap-1.5 rounded-lg border border-border px-3 text-xs hover:bg-bg-subtle"
              >
                <Waypoints className="size-3.5" /> Open in Intel Graph
              </Link>
            </div>
          )}
          <div className="min-h-0 flex-1 overflow-y-auto pb-6">
            {q.isPending ? (
              <div className="flex items-center gap-2 px-5 py-6 text-sm text-muted">
                <Loader2 className="size-4 motion-safe:animate-spin" /> Correlating…
              </div>
            ) : q.error ? (
              <p className="px-5 py-4 text-sm text-danger">{q.error instanceof Error ? q.error.message : "Could not load the context."}</p>
            ) : !ctx ? (
              <div className="px-5 py-4 text-sm text-muted">
                <p>Nothing in the library matches “{refValue}” yet.</p>
                {q.data?.suggestions.length ? (
                  <div className="mt-3">
                    <div className="mb-1.5 flex items-center gap-1.5 text-xs text-subtle">
                      <Search className="size-3.5" /> Did you mean
                    </div>
                    <div className="flex flex-wrap gap-1">
                      {q.data.suggestions.map((s) => (
                        <button key={s.id} type="button" onClick={() => go(s.id)} className="rounded-md border border-border px-2 py-0.5 text-xs hover:border-border-strong">
                          {s.label}
                        </button>
                      ))}
                    </div>
                  </div>
                ) : null}
              </div>
            ) : (
              <>
                <EntityContextBody ctx={ctx} reports={q.data!.reports} theme={theme} onRef={go} />
                <ConnectBox from={ctx.node} theme={theme} onRef={go} />
              </>
            )}
          </div>
          {q.isFetching && !q.isPending && <div className={cn("pointer-events-none absolute right-12 top-5 text-[10px] text-subtle")}>updating…</div>}
        </Dialog.Content>
      </Dialog.Portal>
    </Dialog.Root>
  );
}
