import { Component, Suspense, lazy, useCallback, useEffect, useMemo, useState, type ComponentProps, type ComponentType, type ReactNode } from "react";
import { createFileRoute, useNavigate } from "@tanstack/react-router";
import { useQuery } from "@tanstack/react-query";
import { z } from "zod";
import { Box, ChevronRight, Orbit, RefreshCw, SlidersHorizontal, Square, Waypoints } from "lucide-react";
import { AppShell } from "@/components/app-shell";
import { openEntityContext } from "@/components/agent-handoff";
import { GraphCanvas } from "@/components/graph/graph-canvas";
import { FilterPanel, GRAPH_DETAILS, Inspector, TIME_WINDOWS, TypeDot, type GraphDetail, type TimeWindow } from "@/components/graph/graph-panels";
import { graphTheme, isDarkTheme } from "@/components/graph/graph-style";
import { ActivitySpinner } from "@/components/ui/activity-spinner";
import { EmptyState } from "@/components/ui/primitives";
import { DEFAULT_FILTER, focusView, indexGraph, overviewView, type GraphFilter } from "@/lib/aie/graph/analyze";
import { forceLayout, layout3d, radialLayout, type GraphLayout3 } from "@/lib/aie/graph/layout";
import { withEdgeIds } from "@/lib/aie/graph/client";
import type { IntelGraph } from "@/lib/aie/graph/types";
import { getIntelGraph } from "@/lib/aie/server-graph";
import { cn } from "@/lib/cn";

const searchSchema = z.object({
  focus: z.string().max(400).optional(),
  hops: z.union([z.literal(1), z.literal(2)]).optional(),
});

// The 3D view (three.js) loads only when it is shown.
// If it cannot load (e.g. three.js not installed yet), the page shows the 2D view and says why.
let threeDUnavailable = false;
type Canvas3DProps = Omit<ComponentProps<typeof GraphCanvas>, "layout"> & { layout: GraphLayout3; onFallback?: () => void };
const GraphCanvas3D = lazy<ComponentType<Canvas3DProps>>(() =>
  import("@/components/graph/graph-canvas-3d")
    .then((m) => ({ default: m.GraphCanvas3D as ComponentType<Canvas3DProps> }))
    .catch(() => {
      threeDUnavailable = true;
      return { default: ThreeDUnavailable };
    }),
);

function ThreeDUnavailable({ onFallback }: { onFallback?: () => void }) {
  useEffect(() => {
    onFallback?.();
  }, [onFallback]);
  return null;
}

/** Any crash inside the 3D view (WebGL context lost, driver issue) falls back to 2D. */
class Canvas3DBoundary extends Component<{ onError: () => void; children: ReactNode }, { failed: boolean }> {
  state = { failed: false };
  static getDerivedStateFromError() {
    return { failed: true };
  }
  componentDidCatch(err: unknown) {
    console.warn("[intel-graph] 3D view failed, showing 2D:", err);
    this.props.onError();
  }
  render() {
    return this.state.failed ? null : this.props.children;
  }
}

function GraphCanvas3DSafe(props: Canvas3DProps) {
  return (
    <Canvas3DBoundary onError={() => props.onFallback?.()}>
      <GraphCanvas3D {...props} />
    </Canvas3DBoundary>
  );
}

/** True when the browser can draw WebGL (the 3D view); false on machines without it. */
function webglAvailable(): boolean {
  try {
    const c = document.createElement("canvas");
    return Boolean(c.getContext("webgl2") || c.getContext("webgl"));
  } catch {
    return false;
  }
}

const DIMENSION_KEY = "aie_graph_dimension";

/**
 * Page layout: filters | graph | details on wide screens, stacked on small ones. Rendered with the
 * page (not in the shared stylesheet) so the columns hold even when a browser or proxy serves an
 * older cached stylesheet.
 */
const GRAPH_LAYOUT_CSS = `
.ig-root{display:flex;flex-direction:column;flex:1 1 0%;min-height:0;min-width:0;overflow-x:hidden;overflow-y:auto}
.ig-body{display:flex;flex-direction:column;flex:1 1 0%;min-height:0;min-width:0}
.ig-left{min-width:0;border-bottom:1px solid var(--color-border)}
.ig-right{min-width:0;border-top:1px solid var(--color-border)}
.ig-canvas{position:relative;display:flex;flex-direction:column;min-width:0;height:68vh;min-height:420px;overflow:hidden}
.ig-canvas>*:first-child{flex:1 1 0%;min-height:0}
@media (min-width:1024px){
  .ig-root{overflow:hidden}
  .ig-body{display:grid;grid-template-columns:18rem minmax(0,1fr) 24rem;grid-template-rows:minmax(0,1fr)}
  .ig-left,.ig-right{min-height:0;overflow-x:hidden;overflow-y:auto;border:0}
  .ig-left{border-right:1px solid var(--color-border)}
  .ig-right{border-left:1px solid var(--color-border)}
  .ig-canvas{height:auto;min-height:0}
}
@media (min-width:1024px) and (max-width:1279px){
  .ig-body{grid-template-columns:16rem minmax(0,1fr) 21rem}
}`;

export const Route = createFileRoute("/graph")({
  validateSearch: (search) => searchSchema.parse(search),
  component: IntelGraphPage,
});

function useDarkTheme() {
  const [dark, setDark] = useState(true);
  useEffect(() => {
    const sync = () => setDark(isDarkTheme());
    sync();
    window.addEventListener("aie-theme-changed", sync);
    return () => window.removeEventListener("aie-theme-changed", sync);
  }, []);
  return dark;
}

function IntelGraphPage() {
  const search = Route.useSearch();
  const navigate = useNavigate({ from: "/graph" });
  const center = search.focus ?? null;
  const hops = search.hops ?? 1;
  const dark = useDarkTheme();
  const theme = useMemo(() => graphTheme(dark), [dark]);

  const query = useQuery({ queryKey: ["intel-graph"], queryFn: async () => withEdgeIds(JSON.parse(await getIntelGraph()) as IntelGraph), staleTime: 60_000 });
  const ix = useMemo(() => (query.data ? indexGraph(query.data) : null), [query.data]);

  const [filter, setFilter] = useState<GraphFilter>(DEFAULT_FILTER);
  const [windowValue, setWindowValue] = useState<TimeWindow>("all");
  const [detail, setDetail] = useState<GraphDetail>("standard");
  const [selectedNode, setSelectedNode] = useState<string | null>(center);
  const [selectedEdge, setSelectedEdge] = useState<string | null>(null);
  const [trail, setTrail] = useState<string[]>(center ? [center] : []);
  const [filtersOpen, setFiltersOpen] = useState(false);

  const effective = useMemo<GraphFilter>(() => {
    const days = TIME_WINDOWS.find((w) => w.value === windowValue)?.days ?? 0;
    return { ...filter, since: days ? new Date(Date.now() - days * 86_400_000).toISOString().slice(0, 10) : null };
  }, [filter, windowValue]);

  const view = useMemo(() => {
    if (!ix) return null;
    if (center && ix.node.has(center)) return focusView(ix, center, effective, { hops });
    return overviewView(ix, effective, GRAPH_DETAILS.find((d) => d.id === detail)?.nodes ?? 160);
  }, [ix, center, effective, hops, detail]);
  const [dimension, setDimension] = useState<"2d" | "3d">("3d");
  const [no3d, setNo3d] = useState<string | null>(null);
  useEffect(() => {
    if (!webglAvailable()) {
      setNo3d("This browser cannot draw 3D (WebGL is off), so the graph is shown in 2D.");
      setDimension("2d");
      return;
    }
    try {
      if (localStorage.getItem(DIMENSION_KEY) === "2d") setDimension("2d");
    } catch {
      /* storage unavailable */
    }
  }, []);
  const fallbackTo2d = useCallback(() => {
    setNo3d(
      threeDUnavailable
        ? "The 3D view could not load (its library is missing on the server: run npm install and restart), so the graph is shown in 2D."
        : "The 3D view could not start, so the graph is shown in 2D.",
    );
    setDimension("2d");
  }, []);
  const changeDimension = (d: "2d" | "3d") => {
    setDimension(d);
    try {
      localStorage.setItem(DIMENSION_KEY, d);
    } catch {
      /* storage unavailable */
    }
  };
  const layout = useMemo(() => (view && dimension === "2d" ? (view.mode === "focus" ? radialLayout(view) : forceLayout(view)) : null), [view, dimension]);
  const layout3 = useMemo(() => (view && dimension === "3d" ? layout3d(view) : null), [view, dimension]);

  const focus = (id: string | null) => {
    navigate({ search: (s) => ({ ...s, focus: id ?? undefined }), replace: false });
    setSelectedNode(id);
    setSelectedEdge(null);
    if (id) setTrail((t) => [...t.filter((x) => x !== id), id].slice(-8));
  };
  const setHops = (h: 1 | 2) => navigate({ search: (s) => ({ ...s, hops: h === 1 ? undefined : h }), replace: true });

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape" && !(e.target instanceof HTMLInputElement)) {
        setSelectedNode(null);
        setSelectedEdge(null);
      }
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, []);

  const stats = query.data?.stats;
  const centerNode = center && ix ? ix.node.get(center) : undefined;

  return (
    <AppShell flush>
      <div className="ig-root">
        <style dangerouslySetInnerHTML={{ __html: GRAPH_LAYOUT_CSS }} />
        {/* Top strip: title, mode and counts. */}
        <div className="flex flex-wrap items-center gap-x-5 gap-y-2 border-b border-border px-4 py-3 md:px-6">
          <div className="flex items-center gap-2.5">
            <span className="inline-flex size-8 items-center justify-center rounded-lg" style={{ color: "var(--color-primary)", backgroundColor: "color-mix(in oklab, var(--color-primary) 14%, transparent)" }}>
              <Waypoints className="size-4" />
            </span>
            <div>
              <h1 className="text-base font-semibold leading-tight">Intel Graph</h1>
              <p className="text-[11px] text-subtle">Every actor, tool, technique, target and indicator, linked by what the reports say</p>
            </div>
          </div>

          <div role="tablist" aria-label="View" className="inline-flex rounded-lg border border-border bg-bg-elevated p-0.5">
            <button
              type="button"
              role="tab"
              aria-selected={!center}
              onClick={() => focus(null)}
              className={cn("inline-flex h-7 items-center gap-1.5 rounded-md px-2.5 text-xs font-medium", !center ? "bg-bg-subtle text-fg" : "text-muted hover:text-fg")}
            >
              <Orbit className="size-3.5" /> Overview
            </button>
            <button
              type="button"
              role="tab"
              aria-selected={Boolean(center)}
              disabled={!selectedNode && !center}
              onClick={() => selectedNode && focus(selectedNode)}
              title={!selectedNode && !center ? "Select an entity first" : undefined}
              className={cn("inline-flex h-7 items-center gap-1.5 rounded-md px-2.5 text-xs font-medium disabled:opacity-50", center ? "bg-bg-subtle text-fg" : "text-muted hover:text-fg")}
            >
              Focus
            </button>
          </div>
          <div role="radiogroup" aria-label="Dimensions" className="inline-flex rounded-lg border border-border bg-bg-elevated p-0.5">
            {(["3d", "2d"] as const).map((d) => (
              <button
                key={d}
                type="button"
                role="radio"
                aria-checked={dimension === d}
                onClick={() => changeDimension(d)}
                disabled={d === "3d" && Boolean(no3d)}
                title={d === "3d" && no3d ? no3d : undefined}
                className={cn("inline-flex h-7 items-center gap-1.5 rounded-md px-2.5 text-xs font-medium disabled:opacity-40", dimension === d ? "bg-bg-subtle text-fg" : "text-muted hover:text-fg")}
              >
                {d === "3d" ? <Box className="size-3.5" /> : <Square className="size-3.5" />}
                {d.toUpperCase()}
              </button>
            ))}
          </div>
          {center && (
            <div role="radiogroup" aria-label="Depth" className="inline-flex rounded-lg border border-border bg-bg-elevated p-0.5">
              {([1, 2] as const).map((h) => (
                <button
                  key={h}
                  type="button"
                  role="radio"
                  aria-checked={hops === h}
                  onClick={() => setHops(h)}
                  className={cn("h-7 rounded-md px-2.5 text-xs font-medium", hops === h ? "bg-bg-subtle text-fg" : "text-muted hover:text-fg")}
                >
                  {h === 1 ? "Direct links" : "2 hops"}
                </button>
              ))}
            </div>
          )}

          <div className="ml-auto flex flex-wrap items-center gap-x-4 gap-y-1 font-mono text-[11px] text-muted">
            {stats && (
              <>
                <span>
                  <b className="text-fg">{stats.nodes.toLocaleString()}</b> entities
                </span>
                <span>
                  <b className="text-fg">{stats.edges.toLocaleString()}</b> links
                </span>
                <span>
                  <b className="text-fg">{stats.edges ? Math.round((stats.stated / stats.edges) * 100) : 0}%</b> stated
                </span>
                <span>
                  <b className="text-fg">{stats.reports.toLocaleString()}</b> reports
                </span>
                {view && (
                  <span className="text-subtle">
                    showing {view.nodes.length}
                    {view.hidden > 0 ? ` · ${view.hidden} more filtered for clarity` : ""}
                  </span>
                )}
              </>
            )}
            <button
              type="button"
              onClick={() => query.refetch()}
              aria-label="Reload the graph"
              title="Reload the graph"
              className="inline-flex size-7 items-center justify-center rounded-md text-muted hover:bg-bg-subtle hover:text-fg"
            >
              <RefreshCw className={cn("size-3.5", query.isFetching && "motion-safe:animate-spin")} />
            </button>
          </div>
        </div>

        {no3d && <div className="border-b border-border bg-bg-elevated px-4 py-1.5 text-xs text-muted md:px-6">{no3d}</div>}
        {query.isPending ? (
          <div className="grid flex-1 place-items-center p-10">
            <div className="flex items-center gap-3 text-sm text-muted">
              <ActivitySpinner size="md" /> Building the graph from the library…
            </div>
          </div>
        ) : query.error ? (
          <div className="p-6">
            <EmptyState title="The graph could not be loaded" description={query.error instanceof Error ? query.error.message : String(query.error)} />
          </div>
        ) : !ix || !ix.graph.nodes.length ? (
          <div className="p-6">
            <EmptyState title="Nothing to map yet" description="The graph is built from analysed library reports. Run the crawler or ingest reports, then come back." />
          </div>
        ) : (
          <div className="ig-body">
            {/* Left: filters (a collapsible sheet on small screens). */}
            <aside className="ig-left">
              <button
                type="button"
                onClick={() => setFiltersOpen((v) => !v)}
                aria-expanded={filtersOpen}
                className="flex w-full items-center gap-2 px-4 py-3 text-sm font-medium lg:hidden"
              >
                <SlidersHorizontal className="size-4" /> Search and filters
                <ChevronRight className={cn("ml-auto size-4 transition-transform", filtersOpen && "rotate-90")} />
              </button>
              <div className={cn(filtersOpen ? "block" : "hidden", "lg:block")}>
                <FilterPanel
                  ix={ix}
                  theme={theme}
                  filter={filter}
                  onFilter={setFilter}
                  windowValue={windowValue}
                  onWindow={setWindowValue}
                  detail={detail}
                  onDetail={setDetail}
                  onPick={(id) => {
                    setFiltersOpen(false);
                    // Entities left out of the browser copy open in the context panel instead.
                    if (!ix.node.has(id)) return openEntityContext(id);
                    setSelectedNode(id);
                    setSelectedEdge(null);
                    focus(id);
                  }}
                />
              </div>
            </aside>

            {/* Centre: the graph and the trail of entities visited. */}
            <section className="ig-canvas">
              {view && layout3 && view.nodes.length ? (
                <Suspense fallback={<div className="grid flex-1 place-items-center text-sm text-muted">Loading the 3D view…</div>}>
                  <GraphCanvas3DSafe
                    onFallback={fallbackTo2d}
                    className="min-h-0 flex-1"
                    view={view}
                    layout={layout3}
                    theme={theme}
                    selectedNode={selectedNode}
                    selectedEdge={selectedEdge}
                    onSelectNode={setSelectedNode}
                    onSelectEdge={setSelectedEdge}
                    onFocus={(id) => focus(id)}
                  />
                </Suspense>
              ) : view && layout && view.nodes.length ? (
                <GraphCanvas
                  className="min-h-0 flex-1"
                  view={view}
                  layout={layout}
                  theme={theme}
                  selectedNode={selectedNode}
                  selectedEdge={selectedEdge}
                  onSelectNode={setSelectedNode}
                  onSelectEdge={setSelectedEdge}
                  onFocus={(id) => focus(id)}
                />
              ) : (
                <div className="grid flex-1 place-items-center p-8 text-center text-sm text-muted">No entity passes the current filters. Widen the filters on the left.</div>
              )}
              {(trail.length > 0 || centerNode) && (
                <nav aria-label="Visited entities" className="absolute bottom-3 left-3 right-16 flex flex-wrap items-center gap-1">
                  <button type="button" onClick={() => focus(null)} className="rounded-md border border-border bg-bg-elevated/90 px-2 py-1 text-[11px] text-muted backdrop-blur hover:text-fg">
                    Overview
                  </button>
                  {trail.map((id) => {
                    const n = ix.node.get(id);
                    if (!n) return null;
                    return (
                      <span key={id} className="flex items-center gap-1">
                        <ChevronRight className="size-3 text-subtle" />
                        <button
                          type="button"
                          onClick={() => focus(id)}
                          className={cn(
                            "inline-flex max-w-[11rem] items-center gap-1.5 rounded-md border bg-bg-elevated/90 px-2 py-1 text-[11px] backdrop-blur",
                            id === center ? "border-primary text-fg" : "border-border text-muted hover:text-fg",
                          )}
                        >
                          <TypeDot type={n.type} theme={theme} size={6} />
                          <span className="truncate">{n.label}</span>
                        </button>
                      </span>
                    );
                  })}
                </nav>
              )}
            </section>

            {/* Right: details of the selection, or insights. */}
            <aside className="ig-right">
              <Inspector
                ix={ix}
                theme={theme}
                filter={effective}
                selectedNode={selectedNode}
                selectedEdge={selectedEdge}
                centerId={center}
                onSelectNode={(id) => {
                  setSelectedNode(id);
                  setSelectedEdge(null);
                }}
                onSelectEdge={setSelectedEdge}
                onFocus={(id) => focus(id)}
                onClear={() => {
                  setSelectedNode(null);
                  setSelectedEdge(null);
                }}
              />
            </aside>
          </div>
        )}
      </div>
    </AppShell>
  );
}
