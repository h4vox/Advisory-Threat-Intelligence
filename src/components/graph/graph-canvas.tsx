import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { Maximize2, Minus, Plus } from "lucide-react";
import type { GraphView } from "@/lib/aie/graph/analyze";
import type { GraphLayout, Point } from "@/lib/aie/graph/layout";
import { NODE_TYPE_LABEL, PREDICATE_LABEL, type GraphEdge, type GraphNode } from "@/lib/aie/graph/types";
import { cn } from "@/lib/cn";
import { withAlpha, type GraphTheme } from "./graph-style";

type Props = {
  view: GraphView;
  layout: GraphLayout;
  theme: GraphTheme;
  selectedNode: string | null;
  selectedEdge: string | null;
  onSelectNode: (id: string | null) => void;
  onSelectEdge: (id: string | null) => void;
  onFocus: (id: string) => void;
  className?: string;
};

type Hover = { kind: "node"; node: GraphNode } | { kind: "edge"; edge: GraphEdge } | null;

const nodeRadius = (n: GraphNode, center: boolean) => (center ? 15 : Math.min(14, 3.2 + Math.sqrt(n.reportCount) * 1.7));
const lerp = (a: number, b: number, t: number) => a + (b - a) * t;
const ease = (t: number) => 1 - Math.pow(1 - t, 3);

/**
 * Canvas drawing of one graph view. Wheel / pinch-free zoom with the buttons, drag to pan, hover
 * for a summary card, click to select, double-click to put an entity in the centre.
 */
export function GraphCanvas({ view, layout, theme, selectedNode, selectedEdge, onSelectNode, onSelectEdge, onFocus, className }: Props) {
  const wrapRef = useRef<HTMLDivElement>(null);
  const canvasRef = useRef<HTMLCanvasElement>(null);
  const [size, setSize] = useState({ w: 800, h: 600 });
  const [zoom, setZoom] = useState(1);
  const [pan, setPan] = useState({ x: 0, y: 0 });
  const [hover, setHover] = useState<Hover>(null);
  const [mouse, setMouse] = useState({ x: 0, y: 0 });
  const drag = useRef<{ x: number; y: number; px: number; py: number; moved: boolean } | null>(null);

  // Animated positions: tween from the previous layout to the new one.
  const shown = useRef(new Map<string, Point>());
  const [frame, setFrame] = useState(0);
  useEffect(() => {
    const from = new Map(shown.current);
    const start = performance.now();
    let raf = 0;
    const tick = (now: number) => {
      const t = ease(Math.min(1, (now - start) / 450));
      const next = new Map<string, Point>();
      for (const [id, p] of layout.pos) {
        const a = from.get(id) ?? (view.mode === "focus" ? { x: p.x * 0.2, y: p.y * 0.2 } : { x: p.x * 0.9, y: p.y * 0.9 });
        next.set(id, { x: lerp(a.x, p.x, t), y: lerp(a.y, p.y, t) });
      }
      shown.current = next;
      setFrame((f) => f + 1);
      if (t < 1) raf = requestAnimationFrame(tick);
    };
    raf = requestAnimationFrame(tick);
    return () => cancelAnimationFrame(raf);
  }, [layout, view.mode]);

  // Reset the camera when the view changes centre or mode.
  useEffect(() => {
    setZoom(1);
    setPan({ x: 0, y: 0 });
  }, [view.center, view.mode]);

  useEffect(() => {
    const el = wrapRef.current;
    if (!el) return;
    const ro = new ResizeObserver(([entry]) => {
      const r = entry.contentRect;
      setSize({ w: Math.max(200, Math.round(r.width)), h: Math.max(200, Math.round(r.height)) });
    });
    ro.observe(el);
    return () => ro.disconnect();
  }, []);

  // Wheel zooms the graph, never scrolls the page (React's wheel listener is passive).
  useEffect(() => {
    const el = canvasRef.current;
    if (!el) return;
    const stop = (e: WheelEvent) => e.preventDefault();
    el.addEventListener("wheel", stop, { passive: false });
    return () => el.removeEventListener("wheel", stop);
  }, []);

  const scale = Math.min(size.w, size.h) * 0.41 * zoom;
  const toScreen = useCallback((p: Point) => ({ x: size.w / 2 + pan.x + p.x * scale, y: size.h / 2 + pan.y + p.y * scale }), [size, pan, scale]);

  const nodeById = useMemo(() => new Map(view.nodes.map((n) => [n.id, n])), [view.nodes]);
  const active = hover?.kind === "node" ? hover.node.id : selectedNode;
  const activeEdge = hover?.kind === "edge" ? hover.edge.id : selectedEdge;
  const neighbours = useMemo(() => {
    const s = new Set<string>();
    if (active) {
      s.add(active);
      for (const e of view.edges) {
        if (e.source === active) s.add(e.target);
        if (e.target === active) s.add(e.source);
      }
    }
    const ae = activeEdge ? view.edges.find((e) => e.id === activeEdge) : undefined;
    if (ae) {
      s.add(ae.source);
      s.add(ae.target);
    }
    return s;
  }, [active, activeEdge, view.edges]);
  const dimming = neighbours.size > 0;

  // Draw.
  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    const dpr = window.devicePixelRatio || 1;
    canvas.width = size.w * dpr;
    canvas.height = size.h * dpr;
    const ctx = canvas.getContext("2d");
    if (!ctx) return;
    ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
    ctx.clearRect(0, 0, size.w, size.h);
    const pos = shown.current;
    const c = toScreen({ x: 0, y: 0 });

    // Guide rings and type sectors.
    ctx.lineWidth = 1;
    const rings = layout.rings.length ? layout.rings : [0.35, 0.7, 1.0];
    for (const r of [...rings, (rings[rings.length - 1] ?? 1) + 0.12]) {
      ctx.strokeStyle = theme.ring;
      ctx.beginPath();
      ctx.arc(c.x, c.y, r * scale, 0, Math.PI * 2);
      ctx.stroke();
    }
    const outer = ((rings[rings.length - 1] ?? 1) + 0.17) * scale;
    ctx.font = "600 10px 'IBM Plex Sans', system-ui, sans-serif";
    ctx.textBaseline = "middle";
    for (const s of layout.sectors) {
      const color = theme.type[s.type];
      ctx.strokeStyle = withAlpha(color, 0.35);
      ctx.lineWidth = 2;
      ctx.beginPath();
      ctx.arc(c.x, c.y, outer, s.start + 0.02, s.end - 0.02);
      ctx.stroke();
      const mid = (s.start + s.end) / 2;
      const lx = c.x + Math.cos(mid) * (outer + 14);
      const ly = c.y + Math.sin(mid) * (outer + 14);
      // Sector names stay inside the canvas.
      const text = `${NODE_TYPE_LABEL[s.type].many.toUpperCase()} · ${s.count}`;
      const tw = ctx.measureText(text).width;
      const align = Math.cos(mid) > 0.2 ? "left" : Math.cos(mid) < -0.2 ? "right" : "center";
      const left = align === "left" ? lx : align === "right" ? lx - tw : lx - tw / 2;
      const x0 = Math.max(6, Math.min(size.w - 6 - tw, left));
      ctx.fillStyle = withAlpha(color, 0.9);
      ctx.textAlign = "left";
      ctx.fillText(text, x0, Math.max(10, Math.min(size.h - 10, ly)));
    }

    // Edges.
    for (const e of view.edges) {
      const a = pos.get(e.source);
      const b = pos.get(e.target);
      if (!a || !b) continue;
      const pa = toScreen(a);
      const pb = toScreen(b);
      const on = activeEdge === e.id || (active && (e.source === active || e.target === active));
      const otherType = nodeById.get(view.center === e.source ? e.target : e.source)?.type ?? "technique";
      const base = 0.1 + e.confidence * 0.3;
      const alpha = dimming ? (on ? 0.9 : 0.035) : base;
      ctx.strokeStyle = withAlpha(theme.type[otherType], alpha);
      ctx.lineWidth = (e.basis === "stated" ? 1.6 : 0.8) * (on ? 1.6 : 1) + Math.min(2, Math.log2(e.weight) * 0.4);
      ctx.beginPath();
      if (view.mode === "focus" && e.source !== view.center && e.target !== view.center) {
        // Links between two non-centre entities curve toward the centre, like the reference graph.
        const mx = (pa.x + pb.x) / 2;
        const my = (pa.y + pb.y) / 2;
        ctx.moveTo(pa.x, pa.y);
        ctx.quadraticCurveTo(lerp(mx, c.x, 0.35), lerp(my, c.y, 0.35), pb.x, pb.y);
      } else {
        ctx.moveTo(pa.x, pa.y);
        ctx.lineTo(pb.x, pb.y);
      }
      ctx.stroke();
    }

    // Nodes.
    const ordered = [...view.nodes].sort((x, y) => x.reportCount - y.reportCount);
    for (const n of ordered) {
      const p = pos.get(n.id);
      if (!p) continue;
      const s = toScreen(p);
      const isCenter = n.id === view.center;
      const r = nodeRadius(n, isCenter);
      const color = theme.type[n.type];
      const faded = dimming && !neighbours.has(n.id);
      if (isCenter || n.id === selectedNode) {
        const g = ctx.createRadialGradient(s.x, s.y, r * 0.5, s.x, s.y, r * 3);
        g.addColorStop(0, withAlpha(color, 0.35));
        g.addColorStop(1, withAlpha(color, 0));
        ctx.fillStyle = g;
        ctx.beginPath();
        ctx.arc(s.x, s.y, r * 3, 0, Math.PI * 2);
        ctx.fill();
      }
      ctx.fillStyle = withAlpha(color, faded ? 0.15 : 0.9);
      ctx.beginPath();
      ctx.arc(s.x, s.y, r, 0, Math.PI * 2);
      ctx.fill();
      ctx.lineWidth = n.id === selectedNode ? 2.5 : 1;
      ctx.strokeStyle = n.id === selectedNode ? theme.text : withAlpha(theme.dark ? "#000000" : "#ffffff", faded ? 0.1 : 0.55);
      ctx.stroke();
    }

    // Labels: centre, selection and its neighbours, big entities, and everything when zoomed in;
    // a label that would overlap one already drawn is skipped.
    const placed: Array<{ x: number; y: number; w: number; h: number }> = [];
    const wants = ordered
      .filter((n) => n.id === view.center || neighbours.has(n.id) || (!dimming && (nodeRadius(n, false) >= 7.5 || zoom >= 1.8 || view.nodes.length <= 40)))
      .sort((x, y) => Number(y.id === view.center) - Number(x.id === view.center) || Number(neighbours.has(y.id)) - Number(neighbours.has(x.id)) || y.reportCount - x.reportCount);
    ctx.textAlign = "left";
    for (const n of wants) {
      const p = pos.get(n.id);
      if (!p) continue;
      const s = toScreen(p);
      const isCenter = n.id === view.center;
      const r = nodeRadius(n, isCenter);
      ctx.font = `${isCenter || n.id === active ? 600 : 500} ${isCenter ? 13 : 11}px 'IBM Plex Sans', system-ui, sans-serif`;
      const text = n.label.length > 34 ? `${n.label.slice(0, 33)}…` : n.label;
      const w = ctx.measureText(text).width + 8;
      const h = isCenter ? 19 : 16;
      const box = { x: s.x + r + 3, y: s.y - h / 2, w, h };
      if (box.x + w > size.w - 4) box.x = s.x - r - 3 - w;
      if (placed.some((q) => box.x < q.x + q.w && box.x + box.w > q.x && box.y < q.y + q.h && box.y + box.h > q.y)) continue;
      placed.push(box);
      ctx.fillStyle = theme.labelBg;
      ctx.beginPath();
      ctx.roundRect(box.x, box.y, box.w, box.h, 4);
      ctx.fill();
      ctx.fillStyle = theme.text;
      ctx.fillText(text, box.x + 4, s.y + 0.5);
    }
  }, [frame, size, scale, pan, view, layout, theme, selectedNode, neighbours, dimming, active, activeEdge, nodeById, toScreen, zoom]);

  // Hit testing.
  const hitTest = useCallback(
    (x: number, y: number): Hover => {
      let best: GraphNode | null = null;
      let bestD = Infinity;
      for (const n of view.nodes) {
        const p = shown.current.get(n.id);
        if (!p) continue;
        const s = toScreen(p);
        const d = Math.hypot(s.x - x, s.y - y);
        if (d <= nodeRadius(n, n.id === view.center) + 5 && d < bestD) {
          best = n;
          bestD = d;
        }
      }
      if (best) return { kind: "node", node: best };
      let edge: GraphEdge | null = null;
      let edgeD = 5;
      for (const e of view.edges) {
        const a = shown.current.get(e.source);
        const b = shown.current.get(e.target);
        if (!a || !b) continue;
        if (view.mode === "focus" && e.source !== view.center && e.target !== view.center) continue;
        const pa = toScreen(a);
        const pb = toScreen(b);
        const dx = pb.x - pa.x;
        const dy = pb.y - pa.y;
        const len2 = dx * dx + dy * dy || 1;
        const t = Math.max(0, Math.min(1, ((x - pa.x) * dx + (y - pa.y) * dy) / len2));
        const d = Math.hypot(pa.x + t * dx - x, pa.y + t * dy - y);
        if (d < edgeD) {
          edge = e;
          edgeD = d;
        }
      }
      return edge ? { kind: "edge", edge } : null;
    },
    [view, toScreen],
  );

  const local = (ev: { clientX: number; clientY: number }) => {
    const r = canvasRef.current!.getBoundingClientRect();
    return { x: ev.clientX - r.left, y: ev.clientY - r.top };
  };

  const zoomBy = (f: number, at?: { x: number; y: number }) => {
    const next = Math.max(0.4, Math.min(6, zoom * f));
    const k = next / zoom;
    const ax = (at?.x ?? size.w / 2) - size.w / 2;
    const ay = (at?.y ?? size.h / 2) - size.h / 2;
    setPan((p) => ({ x: ax - (ax - p.x) * k, y: ay - (ay - p.y) * k }));
    setZoom(next);
  };

  const label = (n: GraphNode) => nodeById.get(n.id)?.label ?? n.id;

  return (
    <div ref={wrapRef} className={cn("relative overflow-hidden", className)} style={{ backgroundColor: theme.bg }}>
      <canvas
        ref={canvasRef}
        role="img"
        aria-label={`Intelligence graph: ${view.nodes.length} entities, ${view.edges.length} links`}
        style={{ width: size.w, height: size.h, cursor: hover ? "pointer" : drag.current ? "grabbing" : "grab", touchAction: "none" }}
        onPointerDown={(ev) => {
          (ev.target as HTMLElement).setPointerCapture(ev.pointerId);
          drag.current = { x: ev.clientX, y: ev.clientY, px: pan.x, py: pan.y, moved: false };
        }}
        onPointerMove={(ev) => {
          const p = local(ev);
          setMouse(p);
          const d = drag.current;
          if (d) {
            const dx = ev.clientX - d.x;
            const dy = ev.clientY - d.y;
            if (Math.abs(dx) + Math.abs(dy) > 3) d.moved = true;
            if (d.moved) {
              setPan({ x: d.px + dx, y: d.py + dy });
              return;
            }
          }
          setHover(hitTest(p.x, p.y));
        }}
        onPointerUp={(ev) => {
          const d = drag.current;
          drag.current = null;
          if (d?.moved) return;
          const h = hitTest(...(Object.values(local(ev)) as [number, number]));
          if (h?.kind === "node") {
            onSelectNode(h.node.id);
            onSelectEdge(null);
          } else if (h?.kind === "edge") {
            onSelectEdge(h.edge.id);
          } else {
            onSelectNode(null);
            onSelectEdge(null);
          }
        }}
        onPointerLeave={() => setHover(null)}
        onDoubleClick={(ev) => {
          const p = local(ev);
          const h = hitTest(p.x, p.y);
          if (h?.kind === "node") onFocus(h.node.id);
        }}
        onWheel={(ev) => zoomBy(ev.deltaY < 0 ? 1.15 : 1 / 1.15, local(ev))}
      />

      {hover && !drag.current?.moved && (
        <div
          className="pointer-events-none absolute z-10 max-w-[280px] rounded-lg border px-3 py-2 text-xs shadow-xl"
          style={{
            left: Math.min(mouse.x + 14, size.w - 290),
            top: Math.min(mouse.y + 14, size.h - 110),
            backgroundColor: theme.dark ? "rgba(18,18,21,0.96)" : "rgba(255,255,255,0.97)",
            borderColor: theme.dark ? "#2a2a30" : "#e3e6eb",
            color: theme.text,
          }}
        >
          {hover.kind === "node" ? (
            <>
              <div className="flex items-center gap-1.5 font-medium" style={{ color: theme.type[hover.node.type] }}>
                <span className="inline-block size-2 rounded-full" style={{ backgroundColor: theme.type[hover.node.type] }} />
                {NODE_TYPE_LABEL[hover.node.type].one}
                {hover.node.attackId && <span style={{ color: theme.muted }}>· {hover.node.attackId}</span>}
              </div>
              <div className="mt-0.5 text-[13px] font-semibold">{hover.node.label}</div>
              <div className="mt-1" style={{ color: theme.muted }}>
                {hover.node.reportCount} report{hover.node.reportCount === 1 ? "" : "s"} · {hover.node.degree} link{hover.node.degree === 1 ? "" : "s"}
                {hover.node.lastSeen ? ` · last ${hover.node.lastSeen.slice(0, 10)}` : ""}
              </div>
              <div className="mt-1.5" style={{ color: theme.muted }}>
                Click for details · double-click to centre
              </div>
            </>
          ) : (
            <>
              <div className="font-semibold">
                {label(nodeById.get(hover.edge.source) ?? ({ id: hover.edge.source } as GraphNode))}{" "}
                <span style={{ color: theme.muted }}>{PREDICATE_LABEL[hover.edge.predicate]}</span>{" "}
                {label(nodeById.get(hover.edge.target) ?? ({ id: hover.edge.target } as GraphNode))}
              </div>
              <div className="mt-1" style={{ color: theme.muted }}>
                {hover.edge.basis === "stated" ? "Stated in a report" : "Reported together"} · {hover.edge.weight} report{hover.edge.weight === 1 ? "" : "s"} · confidence{" "}
                {Math.round(hover.edge.confidence * 100)}%
              </div>
            </>
          )}
        </div>
      )}

      <div className="absolute bottom-3 right-3 flex flex-col overflow-hidden rounded-lg border border-border bg-bg-elevated shadow-sm">
        <button type="button" aria-label="Zoom in" onClick={() => zoomBy(1.3)} className="inline-flex size-8 items-center justify-center text-muted hover:bg-bg-subtle hover:text-fg">
          <Plus className="size-4" />
        </button>
        <button type="button" aria-label="Zoom out" onClick={() => zoomBy(1 / 1.3)} className="inline-flex size-8 items-center justify-center border-t border-border text-muted hover:bg-bg-subtle hover:text-fg">
          <Minus className="size-4" />
        </button>
        <button
          type="button"
          aria-label="Reset view"
          onClick={() => {
            setZoom(1);
            setPan({ x: 0, y: 0 });
          }}
          className="inline-flex size-8 items-center justify-center border-t border-border text-muted hover:bg-bg-subtle hover:text-fg"
        >
          <Maximize2 className="size-3.5" />
        </button>
      </div>
    </div>
  );
}
