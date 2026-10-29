import { useEffect, useMemo, useRef, useState } from "react";
import * as THREE from "three";
import { OrbitControls } from "three/examples/jsm/controls/OrbitControls.js";
import { Maximize2, Minus, Pause, Play, Plus } from "lucide-react";
import type { GraphView } from "@/lib/aie/graph/analyze";
import type { GraphLayout3, Point3 } from "@/lib/aie/graph/layout";
import { NODE_TYPE_LABEL, PREDICATE_LABEL, type GraphEdge, type GraphNode } from "@/lib/aie/graph/types";
import { cn } from "@/lib/cn";
import type { GraphTheme } from "./graph-style";

type Props = {
  view: GraphView;
  layout: GraphLayout3;
  theme: GraphTheme;
  selectedNode: string | null;
  selectedEdge: string | null;
  onSelectNode: (id: string | null) => void;
  onSelectEdge: (id: string | null) => void;
  onFocus: (id: string) => void;
  className?: string;
};

/** World units per layout unit. */
const WORLD = 100;
const MAX_LABELS = 36;

const nodeSize = (n: GraphNode, center: boolean) => (center ? 5.2 : Math.min(4.2, 1.1 + Math.sqrt(n.reportCount) * 0.55));

function glowTexture(): THREE.Texture {
  const c = document.createElement("canvas");
  c.width = c.height = 64;
  const g = c.getContext("2d")!;
  const grad = g.createRadialGradient(32, 32, 0, 32, 32, 32);
  grad.addColorStop(0, "rgba(255,255,255,1)");
  grad.addColorStop(0.25, "rgba(255,255,255,0.45)");
  grad.addColorStop(1, "rgba(255,255,255,0)");
  g.fillStyle = grad;
  g.fillRect(0, 0, 64, 64);
  const t = new THREE.CanvasTexture(c);
  t.colorSpace = THREE.SRGBColorSpace;
  return t;
}

type Scene3 = {
  renderer: THREE.WebGLRenderer;
  scene: THREE.Scene;
  camera: THREE.PerspectiveCamera;
  controls: OrbitControls;
  nodes: THREE.InstancedMesh | null;
  halos: THREE.Points | null;
  lines: THREE.LineSegments | null;
  hot: THREE.LineSegments | null;
  stars: THREE.Points;
  glow: THREE.Texture;
  raycaster: THREE.Raycaster;
};

/**
 * WebGL 3D drawing of a graph view: drag to rotate, scroll to zoom, right-drag (or two fingers) to
 * pan, hover for a summary, click to select, double-click to put an entity in the centre. Slowly
 * turns on its own until touched (pause button to stop).
 */
export function GraphCanvas3D({ view, layout, theme, selectedNode, selectedEdge, onSelectNode, onSelectEdge, onFocus, className }: Props) {
  const wrapRef = useRef<HTMLDivElement>(null);
  const labelsRef = useRef<HTMLDivElement>(null);
  const s3 = useRef<Scene3 | null>(null);
  const [hover, setHover] = useState<GraphNode | null>(null);
  const [mouse, setMouse] = useState({ x: 0, y: 0 });
  const [spin, setSpin] = useState(true);
  const pos = useRef(new Map<string, THREE.Vector3>());
  const target = useRef(new Map<string, THREE.Vector3>());
  const order = useRef<GraphNode[]>([]);
  const typeOf = useRef(new Map<string, GraphNode["type"]>());
  const dirty = useRef(true);
  const stateRef = useRef({ view, theme, selectedNode, selectedEdge, hover: null as string | null });
  stateRef.current = { view, theme, selectedNode, selectedEdge, hover: hover?.id ?? null };

  const active = hover?.id ?? selectedNode;
  const neighbours = useMemo(() => {
    const s = new Set<string>();
    if (active) {
      s.add(active);
      for (const e of view.edges) {
        if (e.source === active) s.add(e.target);
        if (e.target === active) s.add(e.source);
      }
    }
    const se = selectedEdge ? view.edges.find((e) => e.id === selectedEdge) : undefined;
    if (se) {
      s.add(se.source);
      s.add(se.target);
    }
    return s;
  }, [active, selectedEdge, view.edges]);
  const neighboursRef = useRef(neighbours);
  neighboursRef.current = neighbours;

  // Scene setup (once).
  useEffect(() => {
    const wrap = wrapRef.current!;
    const renderer = new THREE.WebGLRenderer({ antialias: true, alpha: true, powerPreference: "high-performance" });
    renderer.setPixelRatio(Math.min(2, window.devicePixelRatio || 1));
    renderer.setSize(wrap.clientWidth, wrap.clientHeight);
    renderer.domElement.style.display = "block";
    renderer.domElement.style.touchAction = "none";
    wrap.prepend(renderer.domElement);
    const scene = new THREE.Scene();
    const camera = new THREE.PerspectiveCamera(50, wrap.clientWidth / Math.max(1, wrap.clientHeight), 1, 5000);
    camera.position.set(0, 40, 260);
    const controls = new OrbitControls(camera, renderer.domElement);
    controls.enableDamping = true;
    controls.dampingFactor = 0.08;
    controls.rotateSpeed = 0.7;
    controls.zoomSpeed = 0.9;
    controls.minDistance = 25;
    controls.maxDistance = 900;
    controls.autoRotate = true;
    controls.autoRotateSpeed = 0.5;
    scene.add(new THREE.AmbientLight(0xffffff, 0.75));
    const key = new THREE.DirectionalLight(0xffffff, 1.4);
    key.position.set(120, 200, 160);
    scene.add(key);
    // Background stars for depth.
    const starGeo = new THREE.BufferGeometry();
    const sp = new Float32Array(900 * 3);
    let seed = 7;
    const r = () => ((seed = (seed * 16807) % 2147483647) / 2147483647) * 2 - 1;
    for (let i = 0; i < 900; i++) {
      const v = new THREE.Vector3(r(), r(), r()).normalize().multiplyScalar(700 + Math.abs(r()) * 900);
      sp.set([v.x, v.y, v.z], i * 3);
    }
    starGeo.setAttribute("position", new THREE.BufferAttribute(sp, 3));
    const stars = new THREE.Points(starGeo, new THREE.PointsMaterial({ size: 1.6, sizeAttenuation: false, transparent: true, opacity: 0.35, color: 0xffffff }));
    scene.add(stars);
    s3.current = { renderer, scene, camera, controls, nodes: null, halos: null, lines: null, hot: null, stars, glow: glowTexture(), raycaster: new THREE.Raycaster() };

    const stopSpin = () => {
      controls.autoRotate = false;
      setSpin(false);
    };
    renderer.domElement.addEventListener("pointerdown", stopSpin);
    const ro = new ResizeObserver(() => {
      const w = wrap.clientWidth;
      const h = Math.max(1, wrap.clientHeight);
      renderer.setSize(w, h);
      camera.aspect = w / h;
      camera.updateProjectionMatrix();
    });
    ro.observe(wrap);

    // Render loop: ease nodes to their targets, update geometry, place labels.
    let raf = 0;
    const tmp = new THREE.Object3D();
    const color = new THREE.Color();
    const loop = () => {
      raf = requestAnimationFrame(loop);
      const st = s3.current;
      if (!st) return;
      let moving = false;
      for (const [id, t] of target.current) {
        const p = pos.current.get(id);
        if (!p) {
          pos.current.set(id, t.clone().multiplyScalar(0.05));
          moving = true;
          continue;
        }
        if (p.distanceToSquared(t) > 0.0004) {
          p.lerp(t, 0.12);
          moving = true;
        }
      }
      const { view: v, theme: th, selectedNode: sel } = stateRef.current;
      const nb = neighboursRef.current;
      const dim = nb.size > 0;
      if (st.nodes && (moving || dirty.current)) {
        order.current.forEach((n, i) => {
          const p = pos.current.get(n.id);
          if (!p) return;
          const size = nodeSize(n, n.id === v.center) * (n.id === sel ? 1.35 : 1);
          tmp.position.copy(p);
          tmp.scale.setScalar(size);
          tmp.updateMatrix();
          st.nodes!.setMatrixAt(i, tmp.matrix);
          color.set(th.type[n.type]);
          if (dim && !nb.has(n.id)) color.lerp(new THREE.Color(th.dark ? 0x0a0a0c : 0xffffff), 0.82);
          st.nodes!.setColorAt(i, color);
        });
        st.nodes.instanceMatrix.needsUpdate = true;
        if (st.nodes.instanceColor) st.nodes.instanceColor.needsUpdate = true;
        // Halos: centre, selection and its neighbours.
        if (st.halos) {
          const hp = st.halos.geometry.getAttribute("position") as THREE.BufferAttribute;
          const hc = st.halos.geometry.getAttribute("color") as THREE.BufferAttribute;
          order.current.forEach((n, i) => {
            const p = pos.current.get(n.id)!;
            hp.setXYZ(i, p.x, p.y, p.z);
            color.set(th.type[n.type]);
            const lit = n.id === v.center || n.id === sel || (dim ? nb.has(n.id) : n.reportCount >= 4);
            const k = lit ? (n.id === v.center || n.id === sel ? 1 : 0.55) : dim ? 0 : 0.18;
            hc.setXYZ(i, color.r * k, color.g * k, color.b * k);
          });
          hp.needsUpdate = true;
          hc.needsUpdate = true;
        }
        // Lines.
        const write = (ls: THREE.LineSegments | null, edges: GraphEdge[], bright: boolean) => {
          if (!ls) return;
          const lp = ls.geometry.getAttribute("position") as THREE.BufferAttribute;
          const lc = ls.geometry.getAttribute("color") as THREE.BufferAttribute;
          let k = 0;
          for (const e of edges) {
            const a = pos.current.get(e.source);
            const b = pos.current.get(e.target);
            if (!a || !b) continue;
            color.set(th.type[typeOf.current.get(e.source === v.center ? e.target : e.source) ?? "technique"]);
            const on = !dim || (sel ? e.source === sel || e.target === sel : false) || nb.has(e.source) && nb.has(e.target) && (stateRef.current.hover === e.source || stateRef.current.hover === e.target);
            const alpha = bright ? 0.95 : dim ? (on ? 0.25 : 0.03) : 0.12 + e.confidence * 0.3 + (e.basis === "stated" ? 0.15 : 0);
            const m = th.dark ? alpha : alpha * 0.9;
            lp.setXYZ(k, a.x, a.y, a.z);
            lp.setXYZ(k + 1, b.x, b.y, b.z);
            if (th.dark) {
              lc.setXYZ(k, color.r * m, color.g * m, color.b * m);
              lc.setXYZ(k + 1, color.r * m, color.g * m, color.b * m);
            } else {
              const mix = (c: number) => 1 - (1 - c) * m;
              lc.setXYZ(k, mix(color.r), mix(color.g), mix(color.b));
              lc.setXYZ(k + 1, mix(color.r), mix(color.g), mix(color.b));
            }
            k += 2;
          }
          ls.geometry.setDrawRange(0, k);
          lp.needsUpdate = true;
          lc.needsUpdate = true;
        };
        write(st.lines, v.edges, false);
        const hotEdges = v.edges.filter((e) => e.id === stateRef.current.selectedEdge || (stateRef.current.hover ?? sel) === e.source || (stateRef.current.hover ?? sel) === e.target);
        write(st.hot, hotEdges, true);
        dirty.current = false;
      }
      st.controls.update();
      st.renderer.render(st.scene, st.camera);

      // Labels (HTML, so text stays crisp), with simple overlap avoidance.
      const box = labelsRef.current;
      if (box) {
        const w = st.renderer.domElement.clientWidth;
        const h = st.renderer.domElement.clientHeight;
        const want = [...v.nodes]
          .filter((n) => n.id === v.center || n.id === sel || nb.has(n.id) || (!dim && n.reportCount >= 2))
          .sort((a, b) => Number(b.id === v.center) - Number(a.id === v.center) || Number(nb.has(b.id)) - Number(nb.has(a.id)) || b.reportCount - a.reportCount)
          .slice(0, MAX_LABELS * 2);
        const placed: Array<[number, number, number, number]> = [];
        let used = 0;
        const v3 = new THREE.Vector3();
        for (const n of want) {
          if (used >= MAX_LABELS) break;
          const p = pos.current.get(n.id);
          if (!p) continue;
          v3.copy(p).project(st.camera);
          if (v3.z > 1 || v3.z < -1) continue;
          const sx = (v3.x * 0.5 + 0.5) * w;
          const sy = (-v3.y * 0.5 + 0.5) * h;
          if (sx < 0 || sy < 0 || sx > w || sy > h) continue;
          const text = n.label.length > 30 ? `${n.label.slice(0, 29)}…` : n.label;
          const lw = text.length * 6.4 + 10;
          const rect: [number, number, number, number] = [sx + 8, sy - 9, lw, 18];
          if (placed.some((q) => rect[0] < q[0] + q[2] && rect[0] + rect[2] > q[0] && rect[1] < q[1] + q[3] && rect[1] + rect[3] > q[1])) continue;
          placed.push(rect);
          let el = box.children[used] as HTMLDivElement | undefined;
          if (!el) {
            el = document.createElement("div");
            el.className = "graph3d-label";
            box.appendChild(el);
          }
          el.textContent = text;
          el.style.transform = `translate(${rect[0]}px, ${rect[1]}px)`;
          el.style.display = "block";
          el.style.fontWeight = n.id === v.center || n.id === sel ? "600" : "500";
          el.style.color = th.text;
          el.style.background = th.labelBg;
          el.style.borderLeft = `2px solid ${th.type[n.type]}`;
          el.style.opacity = String(Math.max(0.55, 1 - (v3.z - 0.9) * 6));
          used++;
        }
        for (let i = used; i < box.children.length; i++) (box.children[i] as HTMLDivElement).style.display = "none";
      }
    };
    loop();

    return () => {
      cancelAnimationFrame(raf);
      ro.disconnect();
      renderer.domElement.removeEventListener("pointerdown", stopSpin);
      controls.dispose();
      scene.traverse((o) => {
        const m = o as THREE.Mesh;
        m.geometry?.dispose?.();
        const mat = m.material as THREE.Material | THREE.Material[] | undefined;
        if (Array.isArray(mat)) mat.forEach((x) => x.dispose());
        else mat?.dispose?.();
      });
      s3.current?.glow.dispose();
      renderer.dispose();
      renderer.domElement.remove();
      s3.current = null;
    };
  }, []);

  // Theme: background and star colour.
  useEffect(() => {
    const st = s3.current;
    if (!st) return;
    (st.stars.material as THREE.PointsMaterial).color.set(theme.dark ? 0xffffff : 0x64748b);
    (st.stars.material as THREE.PointsMaterial).opacity = theme.dark ? 0.35 : 0.25;
    dirty.current = true;
  }, [theme]);

  // Rebuild geometry when the set of nodes / edges changes; positions animate to the new layout.
  useEffect(() => {
    const st = s3.current;
    if (!st) return;
    for (const obj of [st.nodes, st.halos, st.lines, st.hot]) {
      if (!obj) continue;
      st.scene.remove(obj);
      obj.geometry.dispose();
      (obj.material as THREE.Material).dispose();
    }
    order.current = view.nodes;
    typeOf.current = new Map(view.nodes.map((n) => [n.id, n.type]));
    target.current = new Map(view.nodes.map((n) => [n.id, new THREE.Vector3(...xyz(layout.pos.get(n.id)))]));
    for (const id of [...pos.current.keys()]) if (!target.current.has(id)) pos.current.delete(id);

    const geo = new THREE.SphereGeometry(1, 20, 14);
    const mat = new THREE.MeshStandardMaterial({ roughness: 0.45, metalness: 0.1 });
    const nodes = new THREE.InstancedMesh(geo, mat, Math.max(1, view.nodes.length));
    nodes.count = view.nodes.length;
    nodes.instanceColor = new THREE.InstancedBufferAttribute(new Float32Array(Math.max(1, view.nodes.length) * 3), 3);
    st.scene.add(nodes);

    const hg = new THREE.BufferGeometry();
    hg.setAttribute("position", new THREE.BufferAttribute(new Float32Array(view.nodes.length * 3), 3));
    hg.setAttribute("color", new THREE.BufferAttribute(new Float32Array(view.nodes.length * 3), 3));
    const halos = new THREE.Points(
      hg,
      new THREE.PointsMaterial({ size: 26, map: st.glow, vertexColors: true, transparent: true, depthWrite: false, blending: theme.dark ? THREE.AdditiveBlending : THREE.NormalBlending, opacity: theme.dark ? 1 : 0.5 }),
    );
    st.scene.add(halos);

    const mkLines = (count: number, opacity: number) => {
      const g = new THREE.BufferGeometry();
      g.setAttribute("position", new THREE.BufferAttribute(new Float32Array(count * 6), 3));
      g.setAttribute("color", new THREE.BufferAttribute(new Float32Array(count * 6), 3));
      return new THREE.LineSegments(
        g,
        new THREE.LineBasicMaterial({ vertexColors: true, transparent: true, opacity, depthWrite: false, blending: theme.dark ? THREE.AdditiveBlending : THREE.NormalBlending }),
      );
    };
    const lines = mkLines(view.edges.length, 1);
    const hot = mkLines(view.edges.length, 1);
    st.scene.add(lines);
    st.scene.add(hot);
    Object.assign(st, { nodes, halos, lines, hot });
    dirty.current = true;
  }, [view, layout, theme.dark]);

  useEffect(() => {
    dirty.current = true;
  }, [selectedNode, selectedEdge, hover, neighbours]);

  // Reset the camera when the centre or mode changes.
  useEffect(() => {
    const st = s3.current;
    if (!st) return;
    st.controls.target.set(0, 0, 0);
    st.camera.position.set(0, 40, view.mode === "focus" ? 310 : 240);
  }, [view.center, view.mode]);

  const pick = (ev: { clientX: number; clientY: number }): GraphNode | null => {
    const st = s3.current;
    if (!st?.nodes) return null;
    const rect = st.renderer.domElement.getBoundingClientRect();
    const ndc = new THREE.Vector2(((ev.clientX - rect.left) / rect.width) * 2 - 1, -((ev.clientY - rect.top) / rect.height) * 2 + 1);
    st.raycaster.setFromCamera(ndc, st.camera);
    const hit = st.raycaster.intersectObject(st.nodes, false)[0];
    if (hit?.instanceId === undefined) return null;
    return order.current[hit.instanceId] ?? null;
  };

  const down = useRef<{ x: number; y: number } | null>(null);
  const zoomBy = (f: number) => {
    const st = s3.current;
    if (!st) return;
    const dir = st.camera.position.clone().sub(st.controls.target);
    st.camera.position.copy(st.controls.target.clone().add(dir.multiplyScalar(f)));
  };

  return (
    <div
      ref={wrapRef}
      className={cn("relative overflow-hidden", className)}
      style={{ background: theme.dark ? "radial-gradient(ellipse at center, #111118 0%, #050507 70%)" : "radial-gradient(ellipse at center, #ffffff 0%, #eef1f5 75%)" }}
      onPointerDown={(e) => (down.current = { x: e.clientX, y: e.clientY })}
      onPointerMove={(e) => {
        const r = wrapRef.current!.getBoundingClientRect();
        setMouse({ x: e.clientX - r.left, y: e.clientY - r.top });
        if (e.buttons) return;
        const n = pick(e);
        if ((n?.id ?? null) !== (hover?.id ?? null)) setHover(n);
        if (wrapRef.current) wrapRef.current.style.cursor = n ? "pointer" : "grab";
      }}
      onPointerLeave={() => setHover(null)}
      onPointerUp={(e) => {
        const d = down.current;
        down.current = null;
        if (!d || Math.hypot(e.clientX - d.x, e.clientY - d.y) > 4) return;
        const n = pick(e);
        onSelectNode(n?.id ?? null);
        onSelectEdge(null);
      }}
      onDoubleClick={(e) => {
        const n = pick(e);
        if (n) onFocus(n.id);
      }}
    >
      <div ref={labelsRef} className="pointer-events-none absolute inset-0 overflow-hidden [&_.graph3d-label]:absolute [&_.graph3d-label]:left-0 [&_.graph3d-label]:top-0 [&_.graph3d-label]:whitespace-nowrap [&_.graph3d-label]:rounded [&_.graph3d-label]:px-1.5 [&_.graph3d-label]:py-px [&_.graph3d-label]:text-[11px]" />

      {hover && (
        <div
          className="pointer-events-none absolute z-10 max-w-[280px] rounded-lg border px-3 py-2 text-xs shadow-xl"
          style={{
            left: Math.min(mouse.x + 14, (wrapRef.current?.clientWidth ?? 800) - 290),
            top: Math.min(mouse.y + 14, (wrapRef.current?.clientHeight ?? 600) - 110),
            backgroundColor: theme.dark ? "rgba(18,18,21,0.96)" : "rgba(255,255,255,0.97)",
            borderColor: theme.dark ? "#2a2a30" : "#e3e6eb",
            color: theme.text,
          }}
        >
          {hover && (
            <>
              <div className="flex items-center gap-1.5 font-medium" style={{ color: theme.type[hover.type] }}>
                <span className="inline-block size-2 rounded-full" style={{ backgroundColor: theme.type[hover.type] }} />
                {NODE_TYPE_LABEL[hover.type].one}
                {hover.attackId && <span style={{ color: theme.muted }}>· {hover.attackId}</span>}
              </div>
              <div className="mt-0.5 text-[13px] font-semibold">{hover.label}</div>
              <div className="mt-1" style={{ color: theme.muted }}>
                {hover.reportCount} report{hover.reportCount === 1 ? "" : "s"} · {hover.degree} link{hover.degree === 1 ? "" : "s"}
              </div>
              {(() => {
                const e = view.edges.find((x) => view.center && ((x.source === view.center && x.target === hover.id) || (x.target === view.center && x.source === hover.id)));
                return e ? (
                  <div className="mt-1" style={{ color: theme.muted }}>
                    {PREDICATE_LABEL[e.predicate]} · {e.basis === "stated" ? "stated" : "reported together"} · {Math.round(e.confidence * 100)}%
                  </div>
                ) : null;
              })()}
              <div className="mt-1.5" style={{ color: theme.muted }}>
                Click for details · double-click to centre
              </div>
            </>
          )}
        </div>
      )}

      <div className="absolute bottom-3 right-3 flex flex-col overflow-hidden rounded-lg border border-border bg-bg-elevated shadow-sm">
        <button type="button" aria-label="Zoom in" onClick={() => zoomBy(0.75)} className="inline-flex size-8 items-center justify-center text-muted hover:bg-bg-subtle hover:text-fg">
          <Plus className="size-4" />
        </button>
        <button type="button" aria-label="Zoom out" onClick={() => zoomBy(1.33)} className="inline-flex size-8 items-center justify-center border-t border-border text-muted hover:bg-bg-subtle hover:text-fg">
          <Minus className="size-4" />
        </button>
        <button
          type="button"
          aria-label={spin ? "Stop turning" : "Turn slowly"}
          onClick={() => {
            const st = s3.current;
            if (!st) return;
            st.controls.autoRotate = !spin;
            setSpin(!spin);
          }}
          className="inline-flex size-8 items-center justify-center border-t border-border text-muted hover:bg-bg-subtle hover:text-fg"
        >
          {spin ? <Pause className="size-3.5" /> : <Play className="size-3.5" />}
        </button>
        <button
          type="button"
          aria-label="Reset view"
          onClick={() => {
            const st = s3.current;
            if (!st) return;
            st.controls.target.set(0, 0, 0);
            st.camera.position.set(0, 40, view.mode === "focus" ? 310 : 240);
          }}
          className="inline-flex size-8 items-center justify-center border-t border-border text-muted hover:bg-bg-subtle hover:text-fg"
        >
          <Maximize2 className="size-3.5" />
        </button>
      </div>
      <p className="pointer-events-none absolute left-3 top-3 text-[11px]" style={{ color: theme.muted }}>
        Drag to rotate · scroll to zoom · right-drag to pan
      </p>
    </div>
  );
}

function xyz(p: Point3 | undefined): [number, number, number] {
  return p ? [p.x * WORLD, p.y * WORLD, p.z * WORLD] : [0, 0, 0];
}
