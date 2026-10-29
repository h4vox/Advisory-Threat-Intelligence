/**
 * Positions for a graph view (./analyze), in a unit space (the drawing scales it to the canvas).
 * Pure and deterministic: the same view always gets the same picture.
 *
 *   - Focus (radial): the centre entity at (0,0); its links on ring 1 and their links on ring 2.
 *     Each entity type owns an angular sector (sized by how many it has), so actors, malware,
 *     techniques… sit in their own arc and the eye can find them.
 *   - Overview (clustered force): each type pulls its entities toward its own anchor around a
 *     circle; links pull related entities together and every entity pushes the others away.
 */
import type { GraphNodeType } from "./types.ts";
import type { GraphView } from "./analyze.ts";
import { edgeStrength } from "./analyze.ts";

export type Point = { x: number; y: number };
export type Sector = { type: GraphNodeType; start: number; end: number; count: number };
export type GraphLayout = { pos: Map<string, Point>; sectors: Sector[]; rings: number[] };

/** Clockwise order of type sectors: who acts, with what, how, against whom. */
export const TYPE_ORDER: GraphNodeType[] = ["actor", "campaign", "malware", "tool", "indicator", "vulnerability", "platform", "geography", "sector", "technique"];

function sectorsFor(counts: Map<GraphNodeType, number>, start = -Math.PI / 2): Sector[] {
  const types = TYPE_ORDER.filter((t) => (counts.get(t) ?? 0) > 0);
  const total = types.reduce((s, t) => s + Math.sqrt(counts.get(t)!) + 0.6, 0) || 1;
  const out: Sector[] = [];
  let a = start;
  for (const t of types) {
    const span = ((Math.sqrt(counts.get(t)!) + 0.6) / total) * Math.PI * 2;
    out.push({ type: t, start: a, end: a + span, count: counts.get(t)! });
    a += span;
  }
  return out;
}

const R1 = 0.5;
const R2 = 0.9;

export function radialLayout(view: GraphView): GraphLayout {
  const pos = new Map<string, Point>();
  const center = view.center!;
  pos.set(center, { x: 0, y: 0 });
  const strength = new Map<string, number>();
  for (const e of view.edges) {
    if (e.source === center) strength.set(e.target, Math.max(strength.get(e.target) ?? 0, edgeStrength(e)));
    if (e.target === center) strength.set(e.source, Math.max(strength.get(e.source) ?? 0, edgeStrength(e)));
  }
  const ring1 = view.nodes.filter((n) => view.ring?.get(n.id) === 1);
  const counts = new Map<GraphNodeType, number>();
  for (const n of ring1) counts.set(n.type, (counts.get(n.type) ?? 0) + 1);
  const sectors = sectorsFor(counts);
  const angle = new Map<string, number>();
  const dense = ring1.length > 28;
  for (const s of sectors) {
    const members = ring1.filter((n) => n.type === s.type).sort((a, b) => (strength.get(b.id) ?? 0) - (strength.get(a.id) ?? 0));
    const pad = Math.min(0.08, (s.end - s.start) * 0.12);
    const span = s.end - s.start - pad * 2;
    members.forEach((n, i) => {
      const a = s.start + pad + (members.length === 1 ? span / 2 : (span * i) / (members.length - 1));
      // Stronger links sit closer to the centre; crowded rings stagger in two lanes.
      const r = R1 * (dense ? (i % 2 ? 1.12 : 0.9) : 1) - Math.min(0.06, (strength.get(n.id) ?? 0) * 0.01);
      angle.set(n.id, a);
      pos.set(n.id, { x: Math.cos(a) * r, y: Math.sin(a) * r });
    });
  }
  // Ring 2: children fan out around their parent's angle.
  const kids = new Map<string, string[]>();
  for (const n of view.nodes) {
    if (view.ring?.get(n.id) !== 2) continue;
    const p = view.parent?.get(n.id);
    if (p) (kids.get(p) ?? kids.set(p, []).get(p)!).push(n.id);
  }
  const step = ring1.length ? (Math.PI * 2) / ring1.length : Math.PI;
  for (const [p, list] of kids) {
    const base = angle.get(p) ?? 0;
    const spread = Math.min(step * 0.9, 0.5);
    list.forEach((id, i) => {
      const a = base + (list.length === 1 ? 0 : -spread / 2 + (spread * i) / (list.length - 1));
      const r = R2 * (i % 2 ? 1.06 : 0.97);
      pos.set(id, { x: Math.cos(a) * r, y: Math.sin(a) * r });
    });
  }
  return { pos, sectors, rings: kids.size ? [R1, R2] : [R1] };
}

/** Small deterministic PRNG (mulberry32). */
function rng(seed: number) {
  let a = seed >>> 0;
  return () => {
    a = (a + 0x6d2b79f5) >>> 0;
    let t = a;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

export function forceLayout(view: GraphView, iterations = 260): GraphLayout {
  const n = view.nodes.length;
  const counts = new Map<GraphNodeType, number>();
  for (const v of view.nodes) counts.set(v.type, (counts.get(v.type) ?? 0) + 1);
  const sectors = sectorsFor(counts);
  const anchor = new Map<GraphNodeType, Point>();
  for (const s of sectors) {
    const a = (s.start + s.end) / 2;
    anchor.set(s.type, { x: Math.cos(a) * 0.55, y: Math.sin(a) * 0.55 });
  }
  const rand = rng(n * 7919 + view.edges.length);
  const idx = new Map(view.nodes.map((v, i) => [v.id, i]));
  const x = new Float64Array(n);
  const y = new Float64Array(n);
  view.nodes.forEach((v, i) => {
    const a = anchor.get(v.type)!;
    x[i] = a.x + (rand() - 0.5) * 0.3;
    y[i] = a.y + (rand() - 0.5) * 0.3;
  });
  const links = view.edges
    .map((e) => ({ s: idx.get(e.source)!, t: idx.get(e.target)!, w: Math.min(1, 0.25 + Math.log2(1 + e.weight) * 0.25) }))
    .filter((l) => l.s !== undefined && l.t !== undefined);
  const k = 0.9 / Math.sqrt(Math.max(1, n));
  const dx = new Float64Array(n);
  const dy = new Float64Array(n);
  for (let it = 0; it < iterations; it++) {
    const temp = 0.06 * (1 - it / iterations) + 0.004;
    dx.fill(0);
    dy.fill(0);
    for (let i = 0; i < n; i++) {
      for (let j = i + 1; j < n; j++) {
        let ddx = x[i] - x[j];
        let ddy = y[i] - y[j];
        let d2 = ddx * ddx + ddy * ddy;
        if (d2 < 1e-6) {
          ddx = (rand() - 0.5) * 1e-3;
          ddy = (rand() - 0.5) * 1e-3;
          d2 = 1e-6;
        }
        const f = (k * k) / d2;
        dx[i] += ddx * f;
        dy[i] += ddy * f;
        dx[j] -= ddx * f;
        dy[j] -= ddy * f;
      }
    }
    for (const l of links) {
      const ddx = x[l.s] - x[l.t];
      const ddy = y[l.s] - y[l.t];
      const d = Math.sqrt(ddx * ddx + ddy * ddy) || 1e-3;
      const f = ((d * d) / k) * 0.5 * l.w;
      dx[l.s] -= (ddx / d) * f;
      dy[l.s] -= (ddy / d) * f;
      dx[l.t] += (ddx / d) * f;
      dy[l.t] += (ddy / d) * f;
    }
    view.nodes.forEach((v, i) => {
      const a = anchor.get(v.type)!;
      dx[i] += (a.x - x[i]) * 0.9;
      dy[i] += (a.y - y[i]) * 0.9;
      const d = Math.sqrt(dx[i] * dx[i] + dy[i] * dy[i]) || 1;
      const step = Math.min(d, temp);
      x[i] += (dx[i] / d) * step;
      y[i] += (dy[i] / d) * step;
    });
  }
  // Fit into the unit circle.
  let max = 0;
  for (let i = 0; i < n; i++) max = Math.max(max, Math.hypot(x[i], y[i]));
  const scale = max > 0 ? 0.95 / max : 1;
  const pos = new Map<string, Point>();
  view.nodes.forEach((v, i) => pos.set(v.id, { x: x[i] * scale, y: y[i] * scale }));
  return { pos, sectors, rings: [] };
}

// ---------------------------------------------------------------------------
// 3D
// ---------------------------------------------------------------------------

export type Point3 = { x: number; y: number; z: number };
export type GraphLayout3 = { pos: Map<string, Point3>; anchors: Array<{ type: GraphNodeType; at: Point3; count: number }> };

/** Evenly spread directions on a sphere (Fibonacci lattice). */
function sphereDirections(n: number): Point3[] {
  const out: Point3[] = [];
  const golden = Math.PI * (3 - Math.sqrt(5));
  for (let i = 0; i < n; i++) {
    const y = n === 1 ? 0 : 1 - (i / (n - 1)) * 2;
    const r = Math.sqrt(1 - y * y);
    const t = golden * i;
    out.push({ x: Math.cos(t) * r, y, z: Math.sin(t) * r });
  }
  return out;
}

/**
 * 3D positions (unit sphere). Each entity type gets an anchor direction; in focus mode the centre
 * entity is at the origin, its links on a shell around it (grouped by type around their anchor),
 * second-hop entities on an outer shell next to the entity they hang off. Overview mode is a
 * clustered force layout in 3D. Deterministic.
 */
export function layout3d(view: GraphView, iterations = 220): GraphLayout3 {
  const counts = new Map<GraphNodeType, number>();
  for (const v of view.nodes) if (v.id !== view.center) counts.set(v.type, (counts.get(v.type) ?? 0) + 1);
  const types = TYPE_ORDER.filter((t) => counts.has(t));
  const dirs = sphereDirections(Math.max(types.length, 2));
  const anchor = new Map<GraphNodeType, Point3>(types.map((t, i) => [t, dirs[i]]));
  const anchors = types.map((t) => ({ type: t, at: anchor.get(t)!, count: counts.get(t)! }));
  const rand = rng(view.nodes.length * 104729 + view.edges.length);
  const n = view.nodes.length;
  const idx = new Map(view.nodes.map((v, i) => [v.id, i]));
  const x = new Float64Array(n);
  const y = new Float64Array(n);
  const z = new Float64Array(n);
  const ringOf = (id: string) => (view.mode === "focus" ? (view.ring?.get(id) ?? 1) : 1);
  const target = (id: string) => (view.mode === "focus" ? [0, 0.5, 0.95][ringOf(id)] : 0);

  // Start around the type anchor (focus: second ring around the parent's direction).
  view.nodes.forEach((v, i) => {
    if (v.id === view.center) return;
    const parent = view.parent?.get(v.id);
    const p = parent && idx.has(parent) ? { x: x[idx.get(parent)!], y: y[idx.get(parent)!], z: z[idx.get(parent)!] } : null;
    const a = anchor.get(v.type) ?? { x: 0, y: 1, z: 0 };
    const base = p && ringOf(v.id) === 2 ? p : a;
    const j = 0.35;
    const dx = base.x + (rand() - 0.5) * j;
    const dy = base.y + (rand() - 0.5) * j;
    const dz = base.z + (rand() - 0.5) * j;
    const len = Math.hypot(dx, dy, dz) || 1;
    const r = view.mode === "focus" ? target(v.id) : 0.6;
    x[i] = (dx / len) * r;
    y[i] = (dy / len) * r;
    z[i] = (dz / len) * r;
  });

  const links = view.edges.map((e) => ({ s: idx.get(e.source)!, t: idx.get(e.target)! })).filter((l) => l.s !== undefined && l.t !== undefined);
  const k = 0.75 / Math.cbrt(Math.max(1, n));
  const dx = new Float64Array(n);
  const dy = new Float64Array(n);
  const dz = new Float64Array(n);
  const centerIdx = view.center ? idx.get(view.center) : undefined;
  for (let it = 0; it < iterations; it++) {
    const temp = 0.05 * (1 - it / iterations) + 0.003;
    dx.fill(0);
    dy.fill(0);
    dz.fill(0);
    for (let i = 0; i < n; i++) {
      for (let j = i + 1; j < n; j++) {
        let ex = x[i] - x[j];
        let ey = y[i] - y[j];
        let ez = z[i] - z[j];
        let d2 = ex * ex + ey * ey + ez * ez;
        if (d2 < 1e-6) {
          ex = (rand() - 0.5) * 1e-3;
          ey = (rand() - 0.5) * 1e-3;
          ez = (rand() - 0.5) * 1e-3;
          d2 = 1e-6;
        }
        const f = (k * k) / d2;
        dx[i] += ex * f;
        dy[i] += ey * f;
        dz[i] += ez * f;
        dx[j] -= ex * f;
        dy[j] -= ey * f;
        dz[j] -= ez * f;
      }
    }
    if (view.mode === "overview") {
      for (const l of links) {
        const ex = x[l.s] - x[l.t];
        const ey = y[l.s] - y[l.t];
        const ez = z[l.s] - z[l.t];
        const d = Math.hypot(ex, ey, ez) || 1e-3;
        const f = ((d * d) / k) * 0.3;
        dx[l.s] -= (ex / d) * f;
        dy[l.s] -= (ey / d) * f;
        dz[l.s] -= (ez / d) * f;
        dx[l.t] += (ex / d) * f;
        dy[l.t] += (ey / d) * f;
        dz[l.t] += (ez / d) * f;
      }
    }
    view.nodes.forEach((v, i) => {
      if (i === centerIdx) return;
      const a = anchor.get(v.type)!;
      if (view.mode === "overview") {
        dx[i] += (a.x * 0.6 - x[i]) * 0.8;
        dy[i] += (a.y * 0.6 - y[i]) * 0.8;
        dz[i] += (a.z * 0.6 - z[i]) * 0.8;
      }
      const d = Math.hypot(dx[i], dy[i], dz[i]) || 1;
      const step = Math.min(d, temp);
      x[i] += (dx[i] / d) * step;
      y[i] += (dy[i] / d) * step;
      z[i] += (dz[i] / d) * step;
      if (view.mode === "focus") {
        // Stay on the node's shell.
        const len = Math.hypot(x[i], y[i], z[i]) || 1;
        const r = target(v.id);
        x[i] = (x[i] / len) * r;
        y[i] = (y[i] / len) * r;
        z[i] = (z[i] / len) * r;
      }
    });
  }
  let max = 0;
  for (let i = 0; i < n; i++) max = Math.max(max, Math.hypot(x[i], y[i], z[i]));
  const scale = max > 0 ? 1 / max : 1;
  const pos = new Map<string, Point3>();
  view.nodes.forEach((v, i) => pos.set(v.id, i === centerIdx ? { x: 0, y: 0, z: 0 } : { x: x[i] * scale, y: y[i] * scale, z: z[i] * scale }));
  return { pos, anchors };
}
