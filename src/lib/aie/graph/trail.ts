/**
 * The focus trail of an Intel Graph investigation: the entities visited in order (APT29 →
 * Government → Cobalt Strike → T1059…) and where the analyst is in it. Works like browser
 * history: going back keeps the later steps (forward), and focusing a new entity from an earlier
 * step replaces the steps after it. Pure; unit-tested.
 */

export type Trail = { steps: string[]; pos: number };

export const MAX_TRAIL = 60;
export const EMPTY_TRAIL: Trail = { steps: [], pos: -1 };

export const currentStep = (t: Trail): string | null => (t.pos >= 0 ? (t.steps[t.pos] ?? null) : null);

/** Focus an entity: a new step after the current one (later steps are replaced). */
export function visit(t: Trail, id: string): Trail {
  if (currentStep(t) === id) return t;
  let steps = [...t.steps.slice(0, t.pos + 1), id];
  if (steps.length > MAX_TRAIL) steps = steps.slice(steps.length - MAX_TRAIL);
  return { steps, pos: steps.length - 1 };
}

/** Go to step k of the trail (nothing is removed). */
export function jump(t: Trail, k: number): Trail {
  return k >= 0 && k < t.steps.length ? { steps: t.steps, pos: k } : t;
}

export const back = (t: Trail): Trail => jump(t, t.pos - 1);
export const forward = (t: Trail): Trail => jump(t, t.pos + 1);
export const canBack = (t: Trail) => t.pos > 0;
export const canForward = (t: Trail) => t.pos >= 0 && t.pos < t.steps.length - 1;

/** A trail restored from saved data, with the position kept in range. */
export function restore(steps: string[], pos: number): Trail {
  const s = steps.filter(Boolean).slice(-MAX_TRAIL);
  return s.length ? { steps: s, pos: Math.max(0, Math.min(s.length - 1, pos)) } : EMPTY_TRAIL;
}
