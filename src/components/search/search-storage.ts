/** Recent and saved searches (per browser; localStorage may be unavailable, so every access is guarded). */

const RECENT_KEY = "aie_search_recent";
const SAVED_KEY = "aie_search_saved";
const MAX_RECENT = 8;
const MAX_SAVED = 20;

export type SavedSearch = { q: string; savedAt: string };

function read<T>(key: string, fallback: T): T {
  try {
    const raw = window.localStorage.getItem(key);
    return raw ? (JSON.parse(raw) as T) : fallback;
  } catch {
    return fallback;
  }
}

function write(key: string, value: unknown) {
  try {
    window.localStorage.setItem(key, JSON.stringify(value));
  } catch {
    /* storage blocked: recent / saved searches simply don't persist */
  }
}

export function loadRecent(): string[] {
  const v = read<unknown>(RECENT_KEY, []);
  return Array.isArray(v) ? v.filter((x): x is string => typeof x === "string").slice(0, MAX_RECENT) : [];
}

export function pushRecent(q: string): string[] {
  const t = q.trim();
  if (!t) return loadRecent();
  const next = [t, ...loadRecent().filter((x) => x !== t)].slice(0, MAX_RECENT);
  write(RECENT_KEY, next);
  return next;
}

export function clearRecent(): string[] {
  write(RECENT_KEY, []);
  return [];
}

export function loadSaved(): SavedSearch[] {
  const v = read<unknown>(SAVED_KEY, []);
  return Array.isArray(v) ? v.filter((x): x is SavedSearch => !!x && typeof (x as SavedSearch).q === "string").slice(0, MAX_SAVED) : [];
}

export function toggleSaved(q: string): SavedSearch[] {
  const t = q.trim();
  const cur = loadSaved();
  const next = cur.some((s) => s.q === t) ? cur.filter((s) => s.q !== t) : [{ q: t, savedAt: new Date().toISOString() }, ...cur].slice(0, MAX_SAVED);
  write(SAVED_KEY, next);
  return next;
}

export function removeSaved(q: string): SavedSearch[] {
  const next = loadSaved().filter((s) => s.q !== q);
  write(SAVED_KEY, next);
  return next;
}
