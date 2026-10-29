/**
 * Accent colour: the colour of primary buttons, selection, links and focus rings. The values live
 * in styles.css (`[data-accent="…"]`, one block per theme); this module lists the choices and
 * applies the saved one. Violet is the default and needs no attribute.
 */

export type AccentId = "violet" | "blue" | "teal" | "green" | "red" | "orange" | "pink" | "graphite";

/** `swatch` is the dark-theme colour, shown in the picker. */
export const ACCENTS: Array<{ id: AccentId; label: string; swatch: string }> = [
  { id: "violet", label: "Violet", swatch: "#7c6cf2" },
  { id: "blue", label: "Blue", swatch: "#3b82f6" },
  { id: "teal", label: "Teal", swatch: "#14a39a" },
  { id: "green", label: "Green", swatch: "#22a05b" },
  { id: "red", label: "Red", swatch: "#e5484d" },
  { id: "orange", label: "Orange", swatch: "#e8701a" },
  { id: "pink", label: "Pink", swatch: "#d6409f" },
  { id: "graphite", label: "Graphite", swatch: "#6b7686" },
];

export const ACCENT_STORAGE_KEY = "aie_accent";
export const ACCENT_CHANGED_EVENT = "aie-accent-changed";

export function isAccentId(v: unknown): v is AccentId {
  return typeof v === "string" && ACCENTS.some((a) => a.id === v);
}

export function readAccent(): AccentId {
  try {
    const v = localStorage.getItem(ACCENT_STORAGE_KEY);
    return isAccentId(v) ? v : "violet";
  } catch {
    return "violet";
  }
}

export function applyAccent(id: AccentId) {
  if (id === "violet") document.documentElement.removeAttribute("data-accent");
  else document.documentElement.setAttribute("data-accent", id);
}

export function saveAccent(id: AccentId) {
  try {
    localStorage.setItem(ACCENT_STORAGE_KEY, id);
  } catch {
    /* storage unavailable: the colour lasts for this page only */
  }
  applyAccent(id);
  window.dispatchEvent(new Event(ACCENT_CHANGED_EVENT));
}
