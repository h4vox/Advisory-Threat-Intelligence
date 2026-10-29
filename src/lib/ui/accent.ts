/**
 * Accent colour: the colour of primary buttons, selection, links and focus rings. This module
 * lists the choices, renders their CSS (accentCss) and applies the saved one (`data-accent` on
 * <html>). Violet is the default and needs no attribute.
 */

export type AccentId = "violet" | "blue" | "teal" | "green" | "red" | "orange" | "pink" | "graphite";

/**
 * `swatch` is the colour shown in the picker; `dark` and `light` are the primary and accent/ring
 * colours for each theme (light-theme shades are deeper so text on them stays readable).
 */
export const ACCENTS: Array<{ id: AccentId; label: string; swatch: string; dark: { primary: string; accent: string }; light: string }> = [
  { id: "violet", label: "Violet", swatch: "#7c6cf2", dark: { primary: "#7c6cf2", accent: "#8b7cf6" }, light: "#5b4bd6" },
  { id: "blue", label: "Blue", swatch: "#3b82f6", dark: { primary: "#3b82f6", accent: "#60a5fa" }, light: "#2563eb" },
  { id: "teal", label: "Teal", swatch: "#14a39a", dark: { primary: "#14a39a", accent: "#2dc5b9" }, light: "#0f7f78" },
  { id: "green", label: "Green", swatch: "#22a05b", dark: { primary: "#22a05b", accent: "#3fbf7a" }, light: "#15803d" },
  { id: "red", label: "Red", swatch: "#e5484d", dark: { primary: "#e5484d", accent: "#f06a6e" }, light: "#c62a2f" },
  { id: "orange", label: "Orange", swatch: "#e8701a", dark: { primary: "#e8701a", accent: "#f28a3d" }, light: "#c2510c" },
  { id: "pink", label: "Pink", swatch: "#d6409f", dark: { primary: "#d6409f", accent: "#e461b3" }, light: "#b8237f" },
  { id: "graphite", label: "Graphite", swatch: "#6b7686", dark: { primary: "#6b7686", accent: "#8d97a6" }, light: "#4b5563" },
];

/**
 * The accent rules, rendered into the page's <head> by the root route (not in styles.css, so a
 * cached stylesheet can never hold them back). Violet is styles.css's default and needs no rule.
 */
export function accentCss(): string {
  return ACCENTS.filter((a) => a.id !== "violet")
    .map(
      (a) =>
        `html[data-accent="${a.id}"]{--color-primary:${a.dark.primary};--color-accent:${a.dark.accent};--color-ring:${a.dark.accent}}` +
        `html[data-accent="${a.id}"][data-theme="light"],html.light[data-accent="${a.id}"]{--color-primary:${a.light};--color-accent:${a.light};--color-ring:${a.light}}`,
    )
    .join("");
}

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
