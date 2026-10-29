import type { GraphNodeType } from "@/lib/aie/graph/types";

/**
 * Entity colours for the intelligence graph, per theme. Kept in code (not CSS variables) because
 * the canvas needs concrete colours and they must match the legend exactly.
 */
const DARK: Record<GraphNodeType, string> = {
  actor: "#f0616d",
  campaign: "#a78bfa",
  malware: "#f59e5b",
  tool: "#f2c14e",
  technique: "#6aa7ff",
  vulnerability: "#e879b9",
  sector: "#6cc28a",
  geography: "#38bdf8",
  platform: "#94a3b8",
  indicator: "#3cc9b4",
};

const LIGHT: Record<GraphNodeType, string> = {
  actor: "#d63c4b",
  campaign: "#6d4fd8",
  malware: "#d26a1f",
  tool: "#a77b06",
  technique: "#2f6fd8",
  vulnerability: "#c23d8f",
  sector: "#2f8a55",
  geography: "#0b84b5",
  platform: "#64748b",
  indicator: "#0f9a86",
};

export type GraphTheme = { dark: boolean; type: Record<GraphNodeType, string>; text: string; muted: string; ring: string; labelBg: string; bg: string };

export function graphTheme(dark: boolean): GraphTheme {
  return dark
    ? { dark, type: DARK, text: "#f2f2f0", muted: "#a3a6a1", ring: "rgba(255,255,255,0.07)", labelBg: "rgba(10,10,12,0.78)", bg: "#08080a" }
    : { dark, type: LIGHT, text: "#111318", muted: "#5b616e", ring: "rgba(17,19,24,0.08)", labelBg: "rgba(255,255,255,0.85)", bg: "#fbfbfc" };
}

/** Current theme, read from <html data-theme>. */
export function isDarkTheme(): boolean {
  if (typeof document === "undefined") return true;
  return document.documentElement.getAttribute("data-theme") !== "light" && !document.documentElement.classList.contains("light");
}

export function withAlpha(hex: string, alpha: number): string {
  const h = hex.replace("#", "");
  const n = parseInt(h.length === 3 ? h.split("").map((c) => c + c).join("") : h, 16);
  return `rgba(${(n >> 16) & 255},${(n >> 8) & 255},${n & 255},${Math.max(0, Math.min(1, alpha)).toFixed(3)})`;
}
