import type { EntityKind } from "@/components/ui/entity";
import { entityMeta } from "@/components/ui/entity";
import type { PurplePath, RiskLevel, Priority } from "@/lib/aie/purple/types";
import { exportFileBase, toCalderaYaml, toJson, toMarkdown } from "@/lib/aie/purple/export";
import type { Tone } from "@/components/ui/primitives";

/** Tactic → category hue (one family per kill-chain stage; tokens only). */
const TACTIC_KIND: Record<string, EntityKind> = {
  Reconnaissance: "source",
  "Resource Development": "source",
  "Initial Access": "cve",
  Execution: "malware",
  Persistence: "advisory",
  "Privilege Escalation": "advisory",
  "Defense Evasion": "flow",
  Stealth: "flow",
  "Defense Impairment": "flow",
  "Credential Access": "actor",
  Discovery: "technique",
  "Lateral Movement": "emulation",
  Collection: "ioc",
  "Command and Control": "ioc",
  Exfiltration: "cve",
  Impact: "actor",
};

export function tacticColor(tactic: string): string {
  return entityMeta(TACTIC_KIND[tactic] ?? "technique").color;
}

export function tint(color: string, pct = 14) {
  return { color, backgroundColor: `color-mix(in oklab, ${color} ${pct}%, transparent)` };
}

export const RISK_TONE: Record<RiskLevel, Tone> = { high: "danger", medium: "warning", low: "success" };
export const RISK_LABEL: Record<RiskLevel, string> = { high: "High risk", medium: "Medium risk", low: "Low risk" };
export const PRIORITY_TONE: Record<Priority, Tone> = { high: "primary", medium: "info", low: "neutral" };
export const PRIORITY_LABEL: Record<Priority, string> = { high: "High priority", medium: "Medium priority", low: "Low priority" };

function download(name: string, text: string, type: string) {
  const blob = new Blob([text], { type });
  const a = document.createElement("a");
  a.href = URL.createObjectURL(blob);
  a.download = name;
  document.body.appendChild(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(a.href), 1000);
}

export function exportPath(p: PurplePath, format: "md" | "json" | "yaml") {
  const base = exportFileBase(p);
  if (format === "md") download(`${base}.md`, toMarkdown(p), "text/markdown");
  else if (format === "json") download(`${base}.json`, toJson(p), "application/json");
  else download(`${base}_caldera_adversary.yml`, toCalderaYaml(p), "application/x-yaml");
}

// ---------------------------------------------------------------------------------------------
// Recent plans (per-viewer convenience; localStorage may be unavailable)
// ---------------------------------------------------------------------------------------------

export type SavedPlanInput = {
  kind: "actor" | "report" | "campaign" | "custom";
  value: string;
  platforms: string[];
  excludeHighRisk: boolean;
  maxSteps: number;
};

export type SavedPlan = {
  key: string;
  name: string;
  savedAt: string;
  steps: number;
  tactics: number;
  input: SavedPlanInput;
};

const KEY = "aie_purple_recent_v1";

export function loadRecentPlans(): SavedPlan[] {
  try {
    const raw = window.localStorage.getItem(KEY);
    const list = raw ? (JSON.parse(raw) as SavedPlan[]) : [];
    return Array.isArray(list) ? list.filter((p) => p && p.input && typeof p.name === "string").slice(0, 12) : [];
  } catch {
    return [];
  }
}

export function saveRecentPlan(plan: SavedPlan): SavedPlan[] {
  const next = [plan, ...loadRecentPlans().filter((p) => p.key !== plan.key)].slice(0, 12);
  try {
    window.localStorage.setItem(KEY, JSON.stringify(next));
  } catch {
    /* storage unavailable: keep in memory only */
  }
  return next;
}

export function removeRecentPlan(key: string): SavedPlan[] {
  const next = loadRecentPlans().filter((p) => p.key !== key);
  try {
    window.localStorage.setItem(KEY, JSON.stringify(next));
  } catch {
    /* ignore */
  }
  return next;
}

export function planKey(i: SavedPlanInput): string {
  return [i.kind, i.value.trim().toLowerCase(), [...i.platforms].sort().join("+"), i.excludeHighRisk ? "nohigh" : "all", i.maxSteps].join("|");
}
