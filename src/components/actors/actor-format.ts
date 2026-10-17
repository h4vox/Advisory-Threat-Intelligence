import type { ActorRow } from "@/lib/aie/actors/types";

/** Formatting and link helpers for the threat-actor pages (no components). */

/** Kill-chain phase hue for a tactic (small marks only: dots, bars). */
const TACTIC_HUE: Record<string, string> = {
  reconnaissance: "var(--color-cat-source)",
  "resource development": "var(--color-cat-source)",
  "initial access": "var(--color-cat-actor)",
  execution: "var(--color-cat-malware)",
  persistence: "var(--color-cat-malware)",
  "privilege escalation": "var(--color-cat-malware)",
  "defense evasion": "var(--color-cat-emulation)",
  stealth: "var(--color-cat-emulation)",
  "defense impairment": "var(--color-cat-emulation)",
  "credential access": "var(--color-cat-cve)",
  discovery: "var(--color-cat-technique)",
  "lateral movement": "var(--color-cat-technique)",
  collection: "var(--color-cat-flow)",
  "command and control": "var(--color-cat-flow)",
  exfiltration: "var(--color-cat-ioc)",
  impact: "var(--color-cat-advisory)",
};

export function tacticHue(tactic: string | null | undefined): string {
  return TACTIC_HUE[(tactic ?? "").toLowerCase()] ?? "var(--color-muted)";
}

const SHORT: Record<string, string> = {
  "resource development": "Resource dev",
  "privilege escalation": "Priv. escalation",
  "command and control": "C2",
  "defense impairment": "Defense impairment",
};

export function shortTactic(tactic: string): string {
  const s = SHORT[tactic.toLowerCase()];
  if (s) return s;
  return tactic.charAt(0).toUpperCase() + tactic.slice(1).toLowerCase();
}

/** Library identifier used in purple / search links: the ATT&CK ID when there is one. */
export function actorRef(row: Pick<ActorRow, "attackId" | "id">): string {
  return row.attackId ?? row.id;
}

/** Link target for the purple path builder: /purple?actor=<G-ID or slug>. */
export function purpleLink(row: Pick<ActorRow, "attackId" | "id">) {
  return { to: "/purple", search: { actor: actorRef(row) } } as const;
}

/** Link target for report search: /search?q=actor:<name>. */
export function searchLink(name: string) {
  return { to: "/search", search: { q: `actor:${/\s/.test(name) ? `"${name}"` : name}` } } as const;
}

export function attackTechniqueUrl(id: string): string {
  return `https://attack.mitre.org/techniques/${id.replace(".", "/")}/`;
}

export function attackSoftwareUrl(id: string): string {
  return `https://attack.mitre.org/software/${id}/`;
}

export function attackCampaignUrl(id: string): string {
  return `https://attack.mitre.org/campaigns/${id}/`;
}

export function formatDay(val: string | null | undefined): string | null {
  if (!val) return null;
  const d = new Date(val);
  if (Number.isNaN(d.getTime())) return null;
  return d.toLocaleDateString("en-US", {
    year: "numeric",
    month: "short",
    day: "numeric",
    timeZone: "UTC",
  });
}
