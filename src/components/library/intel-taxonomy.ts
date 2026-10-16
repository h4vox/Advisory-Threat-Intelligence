import type { DocType, ReportListItem, ReportRecord, SourceTier } from "@/lib/aie/types";
import { lookupAttackTechnique } from "@/lib/aie/mitre-matrix";

/**
 * Client-side taxonomy helpers for the library: document types (with a mapping
 * for records ingested before `docTypes` existed), source tiers, and the entity
 * lists shown on cards and facets. Everything is derived from stored fields only.
 */

type AnyReport = Pick<
  ReportListItem,
  | "docTypes"
  | "classification"
  | "resourceKind"
  | "structured"
  | "publisher"
  | "sourceName"
  | "sourceTier"
  | "sourceConfidence"
  | "analysis"
  | "extractedEntities"
  | "iocs"
> &
  Partial<Pick<ReportListItem, "title">> &
  Partial<Pick<ReportRecord, "tags">>;

const ALL_DOC_TYPES = new Set<DocType>([
  "THREAT_REPORT",
  "THREAT_ADVISORY",
  "INCIDENT_REPORT",
  "DFIR_REPORT",
  "MALWARE_REPORT",
  "VULNERABILITY_ADVISORY",
  "CAMPAIGN_REPORT",
  "MITRE_GROUP",
  "MITRE_SOFTWARE",
  "MITRE_CAMPAIGN",
  "MITRE_TECHNIQUE",
  "ADVERSARY_EMULATION_PLAN",
  "MICRO_EMULATION_PLAN",
  "ATTACK_FLOW",
  "ATOMIC_TEST",
  "CALDERA_ABILITY",
  "PURPLE_TEAM_REPORT",
  "DETECTION_RESEARCH",
  "THREAT_HUNTING_REPORT",
  "KEV_ENTRY",
  "OTHER",
]);

/** Older `classification` values (qualification.ts) → document type. */
const CLASSIFICATION_TO_DOC: Record<string, DocType> = {
  // The qualifier sets ADVERSARY_EMULATION / PURPLE_TEAM for any procedure-rich text, so those only
  // become plan types when the title says so (see docTypesOf); otherwise they are threat reports.
  ADVERSARY_EMULATION: "THREAT_REPORT",
  ADVERSARY_SIMULATION: "THREAT_REPORT",
  INTRUSION_REPORT: "INCIDENT_REPORT",
  ATTACK_CHAIN_REPORT: "THREAT_REPORT",
  MALWARE_ANALYSIS: "MALWARE_REPORT",
  THREAT_ACTOR_REPORT: "THREAT_REPORT",
  CAMPAIGN_REPORT: "CAMPAIGN_REPORT",
  VULNERABILITY_REPORT: "VULNERABILITY_ADVISORY",
  DETECTION_RESEARCH: "DETECTION_RESEARCH",
  THREAT_HUNTING_RESEARCH: "THREAT_HUNTING_REPORT",
  PURPLE_TEAM: "THREAT_REPORT",
  SECURITY_ADVISORY: "THREAT_ADVISORY",
  THREAT_REPORT: "THREAT_REPORT",
};

const KIND_TO_DOC: Record<string, DocType> = {
  FULL_ATTACK_CHAIN: "THREAT_REPORT",
  CAMPAIGN_INTEL: "CAMPAIGN_REPORT",
  PROCEDURE_DEEPDIVE: "THREAT_REPORT",
  MALWARE_ANALYSIS: "MALWARE_REPORT",
  DETECTION_GUIDANCE: "DETECTION_RESEARCH",
  VULNERABILITY_ADVISORY: "VULNERABILITY_ADVISORY",
  THREAT_ACTOR_DOSSIER: "THREAT_REPORT",
};

const STRUCTURED_TO_DOC: Record<string, DocType> = {
  attack_group: "MITRE_GROUP",
  attack_software: "MITRE_SOFTWARE",
  attack_campaign: "MITRE_CAMPAIGN",
  atomic_test: "ATOMIC_TEST",
  emulation_plan: "ADVERSARY_EMULATION_PLAN",
  attack_flow: "ATTACK_FLOW",
  kev: "KEV_ENTRY",
};

/** Document types of a record: stored `docTypes`, else mapped from structured kind / classification / resourceKind. */
export function docTypesOf(r: AnyReport): DocType[] {
  if (r.docTypes && r.docTypes.length > 0) return r.docTypes.filter((d) => ALL_DOC_TYPES.has(d));
  const out: DocType[] = [];
  const add = (d?: DocType) => {
    if (d && !out.includes(d)) out.push(d);
  };
  if (r.structured) {
    const k = r.structured.kind;
    add(k === "emulation_plan" && r.structured.planType === "micro" ? "MICRO_EMULATION_PLAN" : STRUCTURED_TO_DOC[k]);
  }
  const cls = (r.classification || "").toUpperCase();
  const title = r.title ?? "";
  if (/^(ADVERSARY_(EMULATION|SIMULATION)|PURPLE_TEAM)$/.test(cls)) {
    if (/micro[- ]emulation/i.test(title)) add("MICRO_EMULATION_PLAN");
    else if (/emulation plan|adversary emulation/i.test(title)) add("ADVERSARY_EMULATION_PLAN");
    else if (/purple[- ]team/i.test(title)) add("PURPLE_TEAM_REPORT");
  }
  if (ALL_DOC_TYPES.has(cls as DocType) && cls !== "OTHER") add(cls as DocType);
  add(CLASSIFICATION_TO_DOC[cls]);
  // The DFIR Report publishes intrusion case write-ups; label them as such.
  const pub = `${r.publisher || ""} ${r.sourceName || ""}`.toLowerCase();
  if (/\bdfir\b/.test(pub)) add("DFIR_REPORT");
  if (r.resourceKind) add(KIND_TO_DOC[r.resourceKind]);
  if (out.length > 1) {
    // A generic "threat report" label adds nothing next to a more specific one.
    const i = out.indexOf("THREAT_REPORT");
    if (i > -1) out.splice(i, 1);
  }
  // Unclassified intel that maps adversary behaviour to ATT&CK is still a threat report.
  if (out.length === 0 && ((r.analysis?.ttps?.length ?? 0) > 0 || (r.analysis?.attackChain?.length ?? 0) > 0)) add("THREAT_REPORT");
  if (out.length === 0) add("OTHER");
  return out;
}

export type DocTab = { id: string; label: string; types: DocType[] | null };

/** Library category tabs (document-type families). */
export const DOC_TABS: DocTab[] = [
  { id: "ALL", label: "All", types: null },
  { id: "threat", label: "Threat reports", types: ["THREAT_REPORT"] },
  { id: "advisory", label: "Advisories", types: ["THREAT_ADVISORY"] },
  { id: "incident", label: "Incident / DFIR", types: ["INCIDENT_REPORT", "DFIR_REPORT"] },
  { id: "malware", label: "Malware", types: ["MALWARE_REPORT"] },
  { id: "campaign", label: "Campaigns", types: ["CAMPAIGN_REPORT", "MITRE_CAMPAIGN"] },
  { id: "emulation", label: "Emulation plans", types: ["ADVERSARY_EMULATION_PLAN", "MICRO_EMULATION_PLAN", "PURPLE_TEAM_REPORT"] },
  { id: "flow", label: "Attack flows", types: ["ATTACK_FLOW"] },
  { id: "atomic", label: "Atomic tests", types: ["ATOMIC_TEST", "CALDERA_ABILITY"] },
  { id: "attack", label: "ATT&CK groups & software", types: ["MITRE_GROUP", "MITRE_SOFTWARE", "MITRE_TECHNIQUE"] },
  { id: "vuln", label: "Vulnerabilities / KEV", types: ["VULNERABILITY_ADVISORY", "KEV_ENTRY"] },
];

export function inDocTab(r: AnyReport, tab: DocTab): boolean {
  if (!tab.types) return true;
  const types = docTypesOf(r);
  return types.some((t) => tab.types!.includes(t));
}

// ---------------------------------------------------------------------------
// Source tiers (spec §66)
// ---------------------------------------------------------------------------

export const TIER_META: Record<SourceTier, { label: string; short: string; color: string }> = {
  1: { label: "Tier 1 · Structured / authoritative", short: "Tier 1", color: "var(--color-cat-ioc)" },
  2: { label: "Tier 2 · Emulation", short: "Tier 2", color: "var(--color-cat-emulation)" },
  3: { label: "Tier 3 · Vendor research", short: "Tier 3", color: "var(--color-cat-technique)" },
  4: { label: "Tier 4 · Community", short: "Tier 4", color: "var(--color-cat-advisory)" },
};

/** Stored tier, or null when the record predates tiers. */
export function tierOf(r: Pick<AnyReport, "sourceTier">): SourceTier | null {
  return r.sourceTier && TIER_META[r.sourceTier] ? r.sourceTier : null;
}

// ---------------------------------------------------------------------------
// Entities
// ---------------------------------------------------------------------------

const NONE = /^(none( identified)?|unknown|n\/a|-)$/i;

function uniq(values: Array<string | null | undefined>): string[] {
  const seen = new Map<string, string>();
  for (const v of values) {
    const s = (v || "").trim();
    if (!s || NONE.test(s)) continue;
    const k = s.toLowerCase();
    if (!seen.has(k)) seen.set(k, s);
  }
  return Array.from(seen.values());
}

export function actorsOf(r: AnyReport): string[] {
  return uniq([
    ...(r.analysis?.threatActors ?? []),
    ...(r.extractedEntities?.threatActors ?? []),
    ...(r.analysis?.evidence?.actors ?? []).filter((a) => a.label === "observed").map((a) => a.value),
  ]);
}

export function malwareOf(r: AnyReport): string[] {
  return uniq([
    ...(r.analysis?.malware ?? []),
    ...(r.extractedEntities?.malwareFamilies ?? []),
    ...(r.analysis?.evidence?.malware ?? []).filter((a) => a.label === "observed").map((a) => a.value),
  ]);
}

export function cvesOf(r: AnyReport): string[] {
  const all = uniq([
    ...(r.analysis?.vulnerabilities ?? []),
    ...(r.extractedEntities?.cves ?? []),
    ...(r.iocs ?? []).filter((i) => i.kind === "cve").map((i) => i.value),
    r.structured?.kind === "kev" ? r.structured.cveId : null,
  ]).map((c) => c.toUpperCase());
  return Array.from(new Set(all.filter((c) => /^CVE-\d{4}-\d{3,}$/.test(c))));
}

const TID = /T\d{4}(?:\.\d{3})?/i;

export type TechniqueRef = { id: string; name: string | null; tactic: string | null; label: "observed" | "inferred" | "mapped" };

/** Distinct ATT&CK techniques, with evidence label where the analysis recorded one. Order: first mention. */
export function techniquesOf(r: AnyReport): TechniqueRef[] {
  const out = new Map<string, TechniqueRef>();
  const add = (raw: string | null | undefined, label: TechniqueRef["label"], name?: string, tactic?: string) => {
    if (!raw) return;
    const m = raw.match(TID);
    if (!m) return;
    const id = m[0].toUpperCase();
    const ref = lookupAttackTechnique(id);
    const existing = out.get(id);
    if (existing) {
      if (existing.label === "mapped" && label !== "mapped") existing.label = label;
      return;
    }
    const cleanName = name && !TID.test(name.trim()) ? name.trim() : null;
    out.set(id, { id, name: ref?.name ?? cleanName, tactic: ref?.tactic ?? tactic ?? null, label });
  };
  const ev = r.analysis?.evidence;
  if (ev) {
    const steps = [...(ev.chain?.steps ?? [])].sort((a, b) => a.order - b.order);
    for (const s of steps) for (const t of s.techniques) {
      const fact = ev.techniques.find((f) => f.id === t);
      if (fact && (fact.label === "observed" || fact.label === "inferred")) add(t, fact.label, fact.name, fact.tactic);
    }
    for (const f of ev.techniques) if (f.label === "observed" || f.label === "inferred") add(f.id, f.label, f.name, f.tactic);
  }
  for (const s of r.analysis?.attackChain ?? []) for (const t of s.techniques ?? []) add(t, "mapped", undefined, s.tactic);
  for (const t of r.analysis?.ttps ?? []) add(t, "mapped");
  for (const t of r.extractedEntities?.techniques ?? []) add(t.id || t.name, "mapped", t.name, t.tactic);
  const st = r.structured;
  if (st) {
    if ("techniques" in st && Array.isArray(st.techniques)) for (const t of st.techniques) add(t, "mapped");
    if (st.kind === "atomic_test") add(st.techniqueId, "mapped");
    if (st.kind === "attack_flow") for (const a of st.actions) add(a.techniqueId, "mapped");
  }
  return Array.from(out.values());
}

/** ATT&CK enterprise tactics in kill-chain order. */
export const TACTIC_ORDER = [
  "Reconnaissance",
  "Resource Development",
  "Initial Access",
  "Execution",
  "Persistence",
  "Privilege Escalation",
  "Defense Evasion",
  "Credential Access",
  "Discovery",
  "Lateral Movement",
  "Collection",
  "Command and Control",
  "Exfiltration",
  "Impact",
] as const;

export function normalizeTactic(t: string | null | undefined): string | null {
  if (!t) return null;
  const k = t.toLowerCase().replace(/[-_]+/g, " ").replace(/&/g, "and").replace(/\s+/g, " ").trim();
  // ATT&CK v18 splits Defense Evasion into Stealth / Defense Impairment; show them in that column.
  if (k === "stealth" || k === "defense impairment") return "Defense Evasion";
  return TACTIC_ORDER.find((x) => x.toLowerCase() === k) ?? null;
}

export function tacticsOf(r: AnyReport): string[] {
  const set = new Set<string>();
  for (const s of r.analysis?.attackChain ?? []) {
    const t = normalizeTactic(s.tactic);
    if (t) set.add(t);
  }
  for (const t of r.extractedEntities?.tactics ?? []) {
    const n = normalizeTactic(t);
    if (n) set.add(n);
  }
  for (const t of techniquesOf(r)) {
    const n = normalizeTactic(t.tactic);
    if (n) set.add(n);
  }
  return TACTIC_ORDER.filter((t) => set.has(t));
}

/** Techniques per tactic (kill-chain order, only tactics with ≥1 technique). */
export function tacticCoverage(techs: TechniqueRef[]): Array<{ tactic: string; techniques: TechniqueRef[] }> {
  const by = new Map<string, TechniqueRef[]>();
  for (const t of techs) {
    const n = normalizeTactic(t.tactic);
    if (!n) continue;
    by.set(n, [...(by.get(n) ?? []), t]);
  }
  return TACTIC_ORDER.filter((t) => by.has(t)).map((t) => ({ tactic: t, techniques: by.get(t)! }));
}

const EMULATION_DOCS = new Set<DocType>([
  "ADVERSARY_EMULATION_PLAN",
  "MICRO_EMULATION_PLAN",
  "ATTACK_FLOW",
  "ATOMIC_TEST",
  "CALDERA_ABILITY",
  "PURPLE_TEAM_REPORT",
]);

/** True when the record itself carries emulation content (plan / flow / atomic / drafted procedures). */
export function hasEmulationContent(r: AnyReport): boolean {
  if (docTypesOf(r).some((d) => EMULATION_DOCS.has(d))) return true;
  return (r.analysis?.emulation?.length ?? 0) > 0;
}

export function publisherOf(r: Pick<AnyReport, "publisher" | "sourceName">): string {
  return r.publisher || r.sourceName || "Unknown publisher";
}
