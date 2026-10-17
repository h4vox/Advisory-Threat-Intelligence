/**
 * Threat-actor aggregation (pure; server side because it reads the bundled ATT&CK knowledge).
 *
 * Library reports → canonical actors:
 *   - actor names from the analysis (threatActors, evidence.actors, extractedEntities) and ATT&CK
 *     group names/aliases found in the title + excerpt are resolved to ATT&CK group IDs;
 *   - names that don't resolve become "not in ATT&CK" actors with a stable slug id ("x-storm-1234");
 *   - synced ATT&CK reference docs (discoveryMethod "structured_sync") are not library reports.
 * Each actor then carries its reports, observed techniques (with evidence), ATT&CK-attributed
 * techniques / software / campaigns, CVEs, the "new vs ATT&CK" technique diff and an activity score.
 */
import {
  ATTACK_SNAPSHOT_DATE,
  ATTACK_VERSION,
  attackGroups,
  campaignsForGroup,
  findEntitiesInText,
  getGroup,
  getSoftware,
  getTechnique,
  isGenericEntityName,
  normalizeEntityName,
  resolveEntity,
  tacticRank,
  type AttackCampaign,
} from "../attack-knowledge.ts";
import type { EvidenceLabel, ExtractedEntities, IntelAnalysis, IocHit } from "../types.ts";
import type {
  ActorCampaignRow,
  ActorCtidPlan,
  ActorEmulationSummary,
  ActorListKpis,
  ActorProfile,
  ActorReportRef,
  ActorRow,
  ActorSoftwareRow,
  ActorSort,
  ActorSuggestion,
  ActorTechniqueEvidence,
  ActorTechniqueRow,
} from "./types.ts";

/** The subset of a ReportListItem the aggregation reads. */
export type ActorSourceReport = {
  id: string;
  title: string;
  url?: string;
  excerpt?: string;
  publisher?: string;
  sourceName?: string;
  publishedAt?: string | null;
  ingestedAt?: string;
  status?: string;
  discoveryMethod?: string;
  qualityScore?: number;
  iocs?: IocHit[];
  analysis?: IntelAnalysis | null;
  extractedEntities?: ExtractedEntities;
};

export type EmulationContext = {
  synced: boolean;
  /** Technique IDs that have Atomic Red Team tests (null when not synced). */
  atomicTechniques: Set<string> | null;
  /** CTID plans keyed by ATT&CK group ID. */
  plansByGroup: Map<string, ActorCtidPlan[]>;
};

export const NO_EMULATION: EmulationContext = {
  synced: false,
  atomicTechniques: null,
  plansByGroup: new Map(),
};

const TECHNIQUE_LABELS = new Set<EvidenceLabel>(["observed", "inferred"]);
const SKIP_ENTITY_LABELS = new Set<EvidenceLabel>(["negated", "hypothetical", "defensive"]);
const TID = /^(T\d{4}(?:\.\d{3})?)\b/i;
const CVE = /^CVE-\d{4}-\d{4,}$/i;
const MAX_EVIDENCE = 4;

// ---------------------------------------------------------------------------------------------
// Name resolution
// ---------------------------------------------------------------------------------------------

/** Stable id for an actor that is not in ATT&CK. */
export function slugifyActor(name: string): string {
  const s = normalizeEntityName(name)
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-+|-+$/g, "")
    .slice(0, 60);
  return `x-${s || "unknown"}`;
}

export function isSlugActorId(id: string): boolean {
  return id.startsWith("x-");
}

const SUFFIX =
  /\s+(?:group|apt group|threat actor|threat group|actor|ransomware(?: group| gang| operators?)?|gang|operators?|affiliates?|crew)$/i;

export type ResolvedActor = { id: string; attackId: string | null; name: string };

/**
 * Resolves an actor name or alias to an ATT&CK group, or to a slug actor when ATT&CK has no match.
 * Returns null for generic words and names that are really software / campaigns / techniques.
 */
export function resolveActorName(raw: string): ResolvedActor | null {
  const name = raw
    .replace(/\s+/g, " ")
    .trim()
    .replace(/^["'“”]+|["'“”.,;:]+$/g, "");
  if (name.length < 2 || name.length > 80 || !/[a-z]/i.test(name)) return null;
  const candidates = [name];
  const stripped = name.replace(SUFFIX, "").trim();
  if (stripped && stripped !== name) candidates.push(stripped);
  for (const c of candidates) {
    const g = resolveEntity(c, ["group"])[0];
    if (g) return { id: g.id, attackId: g.id, name: g.name };
  }
  for (const c of candidates) {
    if (isGenericEntityName(c)) return null;
    if (resolveEntity(c, ["software", "campaign", "technique"]).length) return null;
  }
  const display = stripped.length >= 2 ? stripped : name;
  return { id: slugifyActor(display), attackId: null, name: display };
}

// ---------------------------------------------------------------------------------------------
// Per-report extraction
// ---------------------------------------------------------------------------------------------

export function isLibraryReport(r: ActorSourceReport): boolean {
  if (r.discoveryMethod === "structured_sync") return false;
  if (r.status && r.status !== "acquired") return false;
  return true;
}

export type ReportActorLink = ResolvedActor & { matchedBy: "analysis" | "text"; matched: string };

/** Actors a report talks about, keyed by actor id. */
export function actorLinksOf(r: ActorSourceReport): Map<string, ReportActorLink> {
  const out = new Map<string, ReportActorLink>();
  const add = (raw: string | undefined, matchedBy: "analysis" | "text") => {
    if (!raw) return;
    const res = resolveActorName(raw);
    if (!res) return;
    const prev = out.get(res.id);
    if (prev && (prev.matchedBy === "analysis" || matchedBy === "text")) return;
    out.set(res.id, { ...res, matchedBy, matched: raw.trim() });
  };
  const a = r.analysis;
  for (const n of a?.threatActors ?? []) add(n, "analysis");
  for (const ev of a?.evidence?.actors ?? [])
    if (!SKIP_ENTITY_LABELS.has(ev.label)) add(ev.value, "analysis");
  for (const n of r.extractedEntities?.threatActors ?? []) add(n, "analysis");
  const text = `${r.title ?? ""}\n${r.excerpt ?? ""}`;
  for (const hit of findEntitiesInText(text, { kinds: ["group"] })) {
    if (!out.has(hit.id))
      out.set(hit.id, {
        id: hit.id,
        attackId: hit.id,
        name: hit.name,
        matchedBy: "text",
        matched: hit.matched,
      });
  }
  return out;
}

export type ReportTechnique = {
  id: string;
  name: string;
  tactic: string | null;
  labels: EvidenceLabel[];
  evidence: Array<{ quote: string; label: EvidenceLabel; section?: string }>;
};

function validTactic(t: string | null | undefined): string | null {
  if (!t) return null;
  const s = t.trim();
  if (!s || /^unknown$/i.test(s)) return null;
  return s;
}

/** Adversary techniques a report records (observed / inferred only; defensive, negated etc. are excluded). */
export function techniquesOfReport(r: ActorSourceReport): Map<string, ReportTechnique> {
  const out = new Map<string, ReportTechnique>();
  const a = r.analysis;
  const facts = a?.evidence?.techniques;
  if (facts) {
    for (const f of facts) {
      if (!TECHNIQUE_LABELS.has(f.label)) continue;
      const id = f.id.toUpperCase();
      const known = getTechnique(id);
      const cur = out.get(id) ?? {
        id,
        name: known?.name ?? f.name ?? id,
        tactic: validTactic(f.tactic) ?? known?.tactics[0] ?? null,
        labels: [],
        evidence: [],
      };
      if (!cur.labels.includes(f.label)) cur.labels.push(f.label);
      for (const e of f.evidence ?? [])
        cur.evidence.push({ quote: e.quote, label: f.label, section: e.section });
      out.set(id, cur);
    }
    return out;
  }
  const add = (raw: string | undefined, name?: string, tactic?: string) => {
    const m = raw?.trim().match(TID);
    if (!m) return;
    const id = m[1].toUpperCase();
    if (out.has(id)) return;
    const known = getTechnique(id);
    out.set(id, {
      id,
      name: known?.name ?? name ?? id,
      tactic: validTactic(tactic) ?? known?.tactics[0] ?? null,
      labels: [],
      evidence: [],
    });
  };
  for (const t of a?.ttps ?? []) add(t);
  for (const t of r.extractedEntities?.techniques ?? []) add(t.id, t.name, t.tactic);
  return out;
}

export type ReportSoftware = { key: string; id: string | null; name: string };

export function softwareOfReport(r: ActorSourceReport): Map<string, ReportSoftware> {
  const out = new Map<string, ReportSoftware>();
  const add = (raw: string | undefined) => {
    const name = raw?.trim();
    if (!name || name.length < 2) return;
    const s = resolveEntity(name, ["software"])[0];
    const key = s ? s.id : `n:${normalizeEntityName(name)}`;
    if (!out.has(key)) out.set(key, { key, id: s?.id ?? null, name: s?.name ?? name });
  };
  const a = r.analysis;
  for (const m of a?.malware ?? []) add(m);
  for (const ev of a?.evidence?.malware ?? []) if (!SKIP_ENTITY_LABELS.has(ev.label)) add(ev.value);
  for (const m of r.extractedEntities?.malwareFamilies ?? []) add(m);
  return out;
}

export function cvesOfReport(r: ActorSourceReport): string[] {
  const set = new Set<string>();
  for (const i of r.iocs ?? [])
    if (i.kind === "cve" && CVE.test(i.value)) set.add(i.value.toUpperCase());
  for (const v of r.analysis?.vulnerabilities ?? [])
    if (CVE.test(v.trim())) set.add(v.trim().toUpperCase());
  for (const v of r.extractedEntities?.cves ?? [])
    if (CVE.test(v.trim())) set.add(v.trim().toUpperCase());
  return [...set].sort();
}

// ---------------------------------------------------------------------------------------------
// Technique diff
// ---------------------------------------------------------------------------------------------

const parentOf = (id: string) => id.split(".")[0];

/**
 * True when an observed technique is not covered by the ATT&CK attribution: neither the exact ID,
 * its parent, nor any of its sub-techniques is attributed.
 */
export function isNewVsAttack(observedId: string, attributed: ReadonlySet<string>): boolean {
  const id = observedId.toUpperCase();
  if (attributed.has(id)) return false;
  const parent = parentOf(id);
  if (parent !== id && attributed.has(parent)) return false;
  for (const a of attributed) if (parentOf(a) === id) return false;
  return true;
}

function hasAtomic(id: string, atomic: Set<string>, atomicParents: Set<string>): boolean {
  return atomic.has(id) || (!id.includes(".") && atomicParents.has(id));
}

// ---------------------------------------------------------------------------------------------
// Index
// ---------------------------------------------------------------------------------------------

type ObservedTechnique = {
  id: string;
  name: string;
  tactic: string | null;
  labels: Set<EvidenceLabel>;
  reportIds: Set<string>;
  evidenceCount: number;
  evidence: ActorTechniqueEvidence[];
};

export type ActorRecord = {
  id: string;
  attackId: string | null;
  name: string;
  aliases: string[];
  inAttack: boolean;
  description: string | null;
  attributedTechniques: string[];
  attributedSoftware: string[];
  campaigns: AttackCampaign[];
  reports: ActorReportRef[];
  observed: Map<string, ObservedTechnique>;
  observedSoftware: Map<string, ReportSoftware & { reportIds: Set<string> }>;
  cves: Map<string, Set<string>>;
  /** Surface names seen in the library (for slug actors and alias search). */
  libraryNames: Set<string>;
  firstSeen: string | null;
  lastSeen: string | null;
  activityScore: number;
};

export type ActorIndex = {
  actors: ActorRecord[];
  byId: Map<string, ActorRecord>;
  libraryReports: number;
  builtAt: number;
};

const dateOf = (r: { publishedAt?: string | null; ingestedAt?: string }) => {
  const d = r.publishedAt || r.ingestedAt || "";
  return d && !Number.isNaN(Date.parse(d)) ? d : null;
};

function newRecord(id: string, attackId: string | null, name: string): ActorRecord {
  const g = attackId ? getGroup(attackId) : undefined;
  return {
    id,
    attackId: g ? g.id : null,
    name: g?.name ?? name,
    aliases: g ? [...g.aliases] : [],
    inAttack: Boolean(g),
    description: g?.description || null,
    attributedTechniques: g ? [...g.techniques] : [],
    attributedSoftware: g ? [...g.software] : [],
    campaigns: g ? campaignsForGroup(g.id) : [],
    reports: [],
    observed: new Map(),
    observedSoftware: new Map(),
    cves: new Map(),
    libraryNames: new Set(),
    firstSeen: null,
    lastSeen: null,
    activityScore: 0,
  };
}

/** Recency-weighted activity: each report counts 10, halving every 180 days; observed techniques add a little. */
export function activityScore(
  reportDates: Array<string | null>,
  observedTechniques: number,
  now: number,
): number {
  let s = 0;
  for (const d of reportDates) {
    const t = d ? Date.parse(d) : NaN;
    const ageDays = Number.isNaN(t) ? 365 : Math.max(0, (now - t) / 86_400_000);
    s += 10 * Math.pow(0.5, ageDays / 180);
  }
  return Math.round((s + observedTechniques * 0.25) * 100) / 100;
}

export function buildActorIndex(reports: ActorSourceReport[], now = Date.now()): ActorIndex {
  const byId = new Map<string, ActorRecord>();
  for (const g of attackGroups()) byId.set(g.id, newRecord(g.id, g.id, g.name));
  let libraryReports = 0;

  for (const r of reports) {
    if (!isLibraryReport(r)) continue;
    libraryReports += 1;
    const links = actorLinksOf(r);
    if (links.size === 0) continue;
    const techs = techniquesOfReport(r);
    const software = softwareOfReport(r);
    const cves = cvesOfReport(r);
    for (const link of links.values()) {
      let rec = byId.get(link.id);
      if (!rec) {
        rec = newRecord(link.id, link.attackId, link.name);
        byId.set(link.id, rec);
      }
      rec.libraryNames.add(link.matched);
      if (rec.reports.some((x) => x.id === r.id)) continue;
      rec.reports.push({
        id: r.id,
        title: r.title,
        publisher: r.publisher || r.sourceName || "",
        publishedAt: r.publishedAt ?? null,
        ingestedAt: r.ingestedAt ?? "",
        url: r.url ?? "",
        matchedBy: link.matchedBy,
        matched: link.matched,
        techniqueCount: techs.size,
        qualityScore: Number(r.qualityScore ?? 0),
      });
      for (const t of techs.values()) {
        const cur = rec.observed.get(t.id) ?? {
          id: t.id,
          name: t.name,
          tactic: t.tactic,
          labels: new Set(),
          reportIds: new Set(),
          evidenceCount: 0,
          evidence: [],
        };
        cur.reportIds.add(r.id);
        for (const l of t.labels) cur.labels.add(l);
        cur.tactic ??= t.tactic;
        cur.evidenceCount += t.evidence.length;
        for (const e of t.evidence) {
          if (cur.evidence.length >= MAX_EVIDENCE) break;
          if (cur.evidence.some((x) => x.quote === e.quote)) continue;
          cur.evidence.push({ ...e, reportId: r.id, reportTitle: r.title });
        }
        rec.observed.set(t.id, cur);
      }
      for (const s of software.values()) {
        const cur = rec.observedSoftware.get(s.key) ?? { ...s, reportIds: new Set<string>() };
        cur.reportIds.add(r.id);
        rec.observedSoftware.set(s.key, cur);
      }
      for (const c of cves) {
        const set = rec.cves.get(c) ?? new Set<string>();
        set.add(r.id);
        rec.cves.set(c, set);
      }
    }
  }

  for (const rec of byId.values()) {
    if (!rec.inAttack) {
      // Most frequent / first surface form as the display name; the rest are aliases.
      const names = [...rec.libraryNames];
      rec.aliases = names.filter((n) => normalizeEntityName(n) !== normalizeEntityName(rec.name));
    }
    const dates = rec.reports
      .map(dateOf)
      .filter((d): d is string => Boolean(d))
      .sort();
    rec.firstSeen = dates[0] ?? null;
    rec.lastSeen = dates[dates.length - 1] ?? null;
    rec.reports.sort((a, b) => (dateOf(b) ?? "").localeCompare(dateOf(a) ?? ""));
    rec.activityScore = activityScore(rec.reports.map(dateOf), rec.observed.size, now);
  }

  return { actors: [...byId.values()], byId, libraryReports, builtAt: now };
}

// ---------------------------------------------------------------------------------------------
// Projections
// ---------------------------------------------------------------------------------------------

function primaryTactic(id: string, observedTactic?: string | null): string | null {
  return observedTactic ?? getTechnique(id)?.tactics[0] ?? null;
}

function allTechniqueIds(rec: ActorRecord): string[] {
  return [...new Set([...rec.attributedTechniques, ...rec.observed.keys()])];
}

function emulationSummary(rec: ActorRecord, emu: EmulationContext): ActorEmulationSummary {
  if (!emu.synced) return { synced: false };
  const ids = allTechniqueIds(rec);
  let covered = 0;
  if (emu.atomicTechniques) {
    const parents = new Set([...emu.atomicTechniques].map(parentOf));
    for (const id of ids) if (hasAtomic(id, emu.atomicTechniques, parents)) covered += 1;
  }
  return {
    synced: true,
    ctidPlans: rec.attackId ? (emu.plansByGroup.get(rec.attackId)?.length ?? 0) : 0,
    atomicCovered: covered,
    techniqueTotal: ids.length,
  };
}

export function actorRow(rec: ActorRecord, emu: EmulationContext = NO_EMULATION): ActorRow {
  const attributed = new Set(rec.attributedTechniques);
  let newTechniques = 0;
  for (const id of rec.observed.keys()) if (isNewVsAttack(id, attributed)) newTechniques += 1;
  const tacticCounts = new Map<string, number>();
  for (const id of allTechniqueIds(rec)) {
    const t = primaryTactic(id, rec.observed.get(id)?.tactic);
    if (t) tacticCounts.set(t, (tacticCounts.get(t) ?? 0) + 1);
  }
  const topTactics = [...tacticCounts.entries()]
    .sort((a, b) => b[1] - a[1] || tacticRank(a[0]) - tacticRank(b[0]))
    .slice(0, 3)
    .map(([tactic, count]) => ({ tactic, count }));
  const publishers = [...new Set(rec.reports.map((r) => r.publisher).filter(Boolean))];
  const softwareIds = new Set(rec.attributedSoftware);
  for (const s of rec.observedSoftware.values()) softwareIds.add(s.id ?? s.key);
  return {
    id: rec.id,
    attackId: rec.attackId,
    name: rec.name,
    aliases: rec.aliases,
    inAttack: rec.inAttack,
    observed: rec.reports.length > 0,
    reportCount: rec.reports.length,
    firstSeen: rec.firstSeen,
    lastSeen: rec.lastSeen,
    publishers,
    attributedTechniques: attributed.size,
    observedTechniques: rec.observed.size,
    newTechniques,
    software: softwareIds.size,
    campaigns: rec.campaigns.length,
    topTactics,
    activityScore: rec.activityScore,
    emulation: emulationSummary(rec, emu),
  };
}

export function techniqueRows(
  rec: ActorRecord,
  emu: EmulationContext = NO_EMULATION,
): ActorTechniqueRow[] {
  const attributed = new Set(rec.attributedTechniques);
  const atomicParents = emu.atomicTechniques
    ? new Set([...emu.atomicTechniques].map(parentOf))
    : null;
  const rows: ActorTechniqueRow[] = allTechniqueIds(rec).map((id) => {
    const obs = rec.observed.get(id);
    const known = getTechnique(id);
    const isAttributed = attributed.has(id);
    return {
      id,
      name: known?.name ?? obs?.name ?? id,
      tactics: known?.tactics ?? (obs?.tactic ? [obs.tactic] : []),
      tactic: primaryTactic(id, obs?.tactic),
      source: obs && isAttributed ? "both" : obs ? "observed" : "attack",
      observedReports: obs?.reportIds.size ?? 0,
      evidenceCount: obs?.evidenceCount ?? 0,
      labels: obs ? [...obs.labels] : [],
      isNew: obs ? isNewVsAttack(id, attributed) : false,
      evidence: obs?.evidence ?? [],
      atomic:
        emu.atomicTechniques && atomicParents
          ? hasAtomic(id, emu.atomicTechniques, atomicParents)
          : null,
    };
  });
  return rows.sort(
    (a, b) =>
      b.observedReports - a.observedReports ||
      tacticRank(a.tactic ?? undefined) - tacticRank(b.tactic ?? undefined) ||
      a.id.localeCompare(b.id),
  );
}

export function softwareRows(rec: ActorRecord): ActorSoftwareRow[] {
  const rows = new Map<string, ActorSoftwareRow>();
  for (const id of rec.attributedSoftware) {
    const s = getSoftware(id);
    rows.set(id, {
      id,
      name: s?.name ?? id,
      type: s?.type ?? null,
      platforms: s?.platforms ?? [],
      techniqueCount: s?.techniques.length ?? 0,
      attributed: true,
      observedReports: 0,
    });
  }
  for (const o of rec.observedSoftware.values()) {
    const key = o.id ?? o.key;
    const cur = rows.get(key);
    if (cur) cur.observedReports = o.reportIds.size;
    else {
      const s = o.id ? getSoftware(o.id) : undefined;
      rows.set(key, {
        id: o.id,
        name: s?.name ?? o.name,
        type: s?.type ?? null,
        platforms: s?.platforms ?? [],
        techniqueCount: s?.techniques.length ?? 0,
        attributed: false,
        observedReports: o.reportIds.size,
      });
    }
  }
  return [...rows.values()].sort(
    (a, b) =>
      b.observedReports - a.observedReports ||
      Number(b.attributed) - Number(a.attributed) ||
      a.name.localeCompare(b.name),
  );
}

export function campaignRows(rec: ActorRecord): ActorCampaignRow[] {
  return rec.campaigns
    .map((c) => ({
      id: c.id,
      name: c.name,
      aliases: c.aliases.filter((a) => a !== c.name),
      firstSeen: c.firstSeen ?? null,
      lastSeen: c.lastSeen ?? null,
      techniqueCount: c.techniques.length,
      softwareCount: c.software.length,
      description: c.description,
    }))
    .sort(
      (a, b) => (b.lastSeen ?? "").localeCompare(a.lastSeen ?? "") || a.name.localeCompare(b.name),
    );
}

export function actorProfile(rec: ActorRecord, emu: EmulationContext = NO_EMULATION): ActorProfile {
  const techniques = techniqueRows(rec, emu);
  const cov = new Map<string, { attributed: number; observed: number }>();
  for (const t of techniques) {
    if (!t.tactic) continue;
    const c = cov.get(t.tactic) ?? { attributed: 0, observed: 0 };
    if (t.source !== "observed") c.attributed += 1;
    if (t.source !== "attack") c.observed += 1;
    cov.set(t.tactic, c);
  }
  return {
    row: actorRow(rec, emu),
    description: rec.description,
    attackUrl: rec.attackId ? `https://attack.mitre.org/groups/${rec.attackId}/` : null,
    techniques,
    reports: rec.reports,
    campaigns: campaignRows(rec),
    software: softwareRows(rec),
    cves: [...rec.cves.entries()]
      .map(([id, set]) => ({ id, reports: set.size }))
      .sort((a, b) => b.reports - a.reports || b.id.localeCompare(a.id)),
    tacticCoverage: [...cov.entries()]
      .map(([tactic, c]) => ({ tactic, ...c }))
      .sort((a, b) => tacticRank(a.tactic) - tacticRank(b.tactic)),
    attackVersion: ATTACK_VERSION ?? null,
    attackSnapshotDate: ATTACK_SNAPSHOT_DATE ?? null,
    emulation: {
      synced: emu.synced,
      plans: rec.attackId ? (emu.plansByGroup.get(rec.attackId) ?? []) : [],
    },
  };
}

// ---------------------------------------------------------------------------------------------
// Lookup, filtering and sorting
// ---------------------------------------------------------------------------------------------

/** Finds an actor by ATT&CK ID, slug, name or alias. */
export function findActor(index: ActorIndex, actorId: string): ActorRecord | undefined {
  const raw = decodeURIComponent(actorId).trim();
  const direct =
    index.byId.get(raw) ?? index.byId.get(raw.toUpperCase()) ?? index.byId.get(raw.toLowerCase());
  if (direct) return direct;
  const res = resolveActorName(raw);
  if (res) return index.byId.get(res.id);
  return undefined;
}

function searchKeys(rec: ActorRecord): string[] {
  return [rec.name, rec.id, ...rec.aliases, ...rec.libraryNames].map(normalizeEntityName);
}

export function matchesActorQuery(rec: ActorRecord, q: string): boolean {
  const n = normalizeEntityName(q);
  if (!n) return true;
  return searchKeys(rec).some((k) => k.includes(n));
}

export function filterActors(
  index: ActorIndex,
  opts: { q?: string; observedOnly?: boolean },
): ActorRecord[] {
  return index.actors.filter(
    (a) =>
      (!opts.observedOnly || a.reports.length > 0) && (!opts.q || matchesActorQuery(a, opts.q)),
  );
}

export function sortActorRows(rows: ActorRow[], sort: ActorSort): ActorRow[] {
  const byName = (a: ActorRow, b: ActorRow) =>
    a.name.localeCompare(b.name, undefined, { sensitivity: "base" });
  const cmp: Record<ActorSort, (a: ActorRow, b: ActorRow) => number> = {
    recent: (a, b) =>
      b.activityScore - a.activityScore ||
      (b.lastSeen ?? "").localeCompare(a.lastSeen ?? "") ||
      b.attributedTechniques - a.attributedTechniques ||
      byName(a, b),
    reports: (a, b) =>
      b.reportCount - a.reportCount ||
      (b.lastSeen ?? "").localeCompare(a.lastSeen ?? "") ||
      byName(a, b),
    techniques: (a, b) =>
      b.observedTechniques - a.observedTechniques ||
      b.attributedTechniques - a.attributedTechniques ||
      byName(a, b),
    name: byName,
  };
  return [...rows].sort(cmp[sort]);
}

export function actorKpis(index: ActorIndex): ActorListKpis {
  const techs = new Set<string>();
  let observed = 0;
  let notInAttack = 0;
  let last: string | null = null;
  for (const a of index.actors) {
    if (!a.inAttack) notInAttack += 1;
    if (a.reports.length) observed += 1;
    for (const id of a.observed.keys()) techs.add(id);
    if (a.lastSeen && (!last || a.lastSeen > last)) last = a.lastSeen;
  }
  return {
    attackGroups: index.actors.filter((a) => a.inAttack).length,
    observedInLibrary: observed,
    notInAttack,
    techniquesObserved: techs.size,
    lastActivity: last,
    libraryReports: index.libraryReports,
  };
}

/** Prefix suggestions over names and aliases (prefix matches first, then substring). */
export function suggestActors(index: ActorIndex, prefix: string, limit = 8): ActorSuggestion[] {
  const n = normalizeEntityName(prefix);
  if (!n) return [];
  const scored: Array<{ s: ActorSuggestion; score: number }> = [];
  for (const a of index.actors) {
    const names = [a.name, ...a.aliases, ...a.libraryNames, a.id];
    let best: { matched: string; score: number } | null = null;
    for (const name of names) {
      const k = normalizeEntityName(name);
      const score = k === n ? 0 : k.startsWith(n) ? 1 : k.includes(n) ? 2 : -1;
      if (score >= 0 && (!best || score < best.score)) best = { matched: name, score };
    }
    if (best)
      scored.push({
        s: {
          id: a.id,
          name: a.name,
          matched: best.matched,
          inAttack: a.inAttack,
          observed: a.reports.length > 0,
        },
        score: best.score - (a.reports.length ? 0.5 : 0),
      });
  }
  return scored
    .sort((a, b) => a.score - b.score || a.s.name.localeCompare(b.s.name))
    .slice(0, limit)
    .map((x) => x.s);
}
