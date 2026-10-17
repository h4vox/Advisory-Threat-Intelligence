/**
 * Library report → SearchDoc. Canonical entities come from the stored
 * analysis / extracted entities and, when not stored, are computed on the fly
 * with findEntitiesInText; aliases resolve to ATT&CK ids ("UNC3944" → G1015).
 * Doc types, tier and confidence use stored values, else the classifier and
 * the source registry.
 *
 * Server-only (imports the ATT&CK snapshot).
 */
import { aliasesFor, findEntitiesInText, getTechnique, isTooGenericForText, resolveEntity } from "../attack-knowledge.ts";
import { registryEntry } from "../catalog.ts";
import { classifyDocument } from "../doc-classifier.ts";
import { SOURCE_CONFIDENCE } from "../types.ts";
import type { DocType, ExtractedEntities, IntelAnalysis, IocHit, SourceTier, StructuredIntel } from "../types.ts";
import { prepareDoc, type DocEntity, type PreparedDoc, type SearchDoc } from "./rank.ts";

/** The report fields search needs (a ReportRecord or a projection of one). */
export type ReportLike = {
  id: string;
  title: string;
  extractedText?: string;
  excerpt?: string;
  url?: string;
  canonicalUrl?: string;
  publisher?: string;
  sourceName?: string;
  sourceId?: string;
  publishedAt?: string | null;
  qualityScore?: number;
  analysis?: IntelAnalysis | null;
  extractedEntities?: ExtractedEntities;
  iocs?: IocHit[];
  docTypes?: DocType[];
  sourceTier?: SourceTier;
  sourceConfidence?: number;
  structured?: StructuredIntel;
  classification?: string;
  resourceKind?: string;
  textHash?: string;
  status?: string;
  version?: number;
};

const EMULATION_TYPES = new Set<DocType>([
  "ADVERSARY_EMULATION_PLAN",
  "MICRO_EMULATION_PLAN",
  "ATTACK_FLOW",
  "ATOMIC_TEST",
  "CALDERA_ABILITY",
  "PURPLE_TEAM_REPORT",
]);

const TID_RE = /\bT\d{4}(?:\.\d{3})?\b/g;
const CVE_RE = /\bCVE-\d{4}-\d{4,7}\b/gi;
const NONE = /^(none( identified)?|unknown|n\/a|-|not specified)$/i;

function uniqStrings(values: Array<string | null | undefined>): string[] {
  const seen = new Map<string, string>();
  for (const v of values) {
    const s = (v ?? "").trim();
    if (!s || NONE.test(s)) continue;
    if (!seen.has(s.toLowerCase())) seen.set(s.toLowerCase(), s);
  }
  return [...seen.values()];
}

function structuredTechniques(st: StructuredIntel | undefined): string[] {
  if (!st) return [];
  if (st.kind === "atomic_test") return [st.techniqueId];
  if (st.kind === "attack_flow") return st.actions.map((a) => a.techniqueId ?? "").filter(Boolean);
  if ("techniques" in st && Array.isArray(st.techniques)) return st.techniques;
  return [];
}

export function docTypesForReport(r: ReportLike): DocType[] {
  if (r.docTypes && r.docTypes.length) return r.docTypes;
  const src = registryEntry(r.sourceId);
  return classifyDocument({
    title: r.title ?? "",
    url: r.url ?? "",
    text: String(r.extractedText ?? "").slice(0, 60_000),
    sourceYields: src?.yields,
    sourceTier: src?.tier,
    classification: r.classification,
    resourceKind: r.resourceKind,
    structuredKind: r.structured?.kind,
  }).docTypes;
}

/** Builds the search document for a stored report. */
export function reportToSearchDoc(r: ReportLike): SearchDoc {
  const text = String(r.extractedText ?? r.excerpt ?? "");
  const a = r.analysis ?? null;
  const ee = r.extractedEntities;
  const src = registryEntry(r.sourceId);

  // Entities: stored names resolved through aliases, plus names found in the text.
  const byKey = new Map<string, DocEntity>();
  const add = (kind: DocEntity["kind"], id: string, name: string, via: string, count: number) => {
    const key = `${kind}:${id}`;
    const prev = byKey.get(key);
    if (prev) {
      prev.count += count;
      if (count > 0 && prev.via === prev.name && via !== name) prev.via = via;
    } else byKey.set(key, { kind, id, name, via, count, rel: "mention" });
  };
  const storedActors = uniqStrings([...(a?.threatActors ?? []), ...(ee?.threatActors ?? []), ee?.campaign ?? null]);
  const storedMalware = uniqStrings([...(a?.malware ?? []), ...(ee?.malwareFamilies ?? [])]);
  const unresolvedActors: string[] = [];
  for (const name of storedActors) {
    const hit = resolveEntity(name, ["group", "campaign"])[0];
    if (hit) add(hit.kind as DocEntity["kind"], hit.id, hit.name, name, 1);
    else unresolvedActors.push(name);
  }
  for (const name of storedMalware) {
    if (isTooGenericForText(name)) continue; // "cmd", "net": OS utilities, not intelligence
    const hit = resolveEntity(name, ["software"])[0];
    if (hit) add("software", hit.id, hit.name, name, 1);
  }
  for (const h of findEntitiesInText(`${r.title}\n${text.slice(0, 200_000)}`)) {
    if (h.kind === "technique") continue;
    add(h.kind as DocEntity["kind"], h.id, h.name, h.matched, h.count);
  }
  const st = r.structured;
  if (st && (st.kind === "attack_group" || st.kind === "attack_software" || st.kind === "attack_campaign")) {
    const kind = st.kind === "attack_group" ? "group" : st.kind === "attack_software" ? "software" : "campaign";
    const hit = resolveEntity(st.attackId)[0];
    if (hit) add(kind, hit.id, hit.name, hit.name, 10);
  }
  const entities = [...byKey.values()].sort((x, y) => y.count - x.count);
  // "via" = the name this document uses most ("Octo Tempest" in a Microsoft report, "UNC3944" in a Mandiant one).
  const hay = `${r.title}\n${text.slice(0, 200_000)}`;
  for (const e of entities.slice(0, 12)) {
    let best = e.via;
    let bestN = 0;
    for (const alias of aliasesFor(e.kind, e.id)) {
      if (alias.length < 3) continue;
      const re = new RegExp(`(?<![\\w-])${alias.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}(?![\\w-])`, /^[A-Za-z]+$/.test(alias) ? "g" : "gi");
      const n = hay.match(re)?.length ?? 0;
      if (n > bestN) {
        bestN = n;
        best = alias;
      }
    }
    if (bestN > 0) e.via = best;
  }

  // Techniques
  const techSet = new Set<string>();
  const addT = (v: string | undefined | null) => {
    const m = String(v ?? "").toUpperCase().match(/T\d{4}(?:\.\d{3})?/);
    if (m && getTechnique(m[0])) techSet.add(m[0]);
  };
  for (const t of a?.ttps ?? []) addT(t);
  for (const s of a?.attackChain ?? []) for (const t of s.techniques ?? []) addT(t);
  for (const f of a?.evidence?.techniques ?? []) if (f.label === "observed" || f.label === "inferred") addT(f.id);
  for (const t of ee?.techniques ?? []) addT(t.id);
  for (const t of structuredTechniques(st)) addT(t);
  for (const m of text.slice(0, 300_000).match(TID_RE) ?? []) addT(m);
  const techniques = [...techSet];

  const tactics = new Set<string>();
  for (const id of techniques) for (const t of getTechnique(id)?.tactics ?? []) tactics.add(t);
  for (const s of a?.attackChain ?? []) if (s.tactic) tactics.add(s.tactic);

  const cves = new Set<string>();
  for (const c of [...(a?.vulnerabilities ?? []), ...(ee?.cves ?? [])]) if (/^CVE-\d{4}-\d{4,7}$/i.test(c.trim())) cves.add(c.trim().toUpperCase());
  for (const i of r.iocs ?? []) if (i.kind === "cve") cves.add(i.value.toUpperCase());
  for (const m of text.slice(0, 300_000).match(CVE_RE) ?? []) cves.add(m.toUpperCase());
  if (st?.kind === "kev") cves.add(st.cveId.toUpperCase());

  const docTypes = docTypesForReport(r);
  const tier = r.sourceTier ?? src?.tier;
  const confidence = r.sourceConfidence ?? (src ? SOURCE_CONFIDENCE[src.confidenceClass] : undefined);
  const ev = a?.evidence;
  const hasEvidence = Boolean(ev && (ev.techniques.length > 0 || ev.actors.length > 0 || ev.malware.length > 0));
  const quality = typeof r.qualityScore === "number" ? (r.qualityScore > 1 ? r.qualityScore / 100 : r.qualityScore) : undefined;
  const summary = String(r.excerpt || text.slice(0, 600)).replace(/\s+/g, " ").trim();

  return {
    id: r.id,
    kind: "report",
    title: r.title || "Untitled report",
    summary: summary.slice(0, 600),
    body: text,
    aliases: [],
    entities,
    techniques,
    tactics: [...tactics],
    cves: [...cves],
    docTypes,
    tier,
    confidence,
    quality,
    publishedAt: r.publishedAt ?? null,
    publisher: r.publisher || r.sourceName || src?.name || "",
    url: r.canonicalUrl || r.url || "",
    hasIocs: (r.iocs?.length ?? 0) > 0,
    hasEmulation: docTypes.some((t) => EMULATION_TYPES.has(t)) || (a?.emulation?.length ?? 0) > 0,
    hasEvidence,
    dupKey: r.textHash || r.canonicalUrl || undefined,
    actorNames: uniqStrings([...entities.filter((e) => e.kind === "group").map((e) => e.name), ...unresolvedActors]),
    meta: {
      sourceId: r.sourceId,
      structuredKind: st?.kind,
      structuredAttackId: st && "attackId" in st ? st.attackId : undefined,
    },
  };
}

export function isEmulationDocType(t: DocType): boolean {
  return EMULATION_TYPES.has(t);
}

// Prepared-document cache: re-tokenizing a 300k-char report per query is the expensive part.
const prepared = new Map<string, PreparedDoc>();
const MAX_CACHE = 2000;

function cacheKey(r: ReportLike): string {
  return `${r.id}|${r.textHash ?? ""}|${r.version ?? ""}|${(r.extractedText ?? "").length}|${r.docTypes?.join(",") ?? ""}|${r.analysis ? "a" : ""}`;
}

export function prepareReport(r: ReportLike): PreparedDoc {
  const key = cacheKey(r);
  const hit = prepared.get(key);
  if (hit) return hit;
  const p = prepareDoc(reportToSearchDoc(r));
  if (prepared.size >= MAX_CACHE) prepared.delete(prepared.keys().next().value as string);
  prepared.set(key, p);
  return p;
}
