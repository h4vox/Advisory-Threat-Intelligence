/**
 * Hybrid ranking for intelligence search.
 *
 *   score = (BM25F text match × term coverage
 *            + canonical entity match (aliases resolved) + exact ids (CVE / T / G / S)
 *            + technique match (exact, parent / sub-technique) + tactic + doc-type intent)
 *           × source confidence × tier × quality × mild recency decay
 *
 * then near-duplicate collapse and publisher diversity (MMR-style greedy
 * re-ranking). Every scored document carries a `why`: matched fields, terms,
 * entities (and the alias the document used), techniques and a score breakdown.
 *
 * Pure module (relative imports only), unit-tested under node --test.
 */
import { isExactIdToken, isLowSignal, tokenize } from "../retrieval.ts";
import type { DocType, SourceTier } from "../types.ts";
import type { InterpretedQuery, MatchedEntity, QueryEntityKind, ResultWhy, ScorePart } from "./types.ts";

export type SearchDocKind = "report" | "group" | "software" | "campaign" | "technique";

export type DocEntity = {
  kind: QueryEntityKind;
  id: string;
  name: string;
  /** Surface form the document uses ("UNC3944"). */
  via: string;
  /** Mentions in the document (0 for structural links). */
  count: number;
  /** self = the knowledge document is this entity; uses = structural ATT&CK link; mention = found in text / analysis. */
  rel: "self" | "uses" | "mention";
};

export type SearchDoc = {
  id: string;
  kind: SearchDocKind;
  title: string;
  summary: string;
  body: string;
  /** Names the document is known by (knowledge docs) or entity names it carries. */
  aliases: string[];
  entities: DocEntity[];
  techniques: string[];
  /** Technique ids that the document is (self) or structurally uses. */
  techniqueRel?: "self" | "uses" | "mention";
  tactics: string[];
  cves: string[];
  docTypes: DocType[];
  tier?: SourceTier;
  confidence?: number;
  /** 0..1 */
  quality?: number;
  publishedAt?: string | null;
  /** Campaign activity window (knowledge campaigns). */
  activeFrom?: string;
  activeTo?: string;
  publisher?: string;
  url?: string;
  hasIocs?: boolean;
  hasEmulation?: boolean;
  hasEvidence?: boolean;
  /** Content hash or canonical URL for exact-duplicate collapse. */
  dupKey?: string;
  /** Facet labels for actors (canonical + unresolved analysis names). */
  actorNames?: string[];
  meta?: Record<string, unknown>;
};

type FieldName = "title" | "aliases" | "summary" | "body";
const FIELDS: FieldName[] = ["title", "aliases", "summary", "body"];
const FIELD_WEIGHT: Record<FieldName, number> = { title: 3, aliases: 2.5, summary: 1.5, body: 1 };
const FIELD_B: Record<FieldName, number> = { title: 0.5, aliases: 0.4, summary: 0.6, body: 0.75 };
const K1 = 1.4;

export type PreparedDoc = {
  doc: SearchDoc;
  tf: Record<FieldName, Map<string, number>>;
  len: Record<FieldName, number>;
  /** Lower-cased, whitespace-collapsed text for phrase / exclusion checks. */
  flat: string;
  /** 5-word shingle hashes of the opening text for near-duplicate detection. */
  shingles: Set<number>;
  entityKey: Set<string>;
};

const MAX_BODY_CHARS = 300_000;

function countTokens(text: string): { tf: Map<string, number>; len: number } {
  const tf = new Map<string, number>();
  const toks = tokenize(text);
  for (const t of toks) tf.set(t, (tf.get(t) ?? 0) + 1);
  return { tf, len: toks.length };
}

function hashStr(s: string): number {
  let h = 2166136261;
  for (let i = 0; i < s.length; i++) {
    h ^= s.charCodeAt(i);
    h = Math.imul(h, 16777619);
  }
  return h >>> 0;
}

function shinglesOf(text: string): Set<number> {
  const words = text.toLowerCase().replace(/[^a-z0-9 ]+/g, " ").split(/\s+/).filter(Boolean).slice(0, 800);
  const out = new Set<number>();
  for (let i = 0; i + 5 <= words.length; i++) out.add(hashStr(words.slice(i, i + 5).join(" ")));
  return out;
}

export function flatten(s: string): string {
  return String(s ?? "").toLowerCase().replace(/\s+/g, " ");
}

/** Tokenizes a document's fields once (cache the result per document version). */
export function prepareDoc(doc: SearchDoc): PreparedDoc {
  const body = String(doc.body ?? "").slice(0, MAX_BODY_CHARS);
  const aliasText = [...doc.aliases, ...doc.entities.filter((e) => e.rel !== "uses").map((e) => `${e.name} ${e.via}`)].join(" \n ");
  const parts: Record<FieldName, string> = { title: doc.title, aliases: aliasText, summary: doc.summary, body };
  const tf = {} as PreparedDoc["tf"];
  const len = {} as PreparedDoc["len"];
  for (const f of FIELDS) {
    const c = countTokens(parts[f]);
    tf[f] = c.tf;
    len[f] = c.len;
  }
  return {
    doc,
    tf,
    len,
    flat: flatten(`${doc.title} \n ${doc.aliases.join(" ")} \n ${doc.summary} \n ${body}`),
    shingles: doc.kind === "report" ? shinglesOf(body.slice(0, 6000)) : new Set(),
    entityKey: new Set(doc.entities.map((e) => `${e.kind}:${e.id}`)),
  };
}

export type CorpusStats = { n: number; avg: Record<FieldName, number>; df: Map<string, number> };

/** Average field lengths and document frequency for the query terms. */
export function corpusStats(docs: PreparedDoc[], terms: string[]): CorpusStats {
  const avg = { title: 0, aliases: 0, summary: 0, body: 0 } as Record<FieldName, number>;
  const df = new Map<string, number>();
  for (const d of docs) {
    for (const f of FIELDS) avg[f] += d.len[f];
    for (const t of terms) if (FIELDS.some((f) => d.tf[f].has(t))) df.set(t, (df.get(t) ?? 0) + 1);
  }
  const n = Math.max(1, docs.length);
  for (const f of FIELDS) avg[f] = Math.max(1, avg[f] / n);
  return { n, avg, df };
}

function termWeight(t: string): number {
  if (isExactIdToken(t)) return 3;
  if (isLowSignal(t)) return 0.3;
  return 1;
}

const W = {
  entityMention: 4,
  entitySelf: 8,
  entityUses: 0.8,
  exactCve: 5,
  techniqueExact: 3,
  techniqueRelated: 1.5,
  techniqueSelf: 8,
  techniqueSelfRelated: 2,
  techniqueUses: 0.6,
  tactic: 0.8,
  docTypeIntent: 2,
  titleEntity: 1,
};

const TIER_MULT: Record<number, number> = { 1: 1.06, 2: 1.04, 3: 1, 4: 0.93 };

export type ScoredDoc = { prepared: PreparedDoc; score: number; why: ResultWhy; adjusted?: number };

export type RankOptions = {
  now?: number;
  /** Skip hard filters (eval baseline experiments). */
  noFilters?: boolean;
};

function round(v: number) {
  return Math.round(v * 1000) / 1000;
}

function wordPresent(p: PreparedDoc, word: string): boolean {
  const toks = tokenize(word);
  if (toks.length === 0) return p.flat.includes(word.toLowerCase());
  return toks.every((t) => FIELDS.some((f) => p.tf[f].has(t)));
}

function entityMatch(p: PreparedDoc, kind: QueryEntityKind, id: string): DocEntity | undefined {
  if (!p.entityKey.has(`${kind}:${id}`)) return undefined;
  return p.doc.entities.find((e) => e.kind === kind && e.id === id);
}

function techniqueRelation(p: PreparedDoc, id: string, related: string[]): "exact" | "parent" | "sub" | null {
  const techs = p.doc.techniques;
  if (techs.includes(id)) return "exact";
  for (const r of related) {
    if (techs.includes(r)) return r.includes(".") ? "sub" : "parent";
  }
  return null;
}

function dateOk(p: PreparedDoc, since?: string, until?: string): boolean {
  if (!since && !until) return true;
  const d = p.doc;
  if (d.kind === "group" || d.kind === "software" || d.kind === "technique") return true; // undated knowledge
  if (d.kind === "campaign") {
    const from = d.activeFrom ?? d.activeTo;
    const to = d.activeTo ?? d.activeFrom;
    if (!from && !to) return true;
    if (since && to && to.slice(0, 10) < since) return false;
    if (until && from && from.slice(0, 10) > until) return false;
    return true;
  }
  const pub = d.publishedAt ? String(d.publishedAt).slice(0, 10) : "";
  if (!/^\d{4}-\d{2}-\d{2}$/.test(pub)) return false;
  if (since && pub < since) return false;
  if (until && pub > until) return false;
  return true;
}

/** Hard filters from the interpreted query. Returns false to drop the document. */
export function passesFilters(p: PreparedDoc, iq: InterpretedQuery): boolean {
  const d = p.doc;
  if (iq.docTypes.length && !d.docTypes.some((t) => iq.docTypes.includes(t))) return false;
  if (iq.excludedDocTypes.length && d.docTypes.some((t) => iq.excludedDocTypes.includes(t))) return false;
  if (iq.tiers.length && !(d.tier && iq.tiers.includes(d.tier))) return false;
  const pub = (d.publisher ?? "").toLowerCase();
  if (iq.publishers.length && !iq.publishers.some((x) => pub.includes(x.toLowerCase()))) return false;
  if (iq.excludedPublishers.some((x) => pub.includes(x.toLowerCase()))) return false;
  if (!dateOk(p, iq.since, iq.until)) return false;
  if (iq.has.includes("iocs") && !d.hasIocs) return false;
  if (iq.has.includes("emulation") && !d.hasEmulation) return false;
  if (iq.has.includes("evidence") && !d.hasEvidence) return false;
  for (const e of iq.entities) {
    if (e.source !== "field") continue;
    const hit = entityMatch(p, e.kind, e.id) !== undefined;
    if (e.negated ? hit : !hit) return false;
  }
  for (const t of iq.techniques) {
    if (t.source !== "field") continue;
    const hit = techniqueRelation(p, t.id, t.related) !== null;
    if (t.negated ? hit : !hit) return false;
  }
  for (const t of iq.tactics) if (t.source === "field" && !d.tactics.some((x) => x.toLowerCase() === t.name.toLowerCase())) return false;
  for (const c of iq.requiredCves) if (!d.cves.includes(c)) return false;
  for (const u of iq.unresolved) {
    if (u.field === "technique") continue;
    const present = p.flat.includes(u.value.toLowerCase());
    if (u.negated ? present : !present) return false;
  }
  for (const ph of iq.phrases) if (!p.flat.includes(flatten(ph))) return false;
  for (const x of iq.excluded) {
    if (x.includes(" ") ? p.flat.includes(flatten(x)) : wordPresent(p, x)) return false;
  }
  return true;
}

/**
 * Scores every document against the interpreted query. Documents that fail a
 * hard filter or match nothing are dropped. Sorted by score, best first.
 */
export function scoreDocs(docs: PreparedDoc[], iq: InterpretedQuery, opts: RankOptions = {}): ScoredDoc[] {
  const now = opts.now ?? Date.now();
  const terms = iq.terms.filter((t) => !iq.excluded.some((x) => tokenize(x).includes(t)));
  const stats = corpusStats(docs, terms);
  const idf = (t: string) => {
    const d = stats.df.get(t) ?? 0;
    return Math.max(0.2, Math.log(1 + (stats.n - d + 0.5) / (d + 0.5)));
  };
  const signalTerms = terms.filter((t) => !isLowSignal(t));
  const positiveEntities = iq.entities.filter((e) => !e.negated);
  const positiveTechniques = iq.techniques.filter((t) => !t.negated);
  const implicitTactics = iq.tactics.filter((t) => t.source === "implicit");
  const consumed = new Set(iq.consumedTerms ?? []);

  const out: ScoredDoc[] = [];
  for (const p of docs) {
    if (!opts.noFilters && !passesFilters(p, iq)) continue;
    const d = p.doc;
    const parts: ScorePart[] = [];
    const matchedFields = new Set<string>();
    const matchedTerms: string[] = [];

    // --- BM25F text match
    let text = 0;
    let signalHits = 0;
    let freeHits = 0;
    for (const t of terms) {
      let tfw = 0;
      for (const f of FIELDS) {
        const tf = p.tf[f].get(t) ?? 0;
        if (!tf) continue;
        matchedFields.add(f);
        tfw += (FIELD_WEIGHT[f] * tf) / (1 - FIELD_B[f] + (FIELD_B[f] * p.len[f]) / stats.avg[f]);
      }
      if (tfw > 0) {
        matchedTerms.push(t);
        if (!isLowSignal(t)) {
          signalHits++;
          if (!consumed.has(t)) freeHits++;
        }
        text += termWeight(t) * idf(t) * (tfw / (K1 + tfw));
      }
    }
    if (signalHits === 0) text = 0;
    const coverage = signalTerms.length ? signalHits / signalTerms.length : 0;
    if (text > 0) {
      text *= 0.5 + 0.5 * coverage;
      parts.push({ key: "text", label: `Text match (BM25F, ${signalHits}/${signalTerms.length} terms)`, value: round(text) });
    }
    // Phrase presence (phrases are also filters)
    if (iq.phrases.length) parts.push({ key: "phrase", label: "Exact phrase", value: 1.5 * iq.phrases.length });

    // --- Entities (aliases resolved to canonical ATT&CK ids)
    const matchedEntities: MatchedEntity[] = [];
    let entityScore = 0;
    for (const e of positiveEntities) {
      const hit = entityMatch(p, e.kind, e.id);
      if (!hit) continue;
      matchedEntities.push({ kind: e.kind, id: e.id, name: e.name, via: hit.via, queryForm: e.matched, rel: hit.rel });
      if (hit.rel === "self") entityScore += W.entitySelf;
      else if (hit.rel === "uses") entityScore += W.entityUses;
      else {
        entityScore += W.entityMention * (1 + Math.min(1, Math.log2(1 + hit.count) / 3));
        if (flatten(d.title).includes(hit.via.toLowerCase()) || flatten(d.title).includes(e.name.toLowerCase())) entityScore += W.titleEntity;
      }
    }
    if (entityScore > 0) {
      matchedFields.add("entities");
      parts.push({ key: "entity", label: `Entity match (${matchedEntities.map((m) => m.name).join(", ")})`, value: round(entityScore) });
    }

    // --- Exact ids
    const matchedIds: string[] = [];
    let idScore = 0;
    for (const c of iq.cves) {
      if (d.cves.includes(c)) {
        matchedIds.push(c);
        idScore += W.exactCve;
      }
    }
    if (idScore > 0) {
      matchedFields.add("cves");
      parts.push({ key: "exactId", label: `Exact id (${matchedIds.join(", ")})`, value: idScore });
    }

    // --- Techniques (with parent / sub-technique expansion)
    const matchedTechniques: ResultWhy["matchedTechniques"] = [];
    let techScore = 0;
    for (const t of positiveTechniques) {
      const rel = techniqueRelation(p, t.id, t.related);
      if (!rel) continue;
      matchedTechniques.push({ id: t.id, name: t.name, relation: rel });
      const self = d.kind === "technique";
      if (self) techScore += rel === "exact" ? W.techniqueSelf : W.techniqueSelfRelated;
      else if (d.kind !== "report") techScore += rel === "exact" ? W.techniqueUses : W.techniqueUses / 2;
      else techScore += rel === "exact" ? W.techniqueExact : W.techniqueRelated;
      if (t.via === "id" && rel === "exact") matchedIds.push(t.id);
    }
    if (techScore > 0) {
      matchedFields.add("techniques");
      parts.push({ key: "technique", label: `Technique (${matchedTechniques.map((m) => (m.relation === "exact" ? m.id : `${m.id} ${m.relation}`)).join(", ")})`, value: round(techScore) });
    }

    // --- Tactics (implicit only; field tactics are filters)
    let tacticScore = 0;
    for (const t of implicitTactics) if (d.tactics.some((x) => x.toLowerCase() === t.name.toLowerCase())) tacticScore += W.tactic;
    if (tacticScore > 0) parts.push({ key: "tactic", label: "Tactic", value: round(tacticScore) });

    // --- Doc-type intent
    const intentHit = iq.docTypeIntent.filter((t) => d.docTypes.includes(t));
    if (intentHit.length) parts.push({ key: "docType", label: `Document type intent (${intentHit.join(", ")})`, value: W.docTypeIntent });

    const base = parts.reduce((a, b) => a + b.value, 0);
    // Knowledge cards must match on something beyond the words that were recognised as an entity
    // ("Cozy Bear" must not surface "Ember Bear" on the word "bear").
    // Text-only relevance needs words beyond those recognised as an entity ("Lazarus Group" must not
    // match every report on the word "group"; "Cozy Bear" must not surface "Ember Bear"), and at least
    // two words of a 3+ word query.
    const minHits = signalTerms.length >= 3 ? 2 : 1;
    const textCounts = text > 0 && freeHits > 0 && signalHits >= minHits;
    // Identifier queries (CVE ids) need an identifier match, like grounded passage selection.
    const structural = entityScore > 0 || idScore > 0 || techScore > 0;
    const relevant = (iq.cves.length > 0 ? structural : textCounts || structural) || iq.phrases.length > 0;
    if (!relevant && !iq.filterOnly) continue;
    // Knowledge cards are the answer when the query names them; matching an ATT&CK description
    // by keyword (or a structural "uses" link) ranks below library reports.
    const selfMatch = matchedEntities.some((m) => p.entityKey.has(`${m.kind}:${m.id}`) && d.entities.find((e) => e.id === m.id)?.rel === "self") || (d.kind === "technique" && matchedTechniques.length > 0);
    if (d.kind !== "report" && !selfMatch) {
      if (iq.since || iq.until) continue; // undated knowledge only answers a dated query when named
    }

    // --- Priors
    let score = iq.filterOnly && !relevant ? 1 : base;
    const mults: ScorePart[] = [];
    const conf = d.confidence ?? (d.kind === "report" ? 0.6 : 1);
    const confMult = 0.85 + 0.15 * Math.max(0, Math.min(1, conf));
    mults.push({ key: "mult:confidence", label: `Source confidence ${Math.round(conf * 100)}%`, value: round(confMult) });
    if (d.tier) mults.push({ key: "mult:tier", label: `Tier ${d.tier}`, value: TIER_MULT[d.tier] ?? 1 });
    if (d.kind === "report") {
      const q = Math.max(0, Math.min(1, d.quality ?? 0.5));
      mults.push({ key: "mult:quality", label: `Quality ${Math.round(q * 100)}%`, value: round(0.9 + 0.1 * q) });
      const ts = d.publishedAt ? Date.parse(String(d.publishedAt)) : NaN;
      if (Number.isFinite(ts)) {
        const years = Math.max(0, (now - ts) / (365.25 * 86400_000));
        mults.push({ key: "mult:recency", label: `Recency (${years < 1 ? "< 1 year" : `${Math.round(years)} yr`})`, value: round(0.9 + 0.1 * Math.exp(-years / 3)) });
      }
    }
    if (d.kind !== "report" && !selfMatch && !iq.filterOnly) mults.push({ key: "mult:knowledge", label: "ATT&CK card matched by keyword / link only", value: 0.5 });
    for (const m of mults) score *= m.value;

    out.push({
      prepared: p,
      score: round(score),
      why: {
        matchedFields: [...matchedFields],
        matchedTerms,
        matchedEntities,
        matchedTechniques,
        matchedIds: [...new Set(matchedIds)],
        docTypeIntent: intentHit.length ? intentHit : undefined,
        breakdown: [...parts, ...mults],
        score: round(score),
      },
    });
  }
  out.sort((a, b) => b.score - a.score || dateNum(b.prepared.doc.publishedAt) - dateNum(a.prepared.doc.publishedAt) || a.prepared.doc.title.localeCompare(b.prepared.doc.title));
  return out;
}

function dateNum(v: string | null | undefined): number {
  const t = v ? Date.parse(String(v)) : NaN;
  return Number.isFinite(t) ? t : 0;
}

function jaccard(a: Set<number>, b: Set<number>): number {
  if (a.size === 0 || b.size === 0) return 0;
  let inter = 0;
  const [small, big] = a.size < b.size ? [a, b] : [b, a];
  for (const x of small) if (big.has(x)) inter++;
  return inter / (a.size + b.size - inter);
}

export type CollapsedDoc = ScoredDoc & { duplicates: PreparedDoc[] };

/**
 * Collapses near-duplicates (same content hash / canonical URL, or ≥ 0.7
 * Jaccard over 5-word shingles of the opening text) into the best-scoring copy.
 */
export function collapseDuplicates(ranked: ScoredDoc[], threshold = 0.7): CollapsedDoc[] {
  const out: CollapsedDoc[] = [];
  for (const r of ranked) {
    const d = r.prepared.doc;
    const host = out.find((o) => {
      const od = o.prepared.doc;
      if (od.kind !== "report" || d.kind !== "report") return false;
      if (od.dupKey && d.dupKey && od.dupKey === d.dupKey) return true;
      return jaccard(o.prepared.shingles, r.prepared.shingles) >= threshold;
    });
    if (host) host.duplicates.push(r.prepared);
    else out.push({ ...r, duplicates: [] });
  }
  return out;
}

/**
 * Publisher diversity: greedy re-ranking where each further result from an
 * already-selected publisher is discounted (0.85^k). Order changes only; no
 * result is dropped. The discount is recorded in the breakdown.
 */
export function diversify<T extends ScoredDoc>(ranked: T[], decay = 0.85): T[] {
  const remaining = [...ranked];
  const seen = new Map<string, number>();
  const out: T[] = [];
  while (remaining.length) {
    let bestIdx = 0;
    let bestVal = -Infinity;
    for (let i = 0; i < remaining.length; i++) {
      const pub = (remaining[i].prepared.doc.publisher ?? "").toLowerCase();
      const k = pub ? seen.get(pub) ?? 0 : 0;
      const v = remaining[i].score * Math.pow(decay, k);
      if (v > bestVal + 1e-9) {
        bestVal = v;
        bestIdx = i;
      }
    }
    const pick = remaining.splice(bestIdx, 1)[0];
    const pub = (pick.prepared.doc.publisher ?? "").toLowerCase();
    const k = pub ? seen.get(pub) ?? 0 : 0;
    if (k > 0) {
      const factor = round(Math.pow(decay, k));
      pick.adjusted = round(pick.score * factor);
      pick.why = { ...pick.why, breakdown: [...pick.why.breakdown, { key: "mult:diversity", label: `Publisher diversity (${k} earlier)`, value: factor }], score: pick.adjusted };
    } else pick.adjusted = pick.score;
    if (pub) seen.set(pub, k + 1);
    out.push(pick);
  }
  return out;
}
