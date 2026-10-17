/**
 * Query understanding for intelligence search.
 *
 *   parseQuery("actor:\"Cozy Bear\" lsass dumping since:2025 -phishing")
 *     → clauses (field / phrase / word, with offsets and negation)
 *   interpretQuery(parsed)
 *     → canonical ATT&CK entities (aliases expanded), techniques (names → IDs,
 *       parent/sub expansion), tactics, CVEs, doc-type filters and intent, tiers,
 *       publishers, date range, has: flags, exclusions, removable chips and a
 *       one-line summary ("actor APT29 (G0016) · since 2025").
 *
 * Field syntax: actor: malware: campaign: technique: tactic: cve: type: tier:
 * publisher: since: until: has:(iocs|emulation|evidence), "exact phrase", -exclusion.
 * Values may be quoted (actor:"Cozy Bear") or comma lists (type:advisory,dfir).
 *
 * Server-only: uses the bundled ATT&CK snapshot.
 */
import { aliasesFor, getTechnique, isTooGenericForText, resolveEntity, type AttackEntityKind } from "../attack-knowledge.ts";
import { isLowSignal, isStopword, tokenize } from "../retrieval.ts";
import type { DocType, SourceTier } from "../types.ts";
import { matchTacticPhrase, matchTechniquePhrase, maxTechniquePhraseWords, relatedTechniques } from "./technique-index.ts";
import type {
  HasFlag,
  InterpretedChip,
  InterpretedQuery,
  ParsedQuery,
  QueryClause,
  QueryEntity,
  QueryEntityKind,
  QueryField,
  QueryTechnique,
  Span,
} from "./types.ts";

// ---------------------------------------------------------------------------
// Parsing
// ---------------------------------------------------------------------------

const FIELD_ALIASES: Record<string, QueryField> = {
  actor: "actor",
  group: "actor",
  apt: "actor",
  "threat-actor": "actor",
  malware: "malware",
  software: "malware",
  tool: "malware",
  family: "malware",
  campaign: "campaign",
  technique: "technique",
  ttp: "technique",
  tech: "technique",
  tactic: "tactic",
  cve: "cve",
  vuln: "cve",
  type: "type",
  doctype: "type",
  kind: "type",
  tier: "tier",
  publisher: "publisher",
  source: "publisher",
  vendor: "publisher",
  since: "since",
  after: "since",
  until: "until",
  before: "until",
  has: "has",
};

/** Known field names, for syntax hints and autocomplete. */
export const QUERY_FIELDS = Object.keys(FIELD_ALIASES);

const MAX_QUERY_CHARS = 500;

function isSpace(ch: string | undefined) {
  return ch === " " || ch === "\t" || ch === "\n" || ch === "\r";
}

/** Lexes the raw query into word / phrase / field clauses with exact offsets. */
export function parseQuery(input: string): ParsedQuery {
  const raw = String(input ?? "").slice(0, MAX_QUERY_CHARS);
  const clauses: QueryClause[] = [];
  const warnings: string[] = [];
  let i = 0;
  const n = raw.length;
  while (i < n) {
    while (i < n && isSpace(raw[i])) i++;
    if (i >= n) break;
    const start = i;
    let negated = false;
    if (raw[i] === "-" && i + 1 < n && !isSpace(raw[i + 1]) && raw[i + 1] !== "-") {
      negated = true;
      i++;
    }
    if (raw[i] === '"') {
      const close = raw.indexOf('"', i + 1);
      const end = close === -1 ? n : close + 1;
      const value = raw.slice(i + 1, close === -1 ? n : close).trim();
      if (value) clauses.push({ type: "phrase", value, negated, span: { start, end } });
      i = end;
      continue;
    }
    let j = i;
    while (j < n && !isSpace(raw[j]) && raw[j] !== '"') j++;
    const token = raw.slice(i, j);
    const fm = token.match(/^([a-zA-Z-]+):(.*)$/);
    const field = fm ? FIELD_ALIASES[fm[1].toLowerCase()] : undefined;
    if (fm && field) {
      let value = fm[2];
      let end = j;
      if (value === "" && raw[j] === '"') {
        const close = raw.indexOf('"', j + 1);
        end = close === -1 ? n : close + 1;
        value = raw.slice(j + 1, close === -1 ? n : close);
      }
      value = value.trim();
      if (value) clauses.push({ type: "field", field, value, negated, span: { start, end }, rawField: fm[1] });
      else warnings.push(`"${fm[1]}:" needs a value`);
      i = end;
      continue;
    }
    if (j < n && raw[j] === '"' && j === i) {
      i = j;
      continue;
    }
    const value = token.replace(/^[([{,;]+|[)\]},;?!]+$/g, "");
    if (value) clauses.push({ type: "word", value, negated, span: { start, end: j } });
    i = j;
  }
  return { raw, clauses, warnings };
}

// ---------------------------------------------------------------------------
// Value helpers
// ---------------------------------------------------------------------------

const ALL_DOC_TYPES: DocType[] = [
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
];

/** Friendly type names → DocTypes. */
const TYPE_NAMES: Record<string, DocType[]> = {
  advisory: ["THREAT_ADVISORY"],
  advisories: ["THREAT_ADVISORY"],
  "threat-advisory": ["THREAT_ADVISORY"],
  report: ["THREAT_REPORT"],
  reports: ["THREAT_REPORT"],
  threat: ["THREAT_REPORT"],
  "threat-report": ["THREAT_REPORT"],
  incident: ["INCIDENT_REPORT", "DFIR_REPORT"],
  dfir: ["DFIR_REPORT"],
  malware: ["MALWARE_REPORT"],
  vulnerability: ["VULNERABILITY_ADVISORY"],
  vuln: ["VULNERABILITY_ADVISORY"],
  cve: ["VULNERABILITY_ADVISORY"],
  campaign: ["CAMPAIGN_REPORT"],
  emulation: ["ADVERSARY_EMULATION_PLAN", "MICRO_EMULATION_PLAN"],
  "emulation-plan": ["ADVERSARY_EMULATION_PLAN"],
  micro: ["MICRO_EMULATION_PLAN"],
  "micro-emulation": ["MICRO_EMULATION_PLAN"],
  flow: ["ATTACK_FLOW"],
  "attack-flow": ["ATTACK_FLOW"],
  atomic: ["ATOMIC_TEST"],
  caldera: ["CALDERA_ABILITY"],
  purple: ["PURPLE_TEAM_REPORT"],
  "purple-team": ["PURPLE_TEAM_REPORT"],
  detection: ["DETECTION_RESEARCH"],
  hunting: ["THREAT_HUNTING_REPORT"],
  hunt: ["THREAT_HUNTING_REPORT"],
  kev: ["KEV_ENTRY"],
  group: ["MITRE_GROUP"],
  "mitre-group": ["MITRE_GROUP"],
  software: ["MITRE_SOFTWARE"],
  technique: ["MITRE_TECHNIQUE"],
};

export function docTypesForName(value: string): DocType[] {
  const k = value.trim().toLowerCase().replace(/[\s_]+/g, "-");
  if (TYPE_NAMES[k]) return TYPE_NAMES[k];
  const upper = value.trim().toUpperCase().replace(/[\s-]+/g, "_");
  return ALL_DOC_TYPES.includes(upper as DocType) ? [upper as DocType] : [];
}

/** Free-text words that signal a document-type intent (boost only). */
const INTENT_WORDS: Array<{ re: RegExp; types: DocType[]; label: string }> = [
  { re: /^advisor(y|ies)$/i, types: ["THREAT_ADVISORY"], label: "Advisory" },
  { re: /^dfir$/i, types: ["DFIR_REPORT", "INCIDENT_REPORT"], label: "DFIR" },
  { re: /^(incident|intrusion)s?$/i, types: ["INCIDENT_REPORT", "DFIR_REPORT"], label: "Incident" },
  { re: /^emulat(e|ion|ions)$/i, types: ["ADVERSARY_EMULATION_PLAN", "MICRO_EMULATION_PLAN", "PURPLE_TEAM_REPORT"], label: "Emulation" },
  { re: /^atomics?$/i, types: ["ATOMIC_TEST"], label: "Atomic test" },
  { re: /^kev$/i, types: ["KEV_ENTRY"], label: "KEV" },
  { re: /^purple$/i, types: ["PURPLE_TEAM_REPORT"], label: "Purple team" },
  { re: /^hunt(ing)?$/i, types: ["THREAT_HUNTING_REPORT"], label: "Hunting" },
  { re: /^detections?$/i, types: ["DETECTION_RESEARCH"], label: "Detection" },
  { re: /^vulnerabilit(y|ies)$/i, types: ["VULNERABILITY_ADVISORY"], label: "Vulnerability" },
];

function parseDateBound(value: string, bound: "since" | "until"): string | null {
  const v = value.trim();
  let m = v.match(/^(\d{4})$/);
  if (m) return bound === "since" ? `${m[1]}-01-01` : `${m[1]}-12-31`;
  m = v.match(/^(\d{4})-(\d{1,2})$/);
  if (m) {
    const y = Number(m[1]);
    const mo = Number(m[2]);
    if (mo < 1 || mo > 12) return null;
    if (bound === "since") return `${m[1]}-${String(mo).padStart(2, "0")}-01`;
    const last = new Date(Date.UTC(y, mo, 0)).getUTCDate();
    return `${m[1]}-${String(mo).padStart(2, "0")}-${String(last).padStart(2, "0")}`;
  }
  m = v.match(/^(\d{4})-(\d{1,2})-(\d{1,2})$/);
  if (m) {
    const d = new Date(Date.UTC(Number(m[1]), Number(m[2]) - 1, Number(m[3])));
    if (Number.isNaN(d.getTime()) || d.getUTCMonth() !== Number(m[2]) - 1) return null;
    return d.toISOString().slice(0, 10);
  }
  return null;
}

function splitList(value: string): string[] {
  return value
    .split(",")
    .map((s) => s.trim())
    .filter(Boolean);
}

/**
 * Single lowercase words that are ATT&CK names but ordinary English (or a
 * product word). They resolve when capitalised ("Snake") or via a field
 * (malware:snake), never implicitly from lowercase free text.
 */
const AMBIGUOUS_WORDS = new Set(
  (
    "mirage snake silence reaper karma wiper page rover epic crimson scorpion chaos anchor spark explosive trinity soldier " +
    "pandora meteor shark kevin james milan solar mango disco samurai ninja agenda embargo aurora avenger proton carbon " +
    "octopus cannon denis mosquito responder empire covenant mythic havoc mantis chimera leviathan cleaver axiom elfin " +
    "rattlesnake crambus spica peppy turian donut caminho pacu ruler gazer pony seasalt kazuar komplex prestige cuba"
  ).split(" "),
);

const ENTITY_KINDS: AttackEntityKind[] = ["group", "campaign", "software"];

function entityFromResolved(
  r: { kind: AttackEntityKind; id: string; name: string },
  matched: string,
  source: "field" | "implicit",
  span?: Span,
  negated?: boolean,
): QueryEntity {
  return {
    kind: r.kind as QueryEntityKind,
    id: r.id,
    name: r.name,
    matched,
    aliases: aliasesFor(r.kind, r.id),
    source,
    span,
    ...(negated ? { negated } : {}),
  };
}

function techniqueEntry(
  id: string,
  matched: string,
  via: QueryTechnique["via"],
  source: "field" | "implicit",
  span?: Span,
  negated?: boolean,
): QueryTechnique | null {
  const t = getTechnique(id);
  if (!t) return null;
  return { id: t.id, name: t.name, matched, tactics: t.tactics, via, related: relatedTechniques(t.id), source, span, ...(negated ? { negated } : {}) };
}

function removeSpan(raw: string, span: Span): string {
  return `${raw.slice(0, span.start)} ${raw.slice(span.end)}`.replace(/\s+/g, " ").trim();
}

function quoteSpan(raw: string, span: Span): string {
  const inner = raw.slice(span.start, span.end).replace(/"/g, "");
  return `${raw.slice(0, span.start)}"${inner}"${raw.slice(span.end)}`.replace(/\s+/g, " ").trim();
}

const KIND_LABEL: Record<QueryEntityKind, string> = { group: "actor", software: "software", campaign: "campaign", technique: "technique" };
const CHIP_KIND: Record<QueryEntityKind, InterpretedChip["kind"]> = { group: "actor", software: "software", campaign: "campaign", technique: "technique" };

const DOC_TYPE_LABEL: Partial<Record<DocType, string>> = {
  THREAT_REPORT: "Threat report",
  THREAT_ADVISORY: "Advisory",
  INCIDENT_REPORT: "Incident report",
  DFIR_REPORT: "DFIR report",
  MALWARE_REPORT: "Malware analysis",
  VULNERABILITY_ADVISORY: "Vulnerability advisory",
  CAMPAIGN_REPORT: "Campaign report",
  MITRE_GROUP: "ATT&CK group",
  MITRE_SOFTWARE: "ATT&CK software",
  MITRE_CAMPAIGN: "ATT&CK campaign",
  MITRE_TECHNIQUE: "ATT&CK technique",
  ADVERSARY_EMULATION_PLAN: "Emulation plan",
  MICRO_EMULATION_PLAN: "Micro emulation plan",
  ATTACK_FLOW: "Attack flow",
  ATOMIC_TEST: "Atomic test",
  CALDERA_ABILITY: "CALDERA ability",
  PURPLE_TEAM_REPORT: "Purple team report",
  DETECTION_RESEARCH: "Detection research",
  THREAT_HUNTING_REPORT: "Threat hunting",
  KEV_ENTRY: "KEV entry",
  OTHER: "Other",
};

export function docTypeLabel(t: DocType): string {
  return DOC_TYPE_LABEL[t] ?? t;
}

function displayDate(rawValue: string): string {
  return rawValue.trim();
}

// ---------------------------------------------------------------------------
// Interpretation
// ---------------------------------------------------------------------------

type WordRef = { value: string; span: Span };

/** Resolves the parsed clauses into an interpreted query (entities, techniques, filters, chips). */
export function interpretQuery(parsed: ParsedQuery): InterpretedQuery {
  const raw = parsed.raw;
  const warnings = [...parsed.warnings];
  const entities: QueryEntity[] = [];
  const techniques: QueryTechnique[] = [];
  const tactics: InterpretedQuery["tactics"] = [];
  const cves: string[] = [];
  const requiredCves: string[] = [];
  const docTypes: DocType[] = [];
  const docTypeIntent: DocType[] = [];
  const excludedDocTypes: DocType[] = [];
  const tiers: SourceTier[] = [];
  const publishers: string[] = [];
  const excludedPublishers: string[] = [];
  const has: HasFlag[] = [];
  const phrases: string[] = [];
  const excluded: string[] = [];
  const unresolved: InterpretedQuery["unresolved"] = [];
  const chips: InterpretedChip[] = [];
  const summaryParts: string[] = [];
  let since: string | undefined;
  let until: string | undefined;
  const freeWords: string[] = [];
  const consumed = new Set<string>();

  const addEntity = (e: QueryEntity) => {
    if (!entities.some((x) => x.kind === e.kind && x.id === e.id && Boolean(x.negated) === Boolean(e.negated))) entities.push(e);
  };
  const addTechnique = (t: QueryTechnique | null) => {
    if (t && !techniques.some((x) => x.id === t.id && Boolean(x.negated) === Boolean(t.negated))) techniques.push(t);
  };
  const addTactic = (name: string, source: "field" | "implicit") => {
    if (!tactics.some((t) => t.name === name)) tactics.push({ name, source });
  };
  let at = 0;
  const chipPos = new Map<string, number>();
  const chip = (c: Omit<InterpretedChip, "key">) => {
    const key = `${c.kind}:${chips.length}`;
    chipPos.set(key, at);
    chips.push({ ...c, key });
  };

  // Runs of consecutive free (non-negated) words: n-grams never cross a field or phrase.
  const runs: WordRef[][] = [];
  let current: WordRef[] = [];
  const flush = () => {
    if (current.length) runs.push(current);
    current = [];
  };

  for (const c of parsed.clauses) {
    at = c.span.start;
    if (c.type === "word") {
      if (c.negated) {
        flush();
        excluded.push(c.value);
        chip({ kind: "exclude", label: `Not ${c.value}`, implicit: false, negated: true, without: removeSpan(raw, c.span) });
        continue;
      }
      current.push({ value: c.value, span: c.span });
      freeWords.push(c.value);
      continue;
    }
    flush();
    if (c.type === "phrase") {
      if (c.negated) {
        excluded.push(c.value);
        chip({ kind: "exclude", label: `Not “${c.value}”`, implicit: false, negated: true, without: removeSpan(raw, c.span) });
      } else {
        phrases.push(c.value);
        chip({ kind: "phrase", label: `“${c.value}”`, detail: "exact phrase", implicit: false, without: removeSpan(raw, c.span) });
        summaryParts.push(`phrase “${c.value}”`);
      }
      continue;
    }
    // Field clause
    const without = removeSpan(raw, c.span);
    const neg = c.negated;
    const notPrefix = neg ? "not " : "";
    switch (c.field) {
      case "actor":
      case "malware":
      case "campaign": {
        for (const v of splitList(c.value)) {
          const kinds: AttackEntityKind[] = c.field === "actor" ? ["group", "campaign"] : c.field === "malware" ? ["software"] : ["campaign"];
          const hit = resolveEntity(v, kinds)[0];
          if (hit) {
            const e = entityFromResolved(hit, v, "field", c.span, neg);
            addEntity(e);
            const label = `${KIND_LABEL[e.kind]} ${e.name}`;
            chip({
              kind: CHIP_KIND[e.kind],
              label: `${neg ? "Not " : ""}${label.charAt(0).toUpperCase()}${label.slice(1)}`,
              detail: `${e.id}${hit.name.toLowerCase() !== v.toLowerCase() ? ` · alias ${v}` : ""}`,
              implicit: false,
              negated: neg,
              without,
            });
            summaryParts.push(`${notPrefix}${KIND_LABEL[e.kind]} ${e.name} (${e.id})`);
          } else {
            unresolved.push({ field: c.field, value: v, ...(neg ? { negated: true } : {}) });
            chip({
              kind: c.field === "malware" ? "software" : c.field === "campaign" ? "campaign" : "actor",
              label: `${neg ? "Not " : ""}${c.field === "malware" ? "Malware" : c.field === "campaign" ? "Campaign" : "Actor"} “${v}”`,
              detail: "not in ATT&CK · matched as text",
              implicit: false,
              negated: neg,
              without,
            });
            summaryParts.push(`${notPrefix}${c.field} “${v}” (text)`);
          }
        }
        break;
      }
      case "technique": {
        for (const v of splitList(c.value)) {
          let t: QueryTechnique | null = null;
          if (/^t\d{4}(\.\d{3})?$/i.test(v)) t = techniqueEntry(v.toUpperCase(), v, "id", "field", c.span, neg);
          else {
            const m = matchTechniquePhrase(v)[0];
            if (m) t = techniqueEntry(m.technique.id, v, "field", "field", c.span, neg);
          }
          if (t) {
            addTechnique(t);
            chip({ kind: "technique", label: `${neg ? "Not " : ""}${t.id}`, detail: t.name, implicit: false, negated: neg, without });
            summaryParts.push(`${notPrefix}technique ${t.id} ${t.name}`);
          } else {
            unresolved.push({ field: "technique", value: v, ...(neg ? { negated: true } : {}) });
            warnings.push(`technique:${v} is not an ATT&CK technique in the bundled snapshot; matched as text`);
            chip({ kind: "technique", label: `Technique “${v}”`, detail: "not recognised · matched as text", implicit: false, without });
          }
        }
        break;
      }
      case "tactic": {
        const name = matchTacticPhrase(c.value.replace(/[-_]/g, " "));
        if (name) {
          addTactic(name, "field");
          chip({ kind: "tactic", label: `Tactic ${name}`, implicit: false, without });
          summaryParts.push(`tactic ${name}`);
        } else warnings.push(`tactic:${c.value} is not an ATT&CK tactic`);
        break;
      }
      case "cve": {
        for (const v of splitList(c.value)) {
          const id = /^\d{4}-\d{4,7}$/.test(v) ? `CVE-${v}` : v.toUpperCase();
          if (/^CVE-\d{4}-\d{4,7}$/.test(id)) {
            if (!cves.includes(id)) cves.push(id);
            if (!requiredCves.includes(id)) requiredCves.push(id);
            chip({ kind: "cve", label: id, implicit: false, without });
            summaryParts.push(id);
          } else warnings.push(`cve:${v} is not a CVE id`);
        }
        break;
      }
      case "type": {
        for (const v of splitList(c.value)) {
          const types = docTypesForName(v);
          if (types.length === 0) {
            warnings.push(`type:${v} is not a known document type`);
            continue;
          }
          for (const t of types) {
            const list = neg ? excludedDocTypes : docTypes;
            if (!list.includes(t)) list.push(t);
          }
          const label = types.map(docTypeLabel).join(" or ");
          chip({ kind: "type", label: `${neg ? "Not " : "Type "}${label}`, implicit: false, negated: neg, without });
          summaryParts.push(`${notPrefix}type ${label}`);
        }
        break;
      }
      case "tier": {
        if (neg) {
          warnings.push("-tier: is not supported; list the tiers to keep instead (tier:1,2)");
          break;
        }
        for (const v of splitList(c.value)) {
          const n = Number(v.replace(/^t/i, ""));
          if ([1, 2, 3, 4].includes(n)) {
            if (!tiers.includes(n as SourceTier)) tiers.push(n as SourceTier);
          } else warnings.push(`tier:${v} must be 1-4`);
        }
        if (tiers.length) {
          chip({ kind: "tier", label: `Tier ${tiers.join(", ")}`, implicit: false, without });
          summaryParts.push(`tier ${tiers.join(", ")}`);
        }
        break;
      }
      case "publisher": {
        for (const v of splitList(c.value)) {
          (neg ? excludedPublishers : publishers).push(v);
          chip({ kind: "publisher", label: `${neg ? "Not " : "Publisher "}${v}`, implicit: false, negated: neg, without });
          summaryParts.push(`${notPrefix}publisher ${v}`);
        }
        break;
      }
      case "since":
      case "until": {
        const iso = parseDateBound(c.value, c.field);
        if (!iso) {
          warnings.push(`${c.field}:${c.value} must be YYYY, YYYY-MM or YYYY-MM-DD`);
          break;
        }
        if (c.field === "since") since = iso;
        else until = iso;
        const shown = displayDate(c.value);
        chip({ kind: "date", label: `${c.field === "since" ? "Since" : "Until"} ${shown}`, implicit: false, without });
        summaryParts.push(`${c.field} ${shown}`);
        break;
      }
      case "has": {
        for (const v of splitList(c.value)) {
          const k = v.toLowerCase().replace(/s$/, "");
          const flag: HasFlag | null = k === "ioc" ? "iocs" : k === "emulation" ? "emulation" : k === "evidence" ? "evidence" : null;
          if (!flag) {
            warnings.push(`has:${v} must be iocs, emulation or evidence`);
            continue;
          }
          if (!has.includes(flag)) has.push(flag);
          chip({ kind: "has", label: `Has ${flag === "iocs" ? "IOCs" : flag}`, implicit: false, without });
          summaryParts.push(`has ${flag}`);
        }
        break;
      }
    }
  }
  flush();

  // Implicit recognition over free-word runs: IDs, then longest-first n-grams.
  const implicitParts: string[] = [];
  const maxN = Math.max(5, maxTechniquePhraseWords());
  for (const run of runs) {
    let i = 0;
    while (i < run.length) {
      const w = run[i];
      const bare = w.value.replace(/[.,;:!?]+$/, "");
      const span = w.span;
      at = span.start;
      // Exact identifiers
      if (/^CVE-\d{4}-\d{4,7}$/i.test(bare)) {
        const id = bare.toUpperCase();
        if (!cves.includes(id)) cves.push(id);
        chip({ kind: "cve", label: id, detail: "exact id", implicit: true, without: quoteSpan(raw, span) });
        implicitParts.push(id);
        i++;
        continue;
      }
      if (/^T\d{4}(\.\d{3})?$/i.test(bare)) {
        const t = techniqueEntry(bare.toUpperCase(), bare, "id", "implicit", span);
        if (t) {
          addTechnique(t);
          chip({ kind: "technique", label: t.id, detail: t.name, implicit: true, without: quoteSpan(raw, span) });
          implicitParts.push(`technique ${t.id}`);
        }
        i++;
        continue;
      }
      if (/^[GSC]\d{4}$/i.test(bare)) {
        const hit = resolveEntity(bare.toUpperCase())[0];
        if (hit && hit.kind !== "technique") {
          const e = entityFromResolved(hit, bare, "implicit", span);
          addEntity(e);
          chip({ kind: CHIP_KIND[e.kind], label: `${cap(KIND_LABEL[e.kind])} ${e.name}`, detail: e.id, implicit: true, without: quoteSpan(raw, span) });
          implicitParts.push(`${KIND_LABEL[e.kind]} ${e.name} (${e.id})`);
          i++;
          continue;
        }
      }
      let consumedLen = 0;
      for (let len = Math.min(maxN, run.length - i); len >= 1 && consumedLen === 0; len--) {
        const slice = run.slice(i, i + len);
        const phrase = slice.map((x) => x.value).join(" ").replace(/[.,;:!?]+$/, "");
        const pspan: Span = { start: slice[0].span.start, end: slice[slice.length - 1].span.end };
        const lower = phrase.toLowerCase();
        // 1. Groups / campaigns / software (aliases → canonical)
        const single = len === 1;
        const singleOk =
          !single ||
          (phrase.length >= 3 &&
            !isStopword(lower) &&
            !isLowSignal(lower) &&
            !isTooGenericForText(phrase) &&
            (/\d/.test(phrase) || /[A-Z]/.test(phrase) || !AMBIGUOUS_WORDS.has(lower)));
        if (singleOk) {
          const hits = resolveEntity(phrase, ENTITY_KINDS);
          if (hits.length > 0) {
            for (const h of hits.slice(0, 2)) {
              const e = entityFromResolved(h, phrase, "implicit", pspan);
              addEntity(e);
              chip({
                kind: CHIP_KIND[e.kind],
                label: `${cap(KIND_LABEL[e.kind])} ${e.name}`,
                detail: `${e.id}${e.name.toLowerCase() !== lower ? ` · alias ${phrase}` : ""}`,
                implicit: true,
                without: quoteSpan(raw, pspan),
              });
              implicitParts.push(`${KIND_LABEL[e.kind]} ${e.name} (${e.id})`);
            }
            consumedLen = len;
            break;
          }
        }
        // 2. Techniques by name / shorthand / token cover
        const tm = matchTechniquePhrase(phrase);
        if (tm.length > 0) {
          for (const m of tm) {
            const t = techniqueEntry(m.technique.id, phrase, m.via, "implicit", pspan);
            if (!t) continue;
            addTechnique(t);
            chip({ kind: "technique", label: t.id, detail: `${t.name} · from “${phrase}”`, implicit: true, without: quoteSpan(raw, pspan) });
            implicitParts.push(`technique ${t.id}`);
          }
          consumedLen = len;
          break;
        }
        // 3. Tactics
        const tac = matchTacticPhrase(phrase);
        if (tac && (len > 1 || lower.length >= 6)) {
          addTactic(tac, "implicit");
          chip({ kind: "tactic", label: `Tactic ${tac}`, implicit: true, without: quoteSpan(raw, pspan) });
          implicitParts.push(`tactic ${tac}`);
          consumedLen = len;
          break;
        }
      }
      if (consumedLen) for (const x of run.slice(i, i + consumedLen)) for (const t of tokenize(x.value)) consumed.add(t);
      i += consumedLen || 1;
    }
  }

  // Doc-type intent from free words (boost only).
  for (const w of freeWords) {
    const intent = INTENT_WORDS.find((x) => x.re.test(w));
    if (!intent) continue;
    let added = false;
    for (const t of intent.types) {
      if (!docTypeIntent.includes(t) && !docTypes.includes(t)) {
        docTypeIntent.push(t);
        added = true;
      }
    }
    if (added) implicitParts.push(`prefers ${intent.label.toLowerCase()}`);
  }

  chips.sort((a, b) => (chipPos.get(a.key) ?? 0) - (chipPos.get(b.key) ?? 0));
  const freeText = freeWords.join(" ");
  const terms = Array.from(
    new Set([
      ...tokenize(freeText),
      ...phrases.flatMap((p) => tokenize(p)),
      ...unresolved.filter((u) => !u.negated).flatMap((u) => tokenize(u.value)),
    ]),
  );
  const keywordTerms = tokenize(freeText).filter((t) => !isLowSignal(t));

  const summary = [...summaryParts, ...implicitParts, ...(keywordTerms.length && implicitParts.length === 0 && summaryParts.length === 0 ? [`keywords ${keywordTerms.slice(0, 8).join(" ")}`] : [])]
    .filter((v, i, a) => a.indexOf(v) === i)
    .join(" · ");

  // Nothing to rank by: list the documents that pass the filters.
  const filterOnly = terms.length === 0 && phrases.length === 0;

  return {
    raw,
    terms,
    consumedTerms: terms.filter((t) => consumed.has(t)),
    phrases,
    excluded,
    entities,
    techniques,
    tactics,
    cves,
    requiredCves,
    docTypes,
    docTypeIntent,
    excludedDocTypes,
    tiers,
    publishers,
    excludedPublishers,
    since,
    until,
    has,
    unresolved,
    warnings,
    chips,
    summary,
    filterOnly,
  };
}

function cap(s: string) {
  return s.charAt(0).toUpperCase() + s.slice(1);
}

/** parseQuery + interpretQuery. */
export function understandQuery(q: string): InterpretedQuery {
  return interpretQuery(parseQuery(q));
}

/**
 * Retrieval expansion for candidate search and passage selection: the free
 * text plus every alias of the recognised entities and the names of the
 * recognised techniques. Never includes excluded / negated items.
 */
export function expansionText(iq: InterpretedQuery, opts: { maxAliases?: number } = {}): string {
  const maxAliases = opts.maxAliases ?? 8;
  const parts: string[] = [];
  for (const w of iq.raw.split(/\s+/)) if (w && !w.startsWith("-") && !/^[a-z-]+:/i.test(w)) parts.push(w.replace(/"/g, ""));
  for (const e of iq.entities) if (!e.negated) parts.push(...e.aliases.slice(0, maxAliases));
  for (const t of iq.techniques) {
    if (t.negated) continue;
    const sub = t.name.includes(": ") ? t.name.split(": ").slice(1).join(": ") : t.name;
    parts.push(sub);
  }
  for (const u of iq.unresolved) if (!u.negated) parts.push(u.value);
  return Array.from(new Set(parts)).join(" ").slice(0, 1500);
}
