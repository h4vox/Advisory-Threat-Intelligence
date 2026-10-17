/**
 * Offline MITRE ATT&CK knowledge (techniques, groups, software, campaigns) from the bundled
 * snapshot in ./data/attack-knowledge.json (regenerate: `npm run build:attack-knowledge`).
 *
 * Used for entity resolution ("Cozy Bear" → APT29 / G0016), actor profiles, purple paths and
 * search query understanding. Server-side only: the JSON is ~700 KB, so never import this from a
 * component; call a server function instead.
 *
 * ATT&CK® content © The MITRE Corporation, used under the ATT&CK Terms of Use.
 */
import knowledge from "./data/attack-knowledge.json" with { type: "json" };

export type AttackTechnique = {
  id: string;
  name: string;
  tactics: string[];
  platforms: string[];
  dataSources: string[];
  isSubtechnique: boolean;
};
export type AttackGroup = { id: string; name: string; aliases: string[]; description: string; techniques: string[]; software: string[] };
export type AttackSoftware = {
  id: string;
  name: string;
  type: "malware" | "tool";
  aliases: string[];
  platforms: string[];
  description: string;
  techniques: string[];
};
export type AttackCampaign = {
  id: string;
  name: string;
  aliases: string[];
  description: string;
  firstSeen?: string;
  lastSeen?: string;
  groups: string[];
  techniques: string[];
  software: string[];
};

export type AttackEntityKind = "group" | "software" | "campaign" | "technique";
export type ResolvedEntity = {
  kind: AttackEntityKind;
  /** ATT&CK ID: G0016, S0154, C0024, T1059.001 */
  id: string;
  /** Canonical ATT&CK name */
  name: string;
  /** The surface form that matched (alias or name) */
  matched: string;
};

type Knowledge = {
  attackVersion: string | null;
  generatedAt: string;
  techniques: AttackTechnique[];
  groups: AttackGroup[];
  software: AttackSoftware[];
  campaigns: AttackCampaign[];
};

const K = knowledge as unknown as Knowledge;

export const ATTACK_VERSION = K.attackVersion;
export const ATTACK_SNAPSHOT_DATE = K.generatedAt;

/** ATT&CK tactic order (Enterprise, v18+ splits Defense Evasion into Stealth / Defense Impairment). */
export const TACTIC_ORDER = [
  "Reconnaissance",
  "Resource Development",
  "Initial Access",
  "Execution",
  "Persistence",
  "Privilege Escalation",
  "Defense Evasion",
  "Stealth",
  "Defense Impairment",
  "Credential Access",
  "Discovery",
  "Lateral Movement",
  "Collection",
  "Command and Control",
  "Exfiltration",
  "Impact",
] as const;

export function tacticRank(tactic: string | undefined): number {
  const i = TACTIC_ORDER.findIndex((t) => t.toLowerCase() === (tactic ?? "").toLowerCase());
  return i === -1 ? TACTIC_ORDER.length : i;
}

const techById = new Map(K.techniques.map((t) => [t.id, t]));
const groupById = new Map(K.groups.map((g) => [g.id, g]));
const softwareById = new Map(K.software.map((s) => [s.id, s]));
const campaignById = new Map(K.campaigns.map((c) => [c.id, c]));

export const attackTechniques = (): readonly AttackTechnique[] => K.techniques;
export const attackGroups = (): readonly AttackGroup[] => K.groups;
export const attackSoftware = (): readonly AttackSoftware[] => K.software;
export const attackCampaigns = (): readonly AttackCampaign[] => K.campaigns;

export function getTechnique(id: string): AttackTechnique | undefined {
  return techById.get(id.trim().toUpperCase());
}
export function getGroup(id: string): AttackGroup | undefined {
  return groupById.get(id.trim().toUpperCase());
}
export function getSoftware(id: string): AttackSoftware | undefined {
  return softwareById.get(id.trim().toUpperCase());
}
export function getCampaign(id: string): AttackCampaign | undefined {
  return campaignById.get(id.trim().toUpperCase());
}

/** Campaigns attributed to a group. */
export function campaignsForGroup(groupId: string): AttackCampaign[] {
  const id = groupId.toUpperCase();
  return K.campaigns.filter((c) => c.groups.includes(id));
}

// ---------------------------------------------------------------------------------------------
// Alias resolution
// ---------------------------------------------------------------------------------------------

/** Lowercase, unify quotes/dashes, collapse whitespace. */
export function normalizeEntityName(s: string): string {
  return s
    .normalize("NFKC")
    .toLowerCase()
    .replace(/[‘’‛`´]/g, "'")
    .replace(/[‐-―]/g, "-")
    .replace(/[^a-z0-9.'\- ]+/g, " ")
    .replace(/\s+/g, " ")
    .trim();
}

/**
 * Names that are ordinary words or generic OS utilities. They resolve when looked up exactly
 * (resolveEntity) but are never auto-detected inside free text (findEntitiesInText).
 */
const GENERIC = new Set(
  [
    "at", "net", "cmd", "ping", "ftp", "tor", "route", "arp", "reg", "sc", "ipconfig", "netstat", "systeminfo",
    "tasklist", "taskkill", "whoami", "nltest", "dsquery", "certutil", "schtasks", "esentutl", "expand", "xcopy",
    "robocopy", "wevtutil", "bitsadmin", "msiexec", "rundll32", "regsvr32", "wmic", "powershell", "psexec", "ngrok",
    "rclone", "winrar", "7-zip", "anydesk", "teamviewer", "screenconnect", "atera", "splashtop", "impacket",
    "mimikatz", "cobalt strike", "metasploit", "empire", "sliver", "bloodhound", "adfind", "advanced ip scanner",
  ].map((s) => s.toLowerCase()),
);
/** Generic words that must never be matched in prose even case-sensitively. */
const NEVER_IN_TEXT = new Set(
  [
    "at", "net", "cmd", "ping", "ftp", "route", "arp", "reg", "sc", "expand", "iron", "gold", "silver", "lotus",
    "cobalt", "magic", "storm", "hive", "royal", "play", "black", "blue", "tick", "sidewinder", "patchwork", "inception",
    "machete", "elephant", "moses", "gallium", "indrik", "wizard", "spider", "bear", "panda", "kitten", "chollima",
    "dragon", "typhoon", "blizzard", "sleet", "sandstorm", "tempest", "rain", "hail", "dust", "cloud", "flame",
    "duqu", "equation", "regin", "dark", "shadow", "ghost", "venom", "titan", "zebra", "sowbug", "molerats",
  ].map((s) => s.toLowerCase()),
);

/** Of the reasons above, which are "too generic to find in prose". Exported for tests. */
export function isTooGenericForText(alias: string): boolean {
  const n = normalizeEntityName(alias);
  if (NEVER_IN_TEXT.has(n)) return true;
  if (n.length < 3) return true;
  return false;
}

type AliasEntry = { kind: AttackEntityKind; id: string; name: string; alias: string };

const aliasIndex = new Map<string, AliasEntry[]>();
function addAlias(entry: AliasEntry) {
  const key = normalizeEntityName(entry.alias);
  if (!key) return;
  const list = aliasIndex.get(key) ?? [];
  if (!list.some((e) => e.kind === entry.kind && e.id === entry.id)) list.push(entry);
  aliasIndex.set(key, list);
}
const KIND_PRIORITY: Record<AttackEntityKind, number> = { group: 0, campaign: 1, software: 2, technique: 3 };
for (const g of K.groups) for (const a of [g.name, ...g.aliases]) addAlias({ kind: "group", id: g.id, name: g.name, alias: a });
for (const c of K.campaigns) for (const a of [c.name, ...c.aliases]) addAlias({ kind: "campaign", id: c.id, name: c.name, alias: a });
for (const s of K.software) for (const a of [s.name, ...s.aliases]) addAlias({ kind: "software", id: s.id, name: s.name, alias: a });
for (const t of K.techniques) addAlias({ kind: "technique", id: t.id, name: t.name, alias: t.name });
for (const list of aliasIndex.values()) list.sort((a, b) => KIND_PRIORITY[a.kind] - KIND_PRIORITY[b.kind]);

/**
 * Resolves one name / alias / ATT&CK ID to canonical entities (most specific kind first).
 * Exact (normalized) match only — no fuzzy guessing. Returns [] when unknown.
 */
export function resolveEntity(input: string, kinds?: AttackEntityKind[]): ResolvedEntity[] {
  const raw = input.trim();
  if (!raw) return [];
  const idMatch = raw.toUpperCase().match(/^(T\d{4}(?:\.\d{3})?|G\d{4}|S\d{4}|C\d{4})$/);
  if (idMatch) {
    const id = idMatch[1];
    const hit =
      id.startsWith("T") ? techById.get(id) && { kind: "technique" as const, name: techById.get(id)!.name }
      : id.startsWith("G") ? groupById.get(id) && { kind: "group" as const, name: groupById.get(id)!.name }
      : id.startsWith("S") ? softwareById.get(id) && { kind: "software" as const, name: softwareById.get(id)!.name }
      : campaignById.get(id) && { kind: "campaign" as const, name: campaignById.get(id)!.name };
    if (hit && (!kinds || kinds.includes(hit.kind))) return [{ kind: hit.kind, id, name: hit.name, matched: raw }];
    return [];
  }
  const list = aliasIndex.get(normalizeEntityName(raw)) ?? [];
  return list
    .filter((e) => !kinds || kinds.includes(e.kind))
    .map((e) => ({ kind: e.kind, id: e.id, name: e.name, matched: e.alias }));
}

/** All surface forms (name + aliases) for a resolved entity, for query expansion. */
export function aliasesFor(kind: AttackEntityKind, id: string): string[] {
  const e =
    kind === "group" ? groupById.get(id)
    : kind === "software" ? softwareById.get(id)
    : kind === "campaign" ? campaignById.get(id)
    : undefined;
  if (kind === "technique") {
    const t = techById.get(id);
    return t ? [t.id, t.name] : [];
  }
  return e ? [e.name, ...e.aliases] : [];
}

// Text scanning: longest-first alias patterns, built lazily and indexed by their first word.
//
// A match of an alias that starts with an ASCII letter or digit can only begin where an ASCII word
// begins in the text (the pattern requires a non-[\w-] character before it), and the text's word
// there must equal the alias's first word. So instead of running ~4,000 regexes over every document,
// the scanner walks the text's words once and tests only the aliases indexed under that word, with a
// sticky copy of the same regex (same boundaries, same case rules). Aliases that start with another
// character keep the full scan. Overlaps resolve exactly as before: longest alias first.
type Pattern = { re: RegExp; sticky: RegExp; entry: AliasEntry; order: number };
let textPatterns: Pattern[] | null = null;
let patternsByWord: Map<string, Pattern[]> | null = null;
let unindexedPatterns: Pattern[] = [];
const WORD_RE = /[A-Za-z0-9]+/g;

function escapeRe(s: string) {
  return s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}
function buildTextPatterns(): Pattern[] {
  const out: Pattern[] = [];
  for (const list of aliasIndex.values()) {
    for (const entry of list) {
      if (entry.kind === "technique") continue; // technique names are matched via IDs elsewhere
      if (isTooGenericForText(entry.alias)) continue;
      const alias = entry.alias.trim();
      // Single plain words (e.g. "Turla", "Emotet") must appear capitalised as written; multi-word or
      // alphanumeric names ("Cozy Bear", "APT29", "UNC2452") match case-insensitively.
      const singleWord = /^[A-Za-z]+$/.test(alias);
      const body = `(?<![\\w-])${escapeRe(alias)}(?![\\w-])`;
      out.push({ re: new RegExp(body, singleWord ? "g" : "gi"), sticky: new RegExp(body, singleWord ? "y" : "iy"), entry, order: 0 });
    }
  }
  out.sort((a, b) => b.entry.alias.length - a.entry.alias.length);
  const byWord = new Map<string, Pattern[]>();
  const unindexed: Pattern[] = [];
  out.forEach((p, i) => {
    p.order = i;
    const first = p.entry.alias.trim().match(/^[A-Za-z0-9]+/)?.[0];
    if (!first) {
      unindexed.push(p);
      return;
    }
    const key = first.toLowerCase();
    const list = byWord.get(key);
    if (list) list.push(p);
    else byWord.set(key, [p]);
  });
  patternsByWord = byWord;
  unindexedPatterns = unindexed;
  return out;
}

export type TextEntityHit = ResolvedEntity & { count: number; firstIndex: number };

/**
 * Finds ATT&CK groups, campaigns and software mentioned in free text (by name or alias).
 * Longer aliases win over overlapping shorter ones; generic words are skipped.
 */
export function findEntitiesInText(text: string, opts: { kinds?: AttackEntityKind[]; limit?: number } = {}): TextEntityHit[] {
  if (!text) return [];
  textPatterns ??= buildTextPatterns();
  const byWord = patternsByWord!;
  const wanted = (p: Pattern) => !opts.kinds || opts.kinds.includes(p.entry.kind);

  // 1. Candidate matches: indexed aliases at word starts, plus the few unindexed aliases.
  const found: Array<{ s: number; e: number; p: Pattern; matched: string }> = [];
  WORD_RE.lastIndex = 0;
  let w: RegExpExecArray | null;
  while ((w = WORD_RE.exec(text))) {
    const candidates = byWord.get(w[0].toLowerCase());
    if (!candidates) continue;
    for (const p of candidates) {
      if (!wanted(p)) continue;
      p.sticky.lastIndex = w.index;
      const m = p.sticky.exec(text);
      if (m) found.push({ s: w.index, e: w.index + m[0].length, p, matched: m[0] });
    }
  }
  for (const p of unindexedPatterns) {
    if (!wanted(p)) continue;
    p.re.lastIndex = 0;
    let m: RegExpExecArray | null;
    while ((m = p.re.exec(text))) found.push({ s: m.index, e: m.index + m[0].length, p, matched: m[0] });
  }

  // 2. Longest alias first (pattern order), then position; skip overlaps with spans already taken.
  found.sort((a, b) => a.p.order - b.p.order || a.s - b.s);
  const taken: Array<[number, number]> = [];
  const overlaps = (s: number, e: number) => taken.some(([a, b]) => s < b && e > a);
  const hits = new Map<string, TextEntityHit>();
  for (const f of found) {
    if (overlaps(f.s, f.e)) continue;
    taken.push([f.s, f.e]);
    const { entry } = f.p;
    const key = `${entry.kind}:${entry.id}`;
    const prev = hits.get(key);
    if (prev) {
      prev.count += 1;
      prev.firstIndex = Math.min(prev.firstIndex, f.s);
    } else {
      hits.set(key, { kind: entry.kind, id: entry.id, name: entry.name, matched: f.matched, count: 1, firstIndex: f.s });
    }
  }
  const list = [...hits.values()].sort((a, b) => b.count - a.count || a.firstIndex - b.firstIndex);
  return opts.limit ? list.slice(0, opts.limit) : list;
}

/** True when a lookup name is a generic utility/word (useful for down-weighting matches). */
export function isGenericEntityName(name: string): boolean {
  return GENERIC.has(normalizeEntityName(name));
}

// Technique prevalence: how many ATT&CK groups use each technique. A group using a
// sub-technique (T1059.001) also counts towards its parent (T1059).
let prevalenceIndex: { counts: Map<string, number>; max: number } | null = null;

export function techniquePrevalence(id: string): { groups: number; share: number } {
  if (!prevalenceIndex) {
    const counts = new Map<string, number>();
    for (const g of K.groups) {
      const ids = new Set<string>();
      for (const t of g.techniques) {
        ids.add(t);
        if (t.includes(".")) ids.add(t.split(".")[0]);
      }
      for (const t of ids) counts.set(t, (counts.get(t) ?? 0) + 1);
    }
    prevalenceIndex = { counts, max: Math.max(1, ...counts.values()) };
  }
  const groups = prevalenceIndex.counts.get(id.trim().toUpperCase()) ?? 0;
  return { groups, share: groups / prevalenceIndex.max };
}
