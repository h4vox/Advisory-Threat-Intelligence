/**
 * Technique-name → ATT&CK ID recognition for search queries, built from the
 * bundled ATT&CK snapshot ("lsass dumping" → T1003.001, "pass the hash" →
 * T1550.002), plus tactic names and parent / sub-technique expansion.
 *
 * Three strategies, strictest first:
 *   1. exact name: the phrase equals a technique name or sub-technique name
 *   2. synonym: a small vocabulary of analyst shorthand (rdp, dcsync, mfa fatigue)
 *      mapped to IDs; entries whose ID is missing from the snapshot are dropped
 *   3. token cover: every (stemmed) word of a 2+ word phrase appears in exactly
 *      one or two technique names ("lsass dumping" ⊂ "OS Credential Dumping: LSASS Memory")
 *
 * Server-only (imports the ATT&CK snapshot).
 */
import { attackTechniques, getTechnique, TACTIC_ORDER, type AttackTechnique } from "../attack-knowledge.ts";

const STOP = new Set(
  "a an and the of or to for in on with by from via at as is are be using use used over into through".split(" "),
);

/** Light, symmetric stemmer: dumping/dumped/dumps → dump, hashes → hash, accounts → account. */
export function stem(word: string): string {
  let w = word.toLowerCase();
  if (w.length > 4 && /(?:sh|ch|x|ss)es$/.test(w)) w = w.slice(0, -2);
  else if (w.length > 4 && w.endsWith("ies")) w = `${w.slice(0, -3)}y`;
  else if (w.length > 3 && w.endsWith("s") && !w.endsWith("ss")) w = w.slice(0, -1);
  if (w.length > 5 && w.endsWith("ing")) w = w.slice(0, -3);
  else if (w.length > 5 && w.endsWith("ed")) w = w.slice(0, -2);
  return w;
}

export function normPhrase(s: string): string {
  return s
    .toLowerCase()
    .replace(/[‘’`´]/g, "'")
    .replace(/[^a-z0-9.'/ -]+/g, " ")
    .replace(/[-/]/g, " ")
    .replace(/\s+/g, " ")
    .trim();
}

function contentStems(s: string): string[] {
  return normPhrase(s)
    .split(" ")
    .filter((w) => w && !STOP.has(w))
    .map(stem);
}

/** Analyst shorthand → technique ID. Only vocabulary, never intelligence. */
const SYNONYMS: Record<string, string> = {
  "lsass dumping": "T1003.001",
  "lsass dump": "T1003.001",
  "dump lsass": "T1003.001",
  "dumping lsass": "T1003.001",
  lsass: "T1003.001",
  "credential dumping": "T1003",
  "cred dumping": "T1003",
  dcsync: "T1003.006",
  ntds: "T1003.003",
  "ntds.dit": "T1003.003",
  pth: "T1550.002",
  ptt: "T1550.003",
  kerberoast: "T1558.003",
  kerberoasting: "T1558.003",
  "asrep roasting": "T1558.004",
  "as rep roasting": "T1558.004",
  rdp: "T1021.001",
  "remote desktop": "T1021.001",
  "admin shares": "T1021.002",
  "mfa fatigue": "T1621",
  "mfa bombing": "T1621",
  "mfa spamming": "T1621",
  "push bombing": "T1621",
  "mfa push": "T1621",
  webshell: "T1505.003",
  "web shells": "T1505.003",
  webshells: "T1505.003",
  spearphishing: "T1566",
  "spear phishing": "T1566",
  vishing: "T1566.004",
  "voice phishing": "T1566.004",
  "help desk social engineering": "T1566.004",
  lolbins: "T1218",
  lolbas: "T1218",
  "ransomware encryption": "T1486",
  "data encryption": "T1486",
  "password spray": "T1110.003",
  "password spraying": "T1110.003",
  "brute forcing": "T1110",
  "dll sideloading": "T1574.001",
  "dll side loading": "T1574.001",
  sideloading: "T1574.001",
  "dll hijacking": "T1574.001",
  "uac bypass": "T1548.002",
  "token impersonation": "T1134.001",
  "token theft": "T1134.001",
  wmi: "T1047",
  "stolen credentials": "T1078",
  "compromised credentials": "T1078",
  "edge device exploitation": "T1190",
  "exploit public facing": "T1190",
  "supply chain": "T1195",
  "dns tunneling": "T1071.004",
  "dns tunnelling": "T1071.004",
  rmm: "T1219",
  "rmm tools": "T1219",
  "remote access software": "T1219",
  "disable edr": "T1685",
  "edr killing": "T1685",
  "edr killer": "T1685",
  "disable security tools": "T1685",
  "disable defender": "T1685",
  "clear event logs": "T1685.005",
  "log clearing": "T1685.005",
  "clear logs": "T1685.005",
  "shadow copy deletion": "T1490",
  "delete shadow copies": "T1490",
  vssadmin: "T1490",
  keylogger: "T1056.001",
  keylogging: "T1056.001",
  "cloud exfiltration": "T1567.002",
  "exfil to cloud": "T1567.002",
  "ssh tunneling": "T1572",
  tunneling: "T1572",
  "session cookie theft": "T1539",
  "cookie theft": "T1539",
  "golden saml": "T1606.002",
  "run keys": "T1547.001",
  "run key": "T1547.001",
  "scheduled tasks": "T1053.005",
  cron: "T1053.003",
};

/** Single words that are technique names but too generic to auto-detect in free text. */
const GENERIC_SINGLE = new Set([
  "services", "service", "software", "modify", "proxy", "screen", "exfiltration", "impact", "discovery", "execution",
  "collection", "persistence", "resources", "accounts", "malware", "tools", "domains", "server", "botnet", "code",
]);

type NameEntry = { id: string; name: string; stems: string[] };

let built: {
  exact: Map<string, string[]>;
  synonyms: Map<string, string>;
  entries: NameEntry[];
  tactics: Map<string, string>;
  maxWords: number;
} | null = null;

function build() {
  const exact = new Map<string, string[]>();
  const addExact = (k: string, id: string) => {
    const key = normPhrase(k);
    if (!key) return;
    const list = exact.get(key) ?? [];
    if (!list.includes(id)) list.push(id);
    exact.set(key, list);
  };
  const entries: NameEntry[] = [];
  let maxWords = 1;
  for (const t of attackTechniques()) {
    addExact(t.name, t.id);
    const sub = t.name.includes(": ") ? t.name.split(": ").slice(1).join(": ") : null;
    if (sub) addExact(sub, t.id);
    entries.push({ id: t.id, name: t.name, stems: contentStems(t.name) });
    maxWords = Math.max(maxWords, normPhrase(sub ?? t.name).split(" ").length);
  }
  // Ambiguous exact sub-names ("DLL", "Cron" in several parents) keep the most specific list; resolution picks the first.
  const synonyms = new Map<string, string>();
  for (const [k, id] of Object.entries(SYNONYMS)) if (getTechnique(id)) synonyms.set(normPhrase(k), id);
  const tactics = new Map<string, string>();
  for (const t of TACTIC_ORDER) tactics.set(normPhrase(t), t);
  tactics.set("c2", "Command and Control");
  tactics.set("command & control", "Command and Control");
  tactics.set("privesc", "Privilege Escalation");
  tactics.set("lateral", "Lateral Movement");
  tactics.set("recon", "Reconnaissance");
  tactics.set("exfil", "Exfiltration");
  tactics.set("defense evasion", "Defense Evasion");
  built = { exact, synonyms, entries, tactics, maxWords: Math.min(6, maxWords) };
  return built;
}

function index() {
  return built ?? build();
}

/** Parent and sub-technique ids related to a technique id. */
export function relatedTechniques(id: string): string[] {
  const up = id.toUpperCase();
  const parent = up.split(".")[0];
  const out: string[] = [];
  if (up.includes(".")) {
    if (getTechnique(parent)) out.push(parent);
  } else {
    for (const t of attackTechniques()) if (t.id.startsWith(`${up}.`)) out.push(t.id);
  }
  return out;
}

export type TechniqueMatch = { technique: AttackTechnique; via: "name" | "synonym" | "token-cover" };

/**
 * Recognise a technique from a phrase (one n-gram of the query). Returns the
 * matching techniques (usually one) or [] when the phrase is not a technique.
 */
export function matchTechniquePhrase(phrase: string, opts: { allowTokenCover?: boolean } = {}): TechniqueMatch[] {
  const idx = index();
  const key = normPhrase(phrase);
  if (!key) return [];
  const words = key.split(" ");
  const syn = idx.synonyms.get(key);
  if (syn) {
    const t = getTechnique(syn);
    return t ? [{ technique: t, via: "synonym" }] : [];
  }
  const exact = idx.exact.get(key);
  if (exact && exact.length > 0) {
    if (words.length === 1 && GENERIC_SINGLE.has(key)) return [];
    if (words.length === 1 && key.length < 5) return [];
    // Prefer the parent when a name is both (e.g. "Phishing"), then the shortest id.
    const sorted = [...exact].sort((a, b) => a.length - b.length || a.localeCompare(b));
    return sorted.slice(0, 1).map((id) => ({ technique: getTechnique(id)!, via: "name" as const }));
  }
  if (opts.allowTokenCover === false || words.length < 2) return [];
  const stems = contentStems(key);
  if (stems.length < 2) return [];
  const hits = idx.entries.filter((e) => stems.every((s) => e.stems.includes(s)));
  if (hits.length === 0 || hits.length > 3) return [];
  const best = Math.min(...hits.map((h) => h.stems.length));
  const chosen = hits.filter((h) => h.stems.length === best).slice(0, 2);
  return chosen.map((h) => ({ technique: getTechnique(h.id)!, via: "token-cover" as const }));
}

/** Tactic name for a phrase ("lateral movement" → "Lateral Movement"), or null. */
export function matchTacticPhrase(phrase: string): string | null {
  return index().tactics.get(normPhrase(phrase)) ?? null;
}

/** Longest phrase length (in words) worth trying. */
export function maxTechniquePhraseWords(): number {
  return index().maxWords;
}
