/**
 * Technical-depth check: does a document describe adversary activity in technical detail?
 *
 * AIE's library holds threat intelligence that analysts can emulate and detect: intrusion and
 * malware reports, campaign and actor reports with attacker behaviour, exploited-vulnerability
 * advisories, detection research. Product pages, strategy and trends pieces, opinion and guidance
 * posts and news coverage without technical detail do not belong there, even when they come from a
 * trusted publisher and mention "lateral movement" or "ransomware".
 *
 * The check reads only the article prose: lines made of links (menus, footers, "related posts",
 * resource lists) are dropped first, so a vendor's footer ("Threat Intel and Incident Response
 * Services", "Advanced Threat Prevention") cannot pass for content. It passes a document on any of:
 *   A. ATT&CK technique IDs            (T1059, T1566.001)
 *   B. two or more indicators          (hashes, defanged domains / URLs, public IP addresses)
 *   C. two or more attacker commands   (powershell -enc, rundll32, schtasks /create, curl … | sh)
 *   D. described attacker activity     (a named actor, malware or cluster with 5+ kinds of attacker
 *                                       behaviour, or 8+ kinds without a name)
 *   E. an exploited-vulnerability advisory from a CERT / government publisher (a CVE together with
 *      exploitation wording)
 * and rejects product / marketing pages and strategic or statistical pieces that have no hard
 * evidence (A–C), whatever else they mention. Calibrated on live Microsoft and Google Threat
 * Intelligence posts (technical reports vs. opinion, guidance and trends posts) and the product
 * page that reached the library.
 *
 * Pure module (no imports) so it runs under `node --test` and in the browser.
 */

export type DepthKind =
  | "technical"
  | "product_marketing"
  | "strategic"
  | "guidance_opinion"
  | "news"
  | "thin"
  | "non_english";

export type DepthStats = {
  proseWords: number;
  techniques: number;
  indicators: number;
  commands: number;
  actors: string[];
  behaviours: string[];
  cves: number;
  exploitedCveAdvisory: boolean;
  marketing: string[];
  /** Strategic / statistical wording per 1000 prose words. */
  strategicPerMille: number;
  /** Advice / opinion wording per 1000 prose words. */
  advicePerMille: number;
};

export type DepthVerdict = {
  pass: boolean;
  kind: DepthKind;
  /** 0–100: how much technical substance the document has. */
  score: number;
  /** What qualified it (empty when it failed). */
  anchors: string[];
  /** Why it failed (empty when it passed), most important first. */
  reasons: string[];
  /** ISO 639-1 code, or "und" when unknown. */
  language: string;
  stats: DepthStats;
};

export type DepthInput = {
  title: string;
  url: string;
  text: string;
  /** The page's declared language (`<html lang>`), when known. */
  htmlLang?: string | null;
};

const MAX_CHARS = 150_000;

// ---------------------------------------------------------------------------
// Prose: the article text without link-only lines
// ---------------------------------------------------------------------------

const MD_LINK = /\[([^\]]*)\]\((?:[^()\s]|\([^()\s]*\))+\)/g;

/**
 * The article prose: drops lines that consist only of links (navigation, footers, related posts,
 * resource lists) and repeated lines; keeps every line that carries its own text.
 */
export function articleProse(text: string): string {
  const out: string[] = [];
  const seen = new Set<string>();
  for (const raw of text.slice(0, MAX_CHARS).split("\n")) {
    const line = raw.trim();
    if (!line) continue;
    const withoutLinks = line.replace(MD_LINK, "").replace(/^(?:[-*•]|\d{1,3}[.)])\s*/, "").replace(/[\s|·,;:•–—-]+/g, "");
    if (withoutLinks.length <= 3 && MD_LINK.test(line)) {
      MD_LINK.lastIndex = 0;
      continue; // link-only line
    }
    MD_LINK.lastIndex = 0;
    const visible = line.replace(MD_LINK, "$1");
    const key = visible.toLowerCase();
    if (seen.has(key)) continue;
    seen.add(key);
    out.push(visible);
  }
  return out.join("\n");
}

// ---------------------------------------------------------------------------
// Language
// ---------------------------------------------------------------------------

const EN_STOPWORDS = new Set(
  "the and of to in is that for with on are as by this from was be an or which it at their they have has were been not but can its".split(" "),
);

/** Best-effort language of a text: English by stopword share, otherwise by script and diacritics. */
export function detectLanguage(text: string, htmlLang?: string | null): { lang: string; english: boolean } {
  const sample = text.slice(0, 20_000);
  const words = sample.toLowerCase().match(/[a-zà-ÿąćęłńóśźżčřšžůőű']+/g) ?? [];
  const declared = (htmlLang ?? "").toLowerCase().split(/[-_]/)[0] || "";
  if (words.length >= 40) {
    const en = words.filter((w) => EN_STOPWORDS.has(w)).length / words.length;
    if (en >= 0.12) return { lang: "en", english: true };
  }
  const has = (re: RegExp, min: number) => (sample.match(re) ?? []).length >= min;
  let lang = "";
  if (has(/[぀-ヿ]/g, 20)) lang = "ja";
  else if (has(/[가-힯]/g, 20)) lang = "ko";
  else if (has(/[一-鿿]/g, 40)) lang = "zh";
  else if (has(/[Ѐ-ӿ]/g, 40)) lang = has(/[ієїґ]/gi, 5) ? "uk" : "ru";
  else if (has(/[؀-ۿ]/g, 40)) lang = "ar";
  else if (has(/[ąćęłńśźż]/gi, 8)) lang = "pl";
  else if (has(/[čřšžůě]/gi, 8)) lang = "cs";
  else if (has(/\b(?:der|die|und|nicht|werden|mit)\b/gi, 12)) lang = "de";
  else if (has(/\b(?:les|des|est|une|dans|pour|avec)\b/gi, 12)) lang = "fr";
  else if (has(/\b(?:los|las|una|para|con|por|que)\b/gi, 14)) lang = "es";
  else if (has(/\b(?:het|een|van|niet|voor|zijn)\b/gi, 12)) lang = "nl";
  else if (has(/\b(?:della|degli|per|una|sono|con)\b/gi, 12)) lang = "it";
  else if (has(/\b(?:não|para|uma|com|dos|das)\b/gi, 12)) lang = "pt";
  if (!lang && declared && declared !== "en") lang = declared;
  if (!lang && words.length < 40) lang = declared || "und";
  if (!lang) lang = "und";
  return { lang, english: lang === "en" };
}

// ---------------------------------------------------------------------------
// Evidence (all counted in prose only)
// ---------------------------------------------------------------------------

function distinct(matches: Iterable<string>): Set<string> {
  const s = new Set<string>();
  for (const m of matches) s.add(m.trim().toLowerCase());
  return s;
}

function isPublicIpv4(ip: string): boolean {
  const o = ip.split(".").map(Number);
  if (o.length !== 4 || o.some((n) => !Number.isInteger(n) || n < 0 || n > 255)) return false;
  const [a, b] = o;
  if (a === 0 || a === 10 || a === 127 || a >= 224) return false;
  if (a === 169 && b === 254) return false;
  if (a === 172 && b >= 16 && b <= 31) return false;
  if (a === 192 && b === 168) return false;
  return !(a === 255 || o.every((n) => n === o[0]));
}

function countIndicators(prose: string): number {
  const found = new Set<string>();
  for (const m of prose.matchAll(/\b(?:[a-f0-9]{64}|[a-f0-9]{40}|[a-f0-9]{32})\b/gi)) {
    const h = m[0].toLowerCase();
    if (/^(.)\1+$/.test(h) || /^\d+$/.test(h)) continue;
    found.add(h);
  }
  for (const m of prose.matchAll(/\bhxxps?:\/\/[^\s)\]"']+/gi)) found.add(m[0].toLowerCase());
  for (const m of prose.matchAll(/\b[\w-]+(?:(?:\[\.\]|\(\.\)|\{\.\}|\[dot\])[\w-]+)+/gi)) {
    // A defanged domain has letters; digits only are part of a defanged IP, counted below.
    if (/[a-z]/i.test(m[0].replace(/\[dot\]/gi, ""))) found.add(m[0].toLowerCase());
  }
  for (const m of prose.matchAll(/(?<![\w.])(\d{1,3}(?:\.|\[\.\])\d{1,3}(?:\.|\[\.\])\d{1,3}(?:\.|\[\.\])\d{1,3})(?![\w.])/g)) {
    const ip = m[1].replace(/\[\.\]/g, ".");
    const before = prose.slice(Math.max(0, (m.index ?? 0) - 12), m.index).toLowerCase();
    if (/(?:version|ver\.?|v|build|release|firmware)\s*$/.test(before)) continue;
    if (isPublicIpv4(ip)) found.add(ip);
  }
  return found.size;
}

const COMMAND_RE =
  /(?:\bpowershell(?:\.exe)?\s+(?:-|\/)\w|\bcmd(?:\.exe)?\s+\/[ck]\s|\brundll32(?:\.exe)?\s+\S|\bregsvr32(?:\.exe)?\s+\/|\bmshta(?:\.exe)?\s+(?:https?|vbscript|javascript)|\bcertutil(?:\.exe)?\s+-\w|\bschtasks(?:\.exe)?\s+\/\w|\breg(?:\.exe)?\s+(?:add|query|save|delete)\s+\S|\bwmic\s+(?:\/\w|process|shadowcopy|os|computersystem)|\bbitsadmin\s+\/\w|\bvssadmin(?:\.exe)?\s+delete|\bnet1?\s+(?:user|group|localgroup)\s+\S|\bnltest\s+\/\w|\bwhoami\s+\/\w|\bcurl\s+(?:-[\w-]+\s+)*['"]?https?:|\bwget\s+(?:-[\w-]+\s+)*['"]?https?:|\bchmod\s+\+x\s|\b(?:ba)?sh\s+-c\s|\/bin\/(?:ba)?sh\b|\bbase64\s+(?:-d|--decode)|\bInvoke-(?:Expression|WebRequest|Mimikatz|Command|RestMethod)\b|\bIEX\s*\(|\bNew-Object\s+(?:System\.)?Net\.WebClient|\bnohup\s+\S|\bpython3?\s+-c\s|\bpsexec(?:64)?(?:\.exe)?\s+\\\\)/gi;

function countCommands(prose: string): number {
  const lines = new Set<string>();
  for (const line of prose.split("\n")) {
    COMMAND_RE.lastIndex = 0;
    if (COMMAND_RE.test(line)) lines.add(line.trim().slice(0, 200));
  }
  COMMAND_RE.lastIndex = 0;
  return lines.size;
}

const NOT_ACTORS = /^(?:MITRE|CISA|NIST|NCSC|FBI|HTTP|HTTPS|HTML|JSON|EDR|XDR|SIEM|SOAR|SASE|IDE|VPN|SSO|MFA|ROI|IDC|IAM|OAUTH|SAML|LLM|GTIG|MSRC|FORGE|CVSS|NOTE|TLP|IOCS?)$/;

const ACTOR_RE =
  /\b(?:APT ?\d{1,3}|UNC\d{3,5}|FIN\d{1,3}|TA\d{3,4}|Storm-\d{3,4}|DEV-\d{4}|TAG-\d{2,4}|UAC-\d{4}|(?:[A-Z][a-z]+ )(?:Typhoon|Blizzard|Sleet|Tempest|Sandstorm|Hail|Dust|Rain|Cyclone|Flood|Panda|Bear|Kitten|Chollima|Spider|Jackal|Leopard|Tiger|Buffalo)|Lazarus|Kimsuky|Andariel|Sandworm|Turla|Gamaredon|ShinyHunters|Scattered Spider|LockBit|BlackCat|ALPHV|Akira|Qilin|RansomHub|Black Basta|Cl0p|Clop|Conti|Emotet|QakBot|Qbot|IcedID|Pikabot|Latrodectus|Lumma(?:C2)?|RedLine|Vidar|Raccoon|AsyncRAT|Remcos|njRAT|PlugX|ShadowPad|Cobalt Strike|Sliver|Brute Ratel|Havoc|Mythic|Mimikatz|Rhadamanthys|SocGholish|GootLoader|Bumblebee|DarkGate|NetSupport)\b|\b[A-Z][A-Z0-9]{3,}(?= (?:malware|backdoor|loader|dropper|downloader|implant|stealer|ransomware|campaign|cluster|toolkit|tool|framework|webshell|botnet|RAT)\b)/g;

function findActors(prose: string): string[] {
  const out = new Set<string>();
  for (const m of prose.matchAll(ACTOR_RE)) {
    const name = m[0].trim();
    if (NOT_ACTORS.test(name.toUpperCase())) continue;
    out.add(name);
  }
  return [...out];
}

/** Kinds of attacker behaviour, roughly the ATT&CK tactics plus infrastructure and malware. */
const BEHAVIOURS: Array<[string, RegExp]> = [
  ["phishing", /\b(?:spear-?phishing|phishing (?:kits?|lures?|emails?|pages?|campaigns?|sites?)|adversary-in-the-middle|AiTM)\b/i],
  ["initial access", /\b(?:initial access (?:broker|vector|was|through|via)|gained (?:initial )?access|initial access via)\b/i],
  ["exploitation", /\b(?:exploited (?:the |a |this )?(?:vulnerabilit|flaw|CVE|bug)|exploitation of CVE|in-the-wild exploitation|exploited in the wild|actively exploited|post-exploitation|exploit chain)\b/i],
  ["execution", /\b(?:executed (?:a |the )?(?:payload|script|command|binary|shellcode)|shellcode|command-line|script(?:s)? (?:was|were) executed)\b/i],
  ["persistence", /\b(?:persistence (?:via|through|by|mechanism)|maintain(?:ed)? persistence|scheduled task|run key|startup folder|launch agent|cron job|web ?shells?|implants?)\b/i],
  ["privilege escalation", /\b(?:privilege escalation|escalated privileges|token (?:theft|impersonation)|UAC bypass)\b/i],
  ["defense evasion", /\b(?:obfuscat(?:ed|ion)|dll side-?loading|process (?:injection|hollowing)|disabl(?:ed|ing) (?:EDR|antivirus|Defender|security tools)|living off the land|LOLBins?|anti-analysis|sandbox evasion)\b/i],
  ["credential access", /\b(?:credential (?:harvesting|theft|dumping|stuffing)|harvest(?:ed|ing)? credentials|stole (?:credentials|tokens|cookies)|session (?:tokens?|cookies?) (?:theft|hijack)|LSASS|kerberoast(?:ing)?|password spray(?:ing)?|brute-?forc(?:e|ed|ing))\b/i],
  ["discovery", /\b(?:reconnaissance|enumerat(?:ed|ion) (?:of )?(?:users|hosts|the network|Active Directory|domain)|network scanning|port scan(?:ning)?)\b/i],
  ["lateral movement", /\b(?:lateral(?:ly)? mov(?:ed|ement)|PsExec|remote desktop protocol|RDP|WinRM|SMB shares?)\b/i],
  ["command and control", /\b(?:command[- ]and[- ]control|C2 (?:servers?|infrastructure|domains?|channels?|traffic|communications?)|beacon(?:ing|s)?|callback (?:domains?|servers?))\b/i],
  ["exfiltration", /\b(?:exfiltrat(?:ed|ion|e|ing)|data theft|stolen data|leak site)\b/i],
  ["impact", /\b(?:ransomware (?:deployment|payload|was deployed|encrypt)|deployed ransomware|encrypted (?:files|systems|data)|extortion|wipers?|data destruction|DDoS)\b/i],
  ["malware", /\b(?:backdoors?|loaders?|droppers?|downloaders?|infostealers?|stealers?|remote access trojans?|RATs?|rootkits?|botnets?|malware famil(?:y|ies))\b/i],
  ["infrastructure", /\b(?:infrastructure (?:used|operated|registered|hosted)|(?:domains?|servers?) (?:registered|hosted|operated) by|bulletproof hosting|VPS|proxy networks?|ORB networks?|Telegram (?:bots?|channels?))\b/i],
  ["social engineering", /\b(?:social engineering|vishing|smishing|impersonat(?:ed|ing|ion)|lures?)\b/i],
];

const MARKETING: Array<[string, RegExp]> = [
  ["request a demo", /\b(?:request|book|schedule|get) (?:a |your )?(?:free )?demo\b/i],
  ["free trial", /\b(?:free trial|start (?:your )?trial)\b/i],
  ["contact sales", /\b(?:contact (?:sales|our sales)|talk to (?:an?|our) (?:expert|specialist)|speak (?:to|with) (?:an? )?expert)\b/i],
  ["get started", /\bget started (?:today|now|with)\b/i],
  ["pricing", /\b(?:pricing|price plans?|per seat|per user per month)\b/i],
  ["datasheet", /\bdatasheets?\b/i],
  ["solution brief", /\bsolution briefs?\b/i],
  ["buyer's guide", /\bbuyer'?s guide\b/i],
  ["customers", /\b(?:trusted by|our customers|customer (?:stories|success|testimonials))\b/i],
  ["ROI", /\b(?:ROI|return on investment|total cost of ownership|business value (?:assessment|study))\b/i],
  ["capabilities & benefits", /\b(?:key (?:capabilities|features|benefits)|benefits (?:&|and) values?|capabilities (?:&|and) features)\b/i],
  ["why choose", /\bwhy choose\b/i],
  ["industry leader", /\b(?:recognized (?:by industry analysts )?as a (?:leader|leading)|named a leader|magic quadrant|forrester wave|identity security leader|market leader)\b/i],
  ["product pitch", /\b(?:our (?:platform|solution|product)s? (?:helps?|protects?|delivers?|secures?|enables?)|seamless business velocity|out-of-the-box (?:templates|policies)|single (?:management )?console)\b/i],
];

const STRATEGIC_RE =
  /\b(?:key judge?ments?|we assess|almost certainly|highly likely|realistic possibility|over the next (?:\w+ )?(?:years|months)|by 20\d\d|threat landscape|trends?|per month|year-over-year|statistics|survey|respondents|outlook|forecast|we expect|expects?|on average|percent(?:age)?|doubled|tripled)\b/gi;
const ADVICE_RE =
  /\b(?:organi[sz]ations (?:should|must|need to|can)|we recommend|best practices?|security leaders|CISOs?|boards?|roadmap|governance|maturity|blueprint|lessons|leaders should|defenders should)\b/gi;
const EXPLOITATION_RE =
  /\b(?:actively exploited|exploited in the wild|in-the-wild exploitation|under active exploitation|known exploited|exploitation (?:has been |was )?(?:observed|detected|attempts?|activity)|threat actors? (?:are |have been |were )?(?:exploiting|exploited)|post-exploitation|web ?shells?|indicators of compromise)\b/i;

const ADVISORY_PUBLISHER =
  /(^|\.)(?:cisa\.gov|us-cert\.gov|ncsc\.gov\.uk|ncsc\.nl|cyber\.gov\.au|cyber\.gc\.ca|cccs\.gc\.ca|ic3\.gov|nsa\.gov|fbi\.gov|bsi\.bund\.de|ssi\.gouv\.fr|enisa\.europa\.eu|cert\.europa\.eu|jpcert\.or\.jp|cert\.[a-z.]{2,12}|[a-z-]{2,12}-cert\.[a-z.]{2,12}|csirt\.[a-z.]{2,12})$/i;

const NEWS_PUBLISHER =
  /(^|\.)(?:cyberdaily\.au|bleepingcomputer\.com|thehackernews\.com|securityweek\.com|darkreading\.com|theregister\.com|zdnet\.com|techcrunch\.com|therecord\.media|infosecurity-magazine\.com|cybersecuritydive\.com|scmagazine\.com|helpnetsecurity\.com|csoonline\.com|itnews\.com\.au|itpro\.com|securityaffairs\.com|hackread\.com|cyberscoop\.com|wired\.com|arstechnica\.com|reuters\.com|bloomberg\.com|forbes\.com|cybernews\.com|gbhackers\.com|cybersecuritynews\.com|teiss\.co\.uk|computerweekly\.com|govinfosecurity\.com|bankinfosecurity\.com|databreaches\.net)$/i;

function hostOf(url: string): string {
  try {
    return new URL(url).hostname.replace(/^www\./, "").toLowerCase();
  } catch {
    return "";
  }
}

function perMille(re: RegExp, text: string, words: number): number {
  const n = (text.match(re) ?? []).length;
  return words > 0 ? Math.round(((n / words) * 1000) * 10) / 10 : 0;
}

/** Assesses whether a document describes adversary activity in technical detail (see the module doc). */
export function assessTechnicalDepth(input: DepthInput): DepthVerdict {
  const prose = articleProse(`${input.title ?? ""}\n${input.text ?? ""}`);
  const proseWords = (prose.match(/\S+/g) ?? []).length;
  const language = detectLanguage(prose, input.htmlLang);
  const host = hostOf(input.url ?? "");

  const techniques = distinct(prose.match(/\bT1\d{3}(?:\.\d{3})?\b/g) ?? []).size;
  const indicators = countIndicators(prose);
  const commands = countCommands(prose);
  const actors = findActors(prose);
  const behaviours = BEHAVIOURS.filter(([, re]) => re.test(prose)).map(([name]) => name);
  const cves = distinct(prose.match(/\bCVE-\d{4}-\d{4,7}\b/gi) ?? []).size;
  const exploitedCveAdvisory = cves > 0 && EXPLOITATION_RE.test(prose) && ADVISORY_PUBLISHER.test(host);
  const marketing = MARKETING.filter(([, re]) => re.test(prose)).map(([name]) => name);
  const strategicPerMille = perMille(STRATEGIC_RE, prose, proseWords);
  const advicePerMille = perMille(ADVICE_RE, prose, proseWords);

  const stats: DepthStats = {
    proseWords,
    techniques,
    indicators,
    commands,
    actors: actors.slice(0, 12),
    behaviours,
    cves,
    exploitedCveAdvisory,
    marketing,
    strategicPerMille,
    advicePerMille,
  };

  const plural = (n: number, one: string, many = `${one}s`) => `${n} ${n === 1 ? one : many}`;
  const hard: string[] = [];
  if (techniques >= 1) hard.push(plural(techniques, "ATT&CK technique ID"));
  if (indicators >= 2) hard.push(plural(indicators, "indicator"));
  if (commands >= 2) hard.push(plural(commands, "attacker command"));
  const anchors = [...hard];
  const activity = (actors.length >= 1 && behaviours.length >= 5) || behaviours.length >= 8;
  if (activity) {
    anchors.push(
      actors.length
        ? `attacker activity by ${actors.slice(0, 3).join(", ")} (${behaviours.length} behaviours)`
        : `attacker activity (${behaviours.length} behaviours)`,
    );
  }
  if (exploitedCveAdvisory) anchors.push(`${plural(cves, "exploited CVE")} in a ${host} advisory`);

  const score = Math.min(
    100,
    Math.min(30, techniques * 6) +
      Math.min(25, indicators * 2) +
      Math.min(20, commands * 4) +
      Math.min(10, actors.length * 3) +
      Math.min(25, behaviours.length * 3) +
      (exploitedCveAdvisory ? 15 : 0),
  );

  const verdict = (pass: boolean, kind: DepthKind, reasons: string[]): DepthVerdict => ({
    pass,
    kind,
    score,
    anchors: pass ? anchors : [],
    reasons: pass ? [] : reasons,
    language: language.lang,
    stats,
  });

  // Hard evidence beats everything; otherwise pages built to sell or to summarise trends are out.
  if (!hard.length) {
    if (marketing.length >= 4) {
      return verdict(false, "product_marketing", [`Product or marketing page (${marketing.slice(0, 4).join(", ")})`, "No attacker techniques, indicators or commands"]);
    }
    if (strategicPerMille >= 4) {
      return verdict(false, "strategic", ["Strategic assessment or trends piece: no attacker techniques, indicators or commands"]);
    }
  }
  if (anchors.length) return verdict(true, "technical", []);

  if (!language.english) {
    return verdict(false, "non_english", [`Not in English (${language.lang}): needs translation before it can be evaluated`]);
  }
  if (NEWS_PUBLISHER.test(host)) {
    return verdict(false, "news", ["News coverage without technical detail (no techniques, indicators, commands or described attacker activity)"]);
  }
  if (advicePerMille >= 5) {
    return verdict(false, "guidance_opinion", ["Guidance or opinion piece: describes no specific attacker activity, techniques or indicators"]);
  }
  return verdict(false, "thin", [
    "No technical detail: no ATT&CK techniques, indicators, attacker commands, exploited-vulnerability details or described attacker activity",
  ]);
}
