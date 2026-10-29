/**
 * Evidence-backed heuristic analyzer (Phase 3).
 *
 * Every fact this module produces (technique, actor, malware, targeting,
 * relationship, chain step) carries the exact sentence(s) that support it,
 * with character offsets into the analysed text, and a label saying how the
 * sentence relates to adversary activity (observed / inferred / defensive /
 * negated / hypothetical / reference). Only observed or inferred statements
 * count as adversary activity; everything else is kept for analyst review.
 *
 * This file must stay dependency-free (no path aliases, no runtime imports)
 * so it can be loaded directly by `node --experimental-strip-types --test`.
 */
import type {
  ChainStepEvidence,
  Evidence,
  EvidenceLabel,
  EvidencedValue,
  IntelEvidence,
  RelationshipFact,
  TargetingFact,
  TechniqueFact,
} from "./types.ts";

// ---------------------------------------------------------------------------
// Sentences & sections
// ---------------------------------------------------------------------------

export type Sentence = { text: string; start: number; end: number };

/** Bullet / list markers stripped from the start of a line (never part of a quote). */
const LEADING_MARKER = /^(?:[\s\u00a0]|[•·▪●◦‣■□►▶✓✔]|[-*–—+](?=\s)|\(?\d{1,2}[.)](?=\s)|\(?[a-z][.)](?=\s))+/;

/** Tokens before a period that do not end a sentence. */
const ABBREVIATION = /(?:^|[\s(])(?:e\.g|i\.e|etc|vs|inc|ltd|corp|co|no|nos|fig|figs|mr|mrs|ms|dr|st|approx|al|jan|feb|mar|apr|jun|jul|aug|sep|sept|oct|nov|dec|u\.s|u\.k|[A-Z])$/i;

/**
 * Split text into sentences with exact offsets. Lines are hard boundaries
 * (bullets, headings, code lines); within a line we split on . ! ? followed
 * by whitespace and an upper-case/digit/quote/bracket start, and on inline
 * bullet characters. Each returned `text` equals `input.slice(start, end)`.
 */
export function splitSentences(text: string): Sentence[] {
  const out: Sentence[] = [];
  const push = (s: number, e: number) => {
    while (s < e && /\s/.test(text[s])) s++;
    while (e > s && /\s/.test(text[e - 1])) e--;
    // Strip leading list markers inside the piece too (inline "• item").
    const lead = LEADING_MARKER.exec(text.slice(s, e));
    if (lead) s += lead[0].length;
    while (e > s && /\s/.test(text[e - 1])) e--;
    if (e - s < 2) return;
    if (!/[A-Za-z0-9]/.test(text.slice(s, e))) return;
    out.push({ text: text.slice(s, e), start: s, end: e });
  };

  const lineRe = /[^\n\r]+/g;
  let lm: RegExpExecArray | null;
  while ((lm = lineRe.exec(text))) {
    const lineStart = lm.index;
    const lineEnd = lm.index + lm[0].length;
    let pieceStart = lineStart;
    const line = lm[0];
    // Boundaries: sentence punctuation + whitespace, or an inline bullet glyph.
    const bRe = /([.!?]+["'”’)\]]*)(\s+)(?=["'“‘([]?[A-Z0-9•])|\s[•▪●◦‣]\s/g;
    let bm: RegExpExecArray | null;
    while ((bm = bRe.exec(line))) {
      if (bm[1]) {
        const punctAbs = lineStart + bm.index;
        const before = text.slice(Math.max(pieceStart, punctAbs - 12), punctAbs);
        if (bm[1] === "." && ABBREVIATION.test(before)) continue;
        push(pieceStart, punctAbs + bm[1].length);
        pieceStart = punctAbs + bm[1].length;
      } else {
        push(pieceStart, lineStart + bm.index);
        pieceStart = lineStart + bm.index + 1;
      }
    }
    push(pieceStart, lineEnd);
  }
  return out;
}

export type Section = { heading: string; start: number };

const SMALL_WORDS = new Set(["a", "an", "and", "as", "at", "by", "for", "from", "in", "into", "of", "on", "or", "the", "to", "vs", "via", "with", "&", "/", "-"]);
const NOT_HEADING = /^(?:figure|fig\.|table|image|source|photo|written by|posted|published|share|link copied|tags|contact|read|learn|download|explore|subscribe|sign up|view|get|watch|see|follow|visit|register)\b|[↗→»]/i;

function isTitleCase(words: string[]): boolean {
  const significant = words.filter((w) => !SMALL_WORDS.has(w.toLowerCase()));
  if (significant.length === 0) return false;
  const caps = significant.filter((w) => /^[A-Z0-9("'“]/.test(w)).length;
  return caps / significant.length >= 0.6;
}

/**
 * Conservative heading detection. A line is a heading when it is a markdown
 * heading (`#`), or short (≤ 10 words, ≤ 90 chars), starts upper-case, has
 * no terminal sentence punctuation, is not a bullet, and is either
 * title-cased or a short sentence-case line followed by a paragraph.
 */
export function detectSections(text: string): Section[] {
  const lines: Array<{ raw: string; start: number }> = [];
  const lineRe = /[^\n\r]+/g;
  let m: RegExpExecArray | null;
  while ((m = lineRe.exec(text))) lines.push({ raw: m[0], start: m.index });

  const sections: Section[] = [];
  for (let i = 0; i < lines.length; i++) {
    const { raw, start } = lines[i];
    const lead = raw.length - raw.trimStart().length;
    const t = raw.trim();
    if (!t) continue;
    const md = /^(#{1,6})\s+(.+?)\s*#*$/.exec(t);
    if (md) {
      sections.push({ heading: md[2], start: start + lead });
      continue;
    }
    if (t.length > 90 || t.length < 3) continue;
    if (/^[•·▪●◦‣\-*–—+]/.test(t)) continue;
    if (!/^[A-Z]/.test(t)) continue;
    if (/[.,;:!?]$/.test(t)) continue;
    if (NOT_HEADING.test(t)) continue;
    if (/[=|{}<>$\\]|\/\/|https?:/.test(t)) continue;
    if (/^\w+ \d{1,2}, \d{4}$/.test(t)) continue; // dates
    if (/\.\s/.test(t)) continue; // contains a sentence break
    const words = t.split(/\s+/);
    if (words.length > 10) continue;
    let ok = isTitleCase(words);
    if (!ok && words.length <= 6) {
      // Sentence-case heading ("Mitigation and protection guidance"):
      // accept when the next non-empty, non-bullet line is a paragraph.
      for (let j = i + 1; j < lines.length && j < i + 4; j++) {
        const n = lines[j].raw.trim();
        if (!n || /^[•·▪●◦‣]$/.test(n)) continue;
        ok = n.length >= 80 && /[.!?:]["'”’)]?$/.test(n);
        break;
      }
    }
    if (ok) sections.push({ heading: t, start: start + lead });
  }
  return sections;
}

// ---------------------------------------------------------------------------
// Sentence classification rules (precision over recall)
// ---------------------------------------------------------------------------

/**
 * Version of the labelling rules below. Bump when they change: stored reports whose evidence was
 * built with older rules are re-labelled in the background (mongodb/intel-refresh-repo).
 */
export const EVIDENCE_RULES_VERSION = 2;

/** Headings whose content is defender advice / detection content. */
export const DEFENSIVE_HEADING =
  /mitigat|recommend|remediat|harden|detection|detections|detecting|hunting|hunt for|defen[cs]|guidance|protect|best practice|response actions|security controls|containment|prevent|playbook|advanced hunting|queries/i;

/**
 * Headings that name attacker activity although they contain a defensive word: the ATT&CK tactic
 * "Defense Evasion", "Impair Defenses", "Evading detection" … Content under them is adversary activity.
 */
const ADVERSARY_HEADING = /defen[cs]e evasion|impair\w* (?:\w+ )?defen[cs]es|evad\w*|evasion|bypass\w*|anti-?(?:analysis|detection|forensics?)|disabl\w* (?:\w+ )?(?:defen[cs]es|security|edr|antivirus)|att&?ck (?:techniques|mapping|ttps)|mitre att&?ck|techniques? (?:observed|used)/i;

/**
 * A row of the report's own ATT&CK mapping table: a technique ID, its name, then what the actor did
 * ("T1140 Deobfuscate/Decode Files or Information | cook.py decodes … at runtime"). The vendor's
 * own mapping of observed activity, whatever section it sits in.
 */
const TECHNIQUE_MAPPING_ROW = /^\s*(?:[-•*]\s*)?(?:\|\s*)?(?:[A-Z][A-Za-z ]{2,30}\s*\|\s*)?T\d{4}(?:\.\d{3})?\b[^|\n]{0,140}(?:\||\s[–—-]\s|\t)\s*\S/;
const ROW_NEGATED = /^\s*(?:not (?:observed|seen|confirmed)|no (?:evidence|indication)|n\/a)\b/i;

/** Headings that end an inherited defensive context (back to report narrative). */
const NARRATIVE_HEADING =
  /^(?:introduction|background|overview|summary|executive summary|conclusion|outlook|indicators|iocs?\b|appendix|acknowledg|references|about|technical (?:analysis|details)|analysis|attribution|victimology|timeline|threat actor|campaign)|lifecycle|attack chain|initial access|^execution$|^persistence$|privilege escalation|defense evasion|credential access|^discovery$|lateral movement$|^collection$|command and control|exfiltration|^impact$|malware analysis/i;

/** Detection-rule syntax (Sigma / YARA / KQL / Snort / ATT&CK mapping fields inside rules). */
export const RULE_SYNTAX: RegExp[] = [
  /^\s*(?:title|id|status|description|author|date|modified|logsource|product|service|category|detection|selection\w*|filter\w*|condition|fields|falsepositives|level|tags|references|meta|strings|technique|tactic|mitre_\w+|rule_name|severity)\s*[:=]/i,
  /^\s*rule\s+\w+\s*(?::\s*[\w ]+)?\{?\s*$/i, // YARA rule header
  /^\s*\$\w*\s*=\s*["'{/]/, // YARA strings
  /^\s*\|\s*(?:where|project|summarize|extend|join|distinct|take|top|sort|order|parse|mv-expand|count)\b/i, // KQL pipe
  /\b(?:DeviceProcessEvents|DeviceNetworkEvents|DeviceFileEvents|DeviceLogonEvents|DeviceRegistryEvents|SecurityEvent|SigninLogs|AuditLogs|CommonSecurityLog|IdentityLogonEvents)\b/,
  /\w+\|(?:contains|endswith|startswith|re|all|base64offset|windash|cidr)\b/i, // Sigma field modifiers
  /\b(?:has_any|has_all|has_cs|matches regex)\b/i, // KQL operators
  /^\s*(?:alert|drop)\s+(?:tcp|udp|http|tls|dns|ip)\b/i, // Snort/Suricata
  /^\s*(?:condition|strings|meta)\s*:/i,
];

/** Negation: the source says it did NOT happen or there is no evidence. */
export const NEGATION: RegExp[] = [
  /\bno (?:definitive |direct |clear |conclusive )?(?:evidence|indications?|signs?|trace)\b/i,
  /\b(?:did|does|do) not\b|\b(?:didn|doesn|don)[’']t\b/i,
  /\b(?:could|can) ?not (?:find|confirm|determine|identify|verify|attribute|establish)\b/i,
  /\bcouldn[’']t (?:find|confirm|determine|identify)\b/i,
  /\b(?:was|were|has not been|have not been|is not|are not) (?:not )?(?:observed|seen|identified|confirmed|detected)\b/i,
  /\bnot (?:been )?(?:observed|seen|identified|confirmed)\b/i,
  /\bunable to (?:confirm|determine|identify|find|verify|attribute)\b/i,
  /\bwithout (?:any )?evidence\b|\bno indication\b|\bnone of\b/i,
];

/** Strong hypothetical: examples, conditionals about an attacker, generic abuse capability. */
const HYPOTHETICAL_STRONG: RegExp[] = [
  /\bif (?:an?|the) (?:attacker|adversary|threat actor|actor|intruder)s?\b/i,
  /\bfor (?:example|instance)\b|\be\.g\.,? an attacker\b/i,
  /\b(?:can|could|may|might) be (?:used|abused|leveraged|exploited|weaponized)\b/i,
  /\bhypothetical(?:ly)?\b|\bin theory\b/i,
];

/** Weak hypothetical: modal verbs (lower-case only, so the month "May" is ignored). */
const HYPOTHETICAL_WEAK: RegExp[] = [/\b(?:could|may|might|would|can|potentially|possibly|possible)\b/];

/** ATT&CK / background boilerplate rather than this incident. */
export const REFERENCE: RegExp[] = [
  /\bMITRE ATT&CK (?:defines|describes|states)\b/i,
  /\bis an? (?:ATT&CK )?(?:technique|sub-technique|tactic)\b/i,
  /\badversaries (?:may|can|often|commonly|frequently)\b/i,
  /\bthis (?:sub-)?technique (?:is|involves|describes)\b/i,
  /\b(?:is|are) (?:commonly|often|frequently|widely) (?:used|abused) by (?:threat actors|attackers|adversaries)\b/i,
];

/** Advice addressed to defenders (imperative or "X should"). */
const IMPERATIVE_VERBS =
  "block|enable|disable|enforce|restrict|review|monitor|implement|ensure|remove|revoke|validate|deny|require|limit|configure|consider|apply|patch|update|upgrade|audit|rotate|reset|isolate|segment|segregate|harden|prioriti[sz]e|investigate|hunt|search|look|identify|detect|alert|prevent|protect|deploy|use|utili[sz]e|avoid|educate|train|establish|maintain|enroll|turn|mitigate|inventory|baseline|scan|check|verify|centrali[sz]e|retain|create|define|document|reduce|minimi[sz]e|add|follow|adopt|leverage|run|investigate|disconnect|quarantine|reimage|rebuild|refer|contact|report|lock|treat|allow|keep|educate";
const IMPERATIVE_START = new RegExp(
  `^(?:(?:additionally|also|then|next|finally|where possible|if possible|whenever possible),?\\s+)?(?:${IMPERATIVE_VERBS})\\b(?!\\s+(?:of|by|was|were|is|are|has|had)\\b)(?!-)`,
  "i",
);
const GERUND_ADVICE_START =
  /^(?:turning (?:on|off)|enabling|implementing|blocking|disabling|enforcing|restricting|requiring|limiting|configuring|deploying|monitoring for|reviewing|applying|patching|hardening|auditing|rotating) /i;

const DEFENSIVE_STRONG: RegExp[] = [
  /\b(?:organi[sz]ations|customers|defenders|administrators|admins|security teams|network defenders|enterprises|users|you|we)\s+(?:should|must|are (?:strongly )?(?:encouraged|advised|urged))\b/i,
  /\b(?:organi[sz]ations|customers|defenders|administrators|security teams|you)\s+can\s+(?:use|enable|block|detect|hunt|monitor|mitigate|reduce|protect|prevent|harden)\b/i,
  /\bwe (?:strongly )?(?:recommend|advise|encourage|suggest)\b|\b(?:is|are) (?:strongly )?recommended\b|\brecommends? (?:that|to|using|enabling|blocking|organi)/i,
  /\bencourages? (?:organi[sz]ations|customers|defenders)\b/i,
  /\b(?:organi[sz]ations|customers|users|administrators|defenders|enterprises)\b[^.]{0,80}\b(?:should|must)\b/i,
  /\bbest practices?\b|\bit is (?:important|advisable|critical|crucial|essential) to\b/i,
  /\bshould (?:be )?(?:configured|enabled|blocked|disabled|restricted|monitored|reviewed|patched|updated|considered|implemented|enforced|audited|rotated)\b/i,
  /\b(?:Microsoft Defender|Defender for (?:Endpoint|Identity|Office 365|Cloud)|Defender XDR|Defender Antivirus|Microsoft Sentinel|Google SecOps|Chronicle|Mandiant Security Validation)\b.{0,40}\b(?:detects?|blocks?|alerts?|identif(?:y|ies)|can|customers|flags?)\b/i,
];

/** Weak defensive vocabulary: only applies when nothing marks the sentence as adversary activity. */
const DEFENSIVE_WEAK =
  /\b(?:mitigat\w*|detect(?:s|ion|ions|ing)?|hunt(?:s|ing)?|harden\w*|remediat\w*|prevent\w*|protect(?:s|ion|ions)?|block(?:s|ing)?|enforc\w*|recommend\w*|safeguards?|countermeasures?|guidance)\b/i;
/** Adversary phrases containing defensive words, removed before the weak check. */
const ADVERSARY_DEFENSIVE_PHRASES =
  /\b(?:evad\w* (?:\w+ )?detection|avoid\w* detection|defen[cs]e evasion|impair\w* defen[cs]es|undetected|to prevent (?:recovery|forensic|analysis|logging))\b/gi;

/** Generic adversary subjects for the "past-tense actor action" rule. */
const ACTOR_SUBJECT =
  "(?:(?:the|this|these|that|an?)\\s+)?(?:threat\\s+)?(?:actors?|attackers?|adversar(?:y|ies)|intruders?|operators?|hackers?|threat group|group|cluster|they|UNC\\d{3,4}|APT ?\\d{1,3}|FIN\\d{1,3}|TA\\d{3,4}|Storm-\\d{4}|DEV-\\d{4}|[A-Z][a-z]+ (?:Typhoon|Blizzard|Sandstorm|Sleet|Tempest|Hail|Cyclone|Tsunami|Spider|Panda|Bear|Kitten|Chollima)|ransomware operators|affiliates?)";
const IRREGULAR_PAST =
  "ran|stole|wrote|made|took|sent|built|set|put|began|found|gave|got|kept|left|brought|sought|hid|struck|spread|became|held|led|drew|chose|knew|broke|sold|bought|dumped|used|abused";
const MODAL_GAP = "(?!(?:should|must|can|cannot|could|may|might|would|will|to|not|if)\\b)";
const PAST_ACTOR_ACTION = new RegExp(
  `\\b${ACTOR_SUBJECT}\\b(?:\\s+${MODAL_GAP}[\\w'’-]+){0,4}?\\s+(?:${IRREGULAR_PAST}|[a-z]{3,}ed)\\b`,
);
/** Present-tense narrative about the adversary ("the group uses KICKPLATE to …"). */
const PRESENT_ACTOR_ACTION = new RegExp(
  `\\b${ACTOR_SUBJECT}\\b(?:\\s+(?:also|then|often|frequently|typically|commonly|subsequently|later))?\\s+(?:uses|employs|leverages|deploys|executes|abuses|exploits|installs|runs|creates|drops|steals|exfiltrates|moves|targets|relies|issues|attempts|establishes|modifies|disables|clears|dumps|accesses|obtains|gains|launches|downloads|uploads|connects|use|employ|leverage|deploy|execute|abuse|exploit|install|run|create|drop|steal|exfiltrate|move|target|rely|issue|attempt|establish|modify|disable|clear|dump|access|obtain|gain|launch|download|upload|connect)\\b`,
);
const OBSERVED_CUES: RegExp[] = [
  /\b(?:we|mandiant|microsoft|gtig|investigators|researchers|analysts|responders|[A-Z][A-Za-z]+ (?:Threat Intelligence|Incident Response)) (?:have |has )?(?:observed|identified|found|discovered|saw|uncovered|attribute[sd]?|tracked)\b/i,
  /\b(?:was|were|been|has been|have been) (?:observed|seen|identified|used|deployed|executed|leveraged|exploited|installed|compromised|targeted)\b/i,
];

export type SentenceInfo = Sentence & {
  label: EvidenceLabel;
  section?: string;
  /** True when the sentence is (part of) detection-rule syntax. */
  isRule: boolean;
  /** True when the sentence is itself a detected heading line. */
  isHeading: boolean;
};

const anyMatch = (rules: RegExp[], s: string) => rules.some((r) => r.test(s));

/** True when the sentence is detection-rule syntax. */
export function isRuleSyntax(sentence: string): boolean {
  return anyMatch(RULE_SYNTAX, sentence);
}

/** True when the sentence narrates adversary activity (past tense, present-tense narrative, or "we observed"). */
export function hasPastActorAction(sentence: string): boolean {
  return PAST_ACTOR_ACTION.test(sentence) || PRESENT_ACTOR_ACTION.test(sentence) || anyMatch(OBSERVED_CUES, sentence);
}

/**
 * Label one sentence. Order matters:
 *  1. rule syntax / defensive section     → defensive
 *  2. negation                             → negated
 *  3. strong hypothetical / ATT&CK boilerplate → hypothetical / reference
 *  4. defender advice (imperative, "organizations should", vendor detections) → defensive
 *  5. past-tense adversary action          → observed (beats the weak cues below,
 *     so "attackers disabled Windows Defender" stays observed)
 *  6. weak defensive vocabulary            → defensive
 *  7. weak modal verbs                     → hypothetical
 *  8. otherwise                            → observed
 */
export function classifySentence(sentence: string, sectionHeading?: string): EvidenceLabel {
  const s = sentence.trim();
  if (isRuleSyntax(s)) return "defensive";
  // The report's own technique mapping row is observed activity; a side clause ("returned
  // credentials were not confirmed") does not negate it, only a row that says so does.
  if (TECHNIQUE_MAPPING_ROW.test(s)) {
    const desc = s.split(/\||\s[–—-]\s|\t/).slice(1).join(" ");
    return ROW_NEGATED.test(desc) ? "negated" : "observed";
  }
  if (sectionHeading && DEFENSIVE_HEADING.test(sectionHeading)) {
    // "Defense Evasion" (an ATT&CK tactic) and similar headings describe the attacker.
    const own = sectionHeading.split(" › ").pop() ?? sectionHeading;
    if (!ADVERSARY_HEADING.test(own)) return "defensive";
  }
  if (anyMatch(NEGATION, s)) return "negated";
  if (anyMatch(REFERENCE, s)) return "reference";
  if (anyMatch(HYPOTHETICAL_STRONG, s)) return "hypothetical";
  if (IMPERATIVE_START.test(s) || GERUND_ADVICE_START.test(s) || anyMatch(DEFENSIVE_STRONG, s)) return "defensive";
  if (hasPastActorAction(s)) return "observed";
  if (DEFENSIVE_WEAK.test(s.replace(ADVERSARY_DEFENSIVE_PHRASES, " "))) return "defensive";
  if (anyMatch(HYPOTHETICAL_WEAK, s)) return "hypothetical";
  return "observed";
}

const META_SENTENCE = /\b(?:this (?:blog|post|report|article)|in this (?:blog|post|report)|we (?:share|detail|provide|outline)|we are sharing|at the end of|read more|learn more)\b|:\s*$/i;

/**
 * A defensive sentence usable as a mitigation: defender advice that is either
 * inside a defensive section or explicitly addressed to defenders. Imperative
 * lines elsewhere are not enough (reports list adversary actions in that form).
 */
export function isMitigationSentence(s: SentenceInfo): boolean {
  if (s.label !== "defensive" || s.isRule || s.isHeading) return false;
  const t = s.text.trim();
  if (t.length < 20 || t.length > 300 || !/[a-z]{3,} [a-z]{2,}/.test(t) || META_SENTENCE.test(t)) return false;
  const inDefensiveSection = !!s.section && DEFENSIVE_HEADING.test(s.section);
  const advice = IMPERATIVE_START.test(t) || GERUND_ADVICE_START.test(t) || anyMatch(DEFENSIVE_STRONG, t);
  return (inDefensiveSection && advice) || anyMatch(DEFENSIVE_STRONG, t);
}

/** Looks like a prose sentence (used to end a detection-rule block). */
function looksLikeProse(s: string): boolean {
  return /[a-z]{2,}\s+[a-z]{2,}\s+[a-z]{2,}/.test(s) && /[.!?]["'”’)]?$/.test(s) && !/[{}=|$]/.test(s);
}

/**
 * Split + label every sentence, tracking sections. Defensive context is
 * inherited by sub-headings (e.g. "Identity" under "Hardening
 * Recommendations") until a narrative heading resets it, and rule syntax
 * continues over adjacent non-prose lines (multi-line Sigma/YARA/KQL).
 */
export function labelSentences(text: string, sections: Section[] = detectSections(text)): SentenceInfo[] {
  const sentences = splitSentences(text);
  // Effective heading per section: inherited defensive parent is prefixed.
  const effective: string[] = [];
  let defensiveParent: string | null = null;
  for (const sec of sections) {
    if (DEFENSIVE_HEADING.test(sec.heading)) {
      defensiveParent = sec.heading;
      effective.push(sec.heading);
    } else if (defensiveParent && !NARRATIVE_HEADING.test(sec.heading)) {
      effective.push(`${defensiveParent} › ${sec.heading}`);
    } else {
      defensiveParent = null;
      effective.push(sec.heading);
    }
  }
  const headingStarts = new Set(sections.map((s) => s.start));

  const out: SentenceInfo[] = [];
  let si = -1;
  let prevRule = false;
  let prevEnd = -1;
  for (const sent of sentences) {
    while (si + 1 < sections.length && sections[si + 1].start <= sent.start) si++;
    const section = si >= 0 ? effective[si] : undefined;
    const isHeading = headingStarts.has(sent.start);
    // Rule continuation: previous sentence was rule syntax, nothing but whitespace between, not prose.
    const gap = prevEnd >= 0 ? text.slice(prevEnd, sent.start) : "";
    const contiguous = prevEnd >= 0 && /^\s*$/.test(gap) && (gap.match(/\n/g)?.length ?? 0) <= 2;
    const isRule: boolean = isRuleSyntax(sent.text) || (prevRule && contiguous && !looksLikeProse(sent.text));
    const label: EvidenceLabel = isRule ? "defensive" : classifySentence(sent.text, section);
    out.push({ ...sent, label, section, isRule, isHeading });
    prevRule = isRule;
    prevEnd = sent.end;
  }
  return out;
}

// ---------------------------------------------------------------------------
// Technique keyword table (moved from attack-chain.ts; regex bugs fixed)
// ---------------------------------------------------------------------------

export type TechniqueRule = { id: string; name: string; tactic: string; pattern: RegExp };

/**
 * Build a case-insensitive alternation with boundaries that work for
 * alternatives starting/ending in non-word characters (".bat", "-enc", "admin$").
 */
function kw(...alts: string[]): RegExp {
  const parts = alts.map((a) => `${/^[A-Za-z0-9]/.test(a) ? "(?<![A-Za-z0-9_])" : ""}(?:${a})(?![A-Za-z0-9_])`);
  return new RegExp(parts.join("|"), "i");
}

export const TECHNIQUE_RULES: TechniqueRule[] = [
  // Initial Access
  { id: "T1190", name: "Exploit Public-Facing Application", tactic: "Initial Access", pattern: kw("exploit public", "web exploit", "apache activemq", "exploit(?:ed|ing|ation of)? (?:a |an |the )?(?:zero-day|0-day|vulnerabilit(?:y|ies)|cve-\\d{4}-\\d+)", "cve-\\d{4}-\\d+ (?:was|were) exploited", "vulnerability exploitation") },
  { id: "T1566.001", name: "Phishing: Spearphishing Attachment", tactic: "Initial Access", pattern: kw("phishing emails?", "malicious attachments?", "iso file", "zip attachment", "macros?") },
  { id: "T1566.002", name: "Phishing: Spearphishing Link", tactic: "Initial Access", pattern: kw("phishing links?", "malicious urls?", "seo poisoning", "malvertising") },
  { id: "T1078.002", name: "Valid Accounts: Domain Accounts", tactic: "Initial Access", pattern: kw("valid rdp credentials", "stolen domain credentials", "compromised accounts?", "valid credentials", "legitimate credentials") },
  { id: "T1133", name: "External Remote Services", tactic: "Initial Access", pattern: kw("vpn access", "citrix (?:gateway|netscaler)", "remote desktop gateway", "exposed rdp", "internet-facing rdp", "external remote services") },
  // Execution
  { id: "T1059.001", name: "Command and Scripting: PowerShell", tactic: "Execution", pattern: kw("powershell", "powershell\\.exe", "encodedcommand", "-enc", "-noni") },
  { id: "T1059.003", name: "Command and Scripting: Windows Command Shell", tactic: "Execution", pattern: kw("cmd\\.exe", "batch scripts?", "\\.bat", "\\.cmd") },
  { id: "T1059.005", name: "Command and Scripting: Visual Basic", tactic: "Execution", pattern: kw("wscript", "cscript", "vbs", "vba") },
  { id: "T1204.002", name: "User Execution: Malicious File", tactic: "Execution", pattern: kw("user executed", "double-clicked", "opened (?:the )?document", "extracted (?:the )?archive") },
  { id: "T1047", name: "Windows Management Instrumentation", tactic: "Execution", pattern: kw("wmic", "wmi execution", "wmic process call") },
  // Persistence
  { id: "T1547.001", name: "Boot or Logon Autostart: Registry Run Keys", tactic: "Persistence", pattern: kw("registry run keys?", "runonce", "currentversion\\\\run") },
  { id: "T1053.005", name: "Scheduled Task/Job: Scheduled Task", tactic: "Persistence", pattern: kw("schtasks", "scheduled tasks?", "task scheduler") },
  { id: "T1543.003", name: "Create or Modify System Process: Windows Service", tactic: "Persistence", pattern: kw("create(?:d)? (?:a )?(?:new )?service", "sc\\.exe create", "new-service") },
  { id: "T1136.001", name: "Create Account: Local Account", tactic: "Persistence", pattern: kw("net user \\S+ \\S+ /add", "net user /add", "created (?:a )?local (?:user|account)", "new (?:local )?admin(?:istrator)? account") },
  // Privilege Escalation
  { id: "T1068", name: "Exploitation for Privilege Escalation", tactic: "Privilege Escalation", pattern: kw("privilege escalation (?:exploit|vulnerability)", "escalated privileges", "kernel exploit", "local privilege escalation") },
  { id: "T1548.002", name: "Abuse Elevation Control: Bypass UAC", tactic: "Privilege Escalation", pattern: kw("bypass(?:ed)? uac", "fodhelper", "eventvwr", "uac bypass") },
  { id: "T1078.001", name: "Valid Accounts: Default Accounts", tactic: "Privilege Escalation", pattern: kw("nt authority\\\\system", "elevated token", "default accounts?") },
  // Defense Evasion
  { id: "T1562.001", name: "Impair Defenses: Disable Tools", tactic: "Defense Evasion", pattern: kw("disabl(?:e|ed|ing) (?:windows |microsoft )?defender", "(?:disabled|stopped|killed|tampered with|uninstalled) (?:the )?(?:edr|av|antivirus|security (?:tools?|services|software|products?)|endpoint (?:protection|security))", "real-?time (?:monitoring|protection)", "tamper(?:ed|ing) (?:with )?protection", "mpcmdrun", "set-mppreference", "sc stop") },
  { id: "T1070.001", name: "Indicator Removal: Clear Windows Event Logs", tactic: "Defense Evasion", pattern: kw("wevtutil cl", "clear-eventlog", "clear(?:ed|ing)? (?:the )?(?:windows )?(?:event|security) logs?") },
  { id: "T1027", name: "Obfuscated Files or Information", tactic: "Defense Evasion", pattern: kw("obfuscated", "obfuscation", "base64[- ]encoded", "xor[- ]encrypted", "string encryption") },
  { id: "T1055", name: "Process Injection", tactic: "Defense Evasion", pattern: kw("process injection", "process hollowing", "hollowed", "reflective dll", "createremotethread") },
  // Credential Access
  { id: "T1003.001", name: "OS Credential Dumping: LSASS Memory", tactic: "Credential Access", pattern: kw("lsass", "procdump", "mimikatz", "sekurlsa", "comsvcs\\.dll", "minidump") },
  { id: "T1003.003", name: "OS Credential Dumping: NTDS", tactic: "Credential Access", pattern: kw("ntds\\.dit", "ntdsutil(?:\\.exe)?", "vssadmin create shadow", "volume shadow copy of") },
  { id: "T1558.003", name: "Steal or Forge Kerberos Tickets: Kerberoasting", tactic: "Credential Access", pattern: kw("kerberoasting", "kerberoast", "rubeus", "spn query") },
  { id: "T1555.003", name: "Credentials from Web Browsers", tactic: "Credential Access", pattern: kw("browser credentials", "chrome passwords", "saved browser passwords", "login data") },
  // Discovery
  { id: "T1087.002", name: "Account Discovery: Domain Account", tactic: "Discovery", pattern: kw("net user /domain", "net user \\S+ /domain", "adfind", "powerview", "get-aduser", "nltest") },
  { id: "T1018", name: "Remote System Discovery", tactic: "Discovery", pattern: kw("advanced ip scanner", "ping sweep", "net view", "port scan(?:ning|s)?", "network scan(?:ning|s)?") },
  { id: "T1069.002", name: "Permission Groups: Domain Groups", tactic: "Discovery", pattern: kw("net group \"?domain admins\"?", "get-adgroupmember", "bloodhound", "sharphound") },
  // Lateral Movement
  { id: "T1021.001", name: "Remote Services: Remote Desktop Protocol", tactic: "Lateral Movement", pattern: kw("rdp connections?", "mstsc", "rdp lateral movement", "remote desktop sessions?", "moved laterally (?:using|via|over) rdp") },
  { id: "T1021.002", name: "Remote Services: SMB/Windows Admin Shares", tactic: "Lateral Movement", pattern: kw("admin\\$", "c\\$", "smb exec", "psexec", "wmi lateral") },
  { id: "T1570", name: "Lateral Tool Transfer", tactic: "Lateral Movement", pattern: kw("copied (?:the )?binar(?:y|ies)", "transferred (?:the )?tools?", "smb copy", "curl download to share") },
  // Collection
  { id: "T1560.001", name: "Archive Collected Data: Archive via Utility", tactic: "Collection", pattern: kw("7z\\.exe", "winrar", "tar czf", "archives? created", "compressed (?:the )?files") },
  { id: "T1005", name: "Data from Local System", tactic: "Collection", pattern: kw("staged files", "collected documents", "sensitive directory") },
  // Command and Control
  { id: "T1071.001", name: "Application Layer Protocol: Web Protocols", tactic: "Command and Control", pattern: kw("c2 over https?", "http beacon(?:s|ing)?", "c2 traffic", "https? (?:for|as) (?:c2|command and control)") },
  { id: "T1572", name: "Protocol Tunneling", tactic: "Command and Control", pattern: kw("chisel tunnel", "ngrok", "socks5? (?:proxy|tunnel)", "cloudflared", "tunnel(?:ed|ing) (?:traffic|connections)") },
  { id: "T1105", name: "Ingress Tool Transfer", tactic: "Command and Control", pattern: kw("certutil -urlcache", "bitsadmin", "invoke-webrequest", "download cradle") },
  // Exfiltration
  { id: "T1567.002", name: "Exfiltration Over Web Service: Cloud Storage", tactic: "Exfiltration", pattern: kw("rclone", "megasync", "exfiltrat(?:ion|ed) to mega", "dropbox upload") },
  { id: "T1048", name: "Exfiltration Over Alternative Protocol", tactic: "Exfiltration", pattern: kw("ftp exfiltration", "sftp upload", "encrypted c2 exfil") },
  // Impact
  { id: "T1486", name: "Data Encrypted for Impact", tactic: "Impact", pattern: kw("ransomware encryption", "encrypted (?:the )?(?:victim(?:'s)? )?files", "ransom notes?", "deployed ransomware", "encryptors?") },
  { id: "T1490", name: "Inhibit System Recovery", tactic: "Impact", pattern: kw("delete shadows", "vssadmin delete shadows", "bcdedit", "wbadmin delete catalog", "disabled recovery") },
];

/** Command-like procedure lines; the leading look-behind keeps "net" from matching inside "Internet". */
export const PROCEDURE_RE =
  /(?<![\w.-])(?:powershell|cmd|wmic|rundll32|certutil|curl|bitsadmin|reg|schtasks|net|nltest|vssadmin|whoami|procdump|mimikatz|rubeus|adfind|powerview|chisel|rclone|megasync|psexec|wevtutil|sc|ntdsutil)(?:\.exe)?\b[^\r\n]{5,130}/gi;

const RULE_BY_ID = new Map(TECHNIQUE_RULES.map((r) => [r.id, r]));

// ---------------------------------------------------------------------------
// Actors, malware, targeting vocabularies (moved from attack-chain.ts)
// ---------------------------------------------------------------------------

export const KNOWN_ACTORS = [
  "APT28", "Fancy Bear", "Forest Blizzard", "Sofacy",
  "APT29", "Cozy Bear", "Midnight Blizzard", "NOBELIUM",
  "APT33", "Elfin", "Peach Sandstorm",
  "APT34", "OilRig", "Hazel Sandstorm",
  "APT38", "Lazarus Group", "HIDDEN COBRA", "Diamond Sleet",
  "APT39", "Chafer",
  "APT40", "Gingham Typhoon",
  "APT41", "Double Dragon", "Brass Typhoon", "Wicked Panda",
  "Kimsuky", "Emerald Sleet",
  "MuddyWater", "Mango Sandstorm",
  "Turla", "Secret Blizzard",
  "Sandworm", "Seashell Blizzard", "TeleBots",
  "HAFNIUM", "Silk Typhoon",
  "Salt Typhoon", "Volt Typhoon", "Vanguard Panda", "Bronze Silhouette",
  "Flax Typhoon", "Charcoal Typhoon",
  "FIN7", "Carbon Spider",
  "FIN8", "FIN11", "FIN12",
  "LockBit", "LockBit 3.0",
  "BlackCat", "ALPHV",
  "Akira",
  "Scattered Spider", "Octo Tempest", "UNC3944", "Muddled Libra",
  "Star Blizzard",
  "Wizard Spider",
  "CL0P", "Lace Tempest",
  "Black Basta",
  "Rhysida", "Vanilla Tempest",
  "BianLian",
  "Play Ransomware",
  "UNC5221", "UNC2630",
];

/** Generic actor naming schemes (case-sensitive). */
const ACTOR_PATTERNS: RegExp[] = [
  /\b(?:UNC\d{3,5}|Storm-\d{4}|DEV-\d{4}|UAC-\d{4}|TA(?!00)\d{3,4}|FIN\d{1,3})\b/g,
  /\bAPT ?\d{1,3}\b/g,
  /\b(?!(?:The|A|An|This|That|Each|Every|Microsoft)\s)[A-Z][a-z]+ (?:Typhoon|Blizzard|Sandstorm|Sleet|Tempest|Hail|Cyclone|Tsunami)\b/g,
  /\b(?!(?:The|A|An|This|That|Each|Every|Teddy|Polar|Giant|Red|Black)\s)[A-Z][a-z]+ (?:Spider|Panda|Kitten|Chollima)\b/g,
];

export const KNOWN_MALWARE_AND_TOOLS = [
  "Cobalt Strike", "Mimikatz", "Qakbot", "Qbot", "Bumblebee", "AdaptixC2", "SystemBC", "IcedID", "Emotet",
  "Sliver", "Havoc C2", "Brute Ratel", "Chisel", "Ligolo-ng", "Ngrok", "BloodHound", "SharpHound", "Impacket",
  "PsExec", "Rubeus", "Certify", "AnyDesk", "TeamViewer", "ScreenConnect", "MegaSync", "Rclone", "7-Zip",
  "AdFind", "PowerView", "Seatbelt", "SharpUp", "LaZagne", "Responder", "Metasploit", "Meterpreter",
  "PlugX", "ShadowPad", "GSocket",
];

/** All-caps family names introduced as "<NAME> backdoor/malware/…" (Mandiant style). */
const MALWARE_INTRO =
  /\b([A-Z][A-Z0-9]{3,}(?:[ -][A-Z0-9]{3,})?)\s+(?:backdoor|malware|implant|loader|dropper|downloader|ransomware|web ?shell|webshell|tunneler|launcher|stealer|infostealer|rootkit|RAT|trojan|wiper|beacon|payload)s?\b/g;
const CAPS_STOPWORDS = new Set([
  "SOCKS4", "SOCKS5", "EDR", "VPN", "SSH", "HTTP", "HTTPS", "DNS", "SMB", "RDP", "API", "URL", "IOC", "IOCS", "TTP", "TTPS", "CVE", "MFA",
  "SSO", "SAML", "AWS", "GCP", "ESXI", "VCENTER", "WINDOWS", "LINUX", "GTIG", "MANDIANT", "MSTIC", "CISA", "NOTE",
  "YARA", "SIGMA", "JSON", "HTML", "TLS", "SSL", "SOCKS", "WMI", "THE", "THIS", "LINUX", "ELF", "UNIX", "MACOS", "CERT",
  "TIP", "IMPORTANT", "WARNING", "UPDATE", "NEW", "GOLANG", "RUST", "JAVA", "UEFI", "BIOS",
]);

const SECTORS: Array<[string, RegExp]> = [
  ["healthcare", /\b(?:health ?care|hospitals?|medical|pharmaceutical|health (?:sector|providers?|systems?))\b/i],
  ["financial services", /\b(?:financial (?:services|sector|institutions?|organi[sz]ations|industry)|banks?|banking|insurance|fintech)\b/i],
  ["government", /\b(?:government(?:al)?|federal agenc(?:y|ies)|ministr(?:y|ies)|public sector|municipal)\b/i],
  ["energy", /\b(?:energy (?:sector|companies|providers|industry)|oil and gas|utilit(?:y|ies)|electric (?:grid|utilit(?:y|ies)))\b/i],
  ["telecommunications", /\b(?:telecommunications?|telecoms?|telcos?|communications (?:sector|providers?|companies)|internet service providers?)\b/i],
  ["manufacturing", /\bmanufactur(?:ing|ers?)\b/i],
  ["education", /\b(?:education(?:al)?(?: sector| institutions?)?|universit(?:y|ies)|schools?|academi[ac])\b/i],
  ["legal", /\b(?:legal (?:services|sector|industry|firms?)|law firms?)\b/i],
  ["technology", /\b(?:tech(?:nology)? (?:sector|companies|firms|providers|industry|organi[sz]ations|verticals?)|SaaS providers?|software (?:companies|vendors|providers)|information technology|IT (?:sector|services|providers))\b/i],
  ["defense", /\b(?:defen[cs]e (?:industrial base|contractors?|sector|industry|organi[sz]ations)|military)\b/i],
  ["critical infrastructure", /\bcritical infrastructure\b/i],
  ["retail", /\bretail(?:ers?)?\b/i],
  ["transportation", /\b(?:transportation|logistics|aviation|airlines?|maritime|shipping)\b/i],
  ["hospitality", /\b(?:hospitality|hotels?)\b/i],
  ["construction", /\bconstruction\b/i],
  ["business process outsourcing", /\b(?:business process outsourc\w*|BPOs?)\b/],
  ["media", /\b(?:media (?:organi[sz]ations|companies|outlets)|journalists?)\b/i],
  ["non-governmental organizations", /\b(?:NGOs?|non-governmental organi[sz]ations?|think tanks?)\b/],
];

const GEOGRAPHY: Array<[string, RegExp]> = [
  ["United States", /\b(?:United States|U\.S\.(?![a-z])|USA|US(?= (?:[a-z]|-based))|America(?!n))\b|\bU\.S\./],
  ["United Kingdom", /\b(?:United Kingdom|UK|Britain)\b/],
  ["Canada", /\bCanada\b/], ["Mexico", /\bMexico\b/], ["Brazil", /\bBrazil\b/], ["Argentina", /\bArgentina\b/],
  ["Colombia", /\bColombia\b/], ["Chile", /\bChile\b/], ["Germany", /\bGermany\b/], ["France", /\bFrance\b/],
  ["Italy", /\bItaly\b/], ["Spain", /\bSpain\b/], ["Netherlands", /\bNetherlands\b/], ["Belgium", /\bBelgium\b/],
  ["Poland", /\bPoland\b/], ["Ukraine", /\bUkraine\b/], ["Russia", /\bRussia\b/], ["China", /\bChina\b/],
  ["Taiwan", /\bTaiwan\b/], ["Japan", /\bJapan\b/], ["South Korea", /\bSouth Korea\b/], ["North Korea", /\bNorth Korea\b/],
  ["India", /\bIndia\b/], ["Pakistan", /\bPakistan\b/], ["Iran", /\bIran\b/], ["Israel", /\bIsrael\b/],
  ["Saudi Arabia", /\bSaudi Arabia\b/], ["United Arab Emirates", /\b(?:United Arab Emirates|UAE)\b/], ["Turkey", /\b(?:Turkey|Türkiye)\b/],
  ["Australia", /\bAustralia\b/], ["New Zealand", /\bNew Zealand\b/], ["Singapore", /\bSingapore\b/], ["Vietnam", /\bVietnam\b/],
  ["Philippines", /\bPhilippines\b/], ["Indonesia", /\bIndonesia\b/], ["Malaysia", /\bMalaysia\b/], ["Thailand", /\bThailand\b/],
  ["Guam", /\bGuam\b/], ["Europe", /\bEurope\b/], ["Middle East", /\bMiddle East\b/], ["Latin America", /\bLatin America\b/],
  ["Africa", /\bAfrica\b/], ["Asia-Pacific", /\b(?:Asia[- ]Pacific|APAC)\b/], ["North America", /\bNorth America\b/],
  ["South America", /\bSouth America\b/], ["Asia", /\bAsia\b(?![- ]Pacific)/],
];
/** Geography used as actor origin ("China-nexus", "based in Iran") is not targeting. */
const ORIGIN_AFTER = /^-?\s?(?:nexus|based|linked|sponsored|aligned|backed|affiliated|state)/i;
const ORIGIN_BEFORE = /(?:based in|located in|originating (?:from|in)|operating (?:from|out of)|nexus|from)\s*$/i;

const PLATFORMS: Array<[string, RegExp]> = [
  ["Windows", /\bWindows\b(?! Defender)/], ["Linux", /\bLinux\b/], ["macOS", /\b(?:macOS|Mac OS)\b/],
  ["VMware ESXi", /\bESXi\b/i], ["VMware vCenter", /\bvCenter\b/i], ["VMware", /\bVMware\b(?! (?:ESXi|vCenter))/i],
  ["Active Directory", /\bActive Directory\b/], ["Entra ID", /\b(?:Entra ID|Azure AD|Azure Active Directory)\b/],
  ["Microsoft 365", /\b(?:Microsoft 365|Office 365|M365|O365)\b/], ["AWS", /\b(?:AWS|Amazon Web Services)\b/],
  ["Azure", /\bAzure\b(?! (?:AD|Active Directory))/], ["Google Cloud", /\b(?:GCP|Google Cloud)\b/], ["Kubernetes", /\bKubernetes\b/i],
  ["Citrix", /\bCitrix\b/], ["Fortinet", /\b(?:Fortinet|FortiGate|FortiOS|FortiGuard)\b/], ["Ivanti", /\bIvanti\b/],
  ["Cisco", /\bCisco\b/], ["Palo Alto Networks", /\b(?:Palo Alto Networks|PAN-OS|GlobalProtect)\b/],
  ["Microsoft Exchange", /\b(?:Microsoft Exchange|Exchange (?:Server|Online))\b/], ["SharePoint", /\bSharePoint\b/],
  ["Okta", /\bOkta\b/], ["Salesforce", /\bSalesforce\b/],
];

const OBJECTIVES: Array<[string, RegExp]> = [
  ["espionage", /\b(?:espionage|intelligence (?:gathering|collection)|information gathering)\b/i],
  ["financial gain", /\b(?:financially[- ]motivated|financial gain|monetiz\w+)\b/i],
  ["extortion", /\b(?:extortion|extort(?:ed|ing)?|ransom demands?)\b/i],
  ["ransomware deployment", /\b(?:deploy(?:ed|ing|ment of)? (?:\w+ )?ransomware|ransomware deployment)\b/i],
  ["destruction", /\b(?:destructive|wipers?|destroy(?:ed|ing)?)\b/i],
  ["data theft", /\b(?:data theft|exfiltrat\w+|st(?:ole|eal|ealing) (?:sensitive )?data)\b/i],
];

const COMPROMISE_WORDS = /\b(?:compromis\w*|breach(?:ed|es)?|attacked|victims?|intrusions?|infected|impacted|affected organi[sz]ations)\b/i;
const TARGET_WORDS = /\b(?:target(?:ed|ing|s)?|focus(?:ed|es|ing)? on|aimed at)\b/i;
const AT_RISK_WORDS = /\b(?:at risk|vulnerable|should patch|exposed to)\b/i;

// ---------------------------------------------------------------------------
// Builder
// ---------------------------------------------------------------------------

export type TechniqueLookup = (id: string) => { name: string; tactic: string } | null;

export type BuildEvidenceOptions = {
  title?: string;
  /** Resolve names/tactics for explicit technique IDs not in TECHNIQUE_RULES. */
  lookup?: TechniqueLookup;
};

const MAX_QUOTE = 400;
const MAX_EVIDENCE = 5;
const ADVERSARY: ReadonlySet<EvidenceLabel> = new Set<EvidenceLabel>(["observed", "inferred"]);

/** Evidence for a sentence; long sentences are windowed around the match so the quote stays ≤ 400 chars. */
function makeEvidence(text: string, s: SentenceInfo, matchStart?: number, matchEnd?: number): Evidence {
  let start = s.start;
  let end = s.end;
  if (end - start > MAX_QUOTE) {
    const ms = matchStart ?? start;
    const me = matchEnd ?? ms;
    const center = Math.floor((ms + me) / 2);
    start = Math.max(s.start, Math.min(center - MAX_QUOTE / 2, s.end - MAX_QUOTE));
    end = Math.min(s.end, start + MAX_QUOTE);
    // Trim to whitespace so words are not cut, keeping offsets exact.
    const ws = text.slice(start, end).search(/\s/);
    if (start > s.start && ws > 0 && ws < 40) start += ws + 1;
    const tail = text.slice(start, end);
    const lastWs = Math.max(tail.lastIndexOf(" "), tail.lastIndexOf("\t"));
    if (end < s.end && lastWs > tail.length - 40) end = start + lastWs;
  }
  const ev: Evidence = { quote: text.slice(start, end), start, end };
  if (s.section) ev.section = s.section;
  return ev;
}

type Hit = { sent: SentenceInfo; ev: Evidence; explicit: boolean };

const LABEL_PRIORITY: EvidenceLabel[] = ["observed", "inferred", "defensive", "negated", "hypothetical", "reference"];

function aggregateLabel(labels: EvidenceLabel[]): EvidenceLabel {
  for (const l of LABEL_PRIORITY) if (labels.includes(l)) return l;
  return "observed";
}

/** Prefer adversary-activity sentences, then the rest, capped; returned in text order. */
function pickEvidence(hits: Hit[], adversaryOnly: boolean): Evidence[] {
  const adv = hits.filter((h) => ADVERSARY.has(h.sent.label));
  const other = hits.filter((h) => !ADVERSARY.has(h.sent.label));
  const chosen = (adversaryOnly ? adv : [...adv, ...other]).slice(0, MAX_EVIDENCE);
  return chosen.map((h) => h.ev).sort((a, b) => a.start - b.start);
}

const escapeRe = (s: string) => s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");

type NameHit = { value: string; start: number; end: number };

function findNames(sentenceText: string, offset: number, known: string[], patterns: RegExp[]): NameHit[] {
  const hits: NameHit[] = [];
  for (const name of known) {
    const re = new RegExp(`(?<![A-Za-z0-9_-])${escapeRe(name)}(?![A-Za-z0-9_-])`, "gi");
    let m: RegExpExecArray | null;
    while ((m = re.exec(sentenceText))) hits.push({ value: name, start: offset + m.index, end: offset + m.index + m[0].length });
  }
  for (const p of patterns) {
    const re = new RegExp(p.source, p.flags.includes("g") ? p.flags : p.flags + "g");
    let m: RegExpExecArray | null;
    while ((m = re.exec(sentenceText))) {
      const value = m[0].replace(/^APT (\d)/, "APT$1");
      hits.push({ value, start: offset + m.index, end: offset + m.index + m[0].length });
    }
  }
  return hits;
}

/**
 * Build fact-level evidence for a report. Offsets index `text` exactly;
 * `textHash` is left for the caller to set.
 */
export function buildEvidence(text: string, options: BuildEvidenceOptions = {}): IntelEvidence {
  const sections = detectSections(text);
  const sentences = labelSentences(text, sections).filter((s) => !s.isHeading);
  const titleLower = (options.title ?? "").toLowerCase();

  // ---- Techniques -------------------------------------------------------
  type TechAgg = { id: string; name: string; tactic: string; hits: Hit[]; firstMatch: Map<number, string> };
  const techs = new Map<string, TechAgg>();
  const sentenceTechs = new Map<number, Array<{ id: string; explicit: boolean }>>();
  const resolve = (id: string) => {
    const rule = RULE_BY_ID.get(id);
    if (rule) return { name: rule.name, tactic: rule.tactic };
    const looked = options.lookup?.(id);
    if (looked) return looked;
    const parent = id.includes(".") ? RULE_BY_ID.get(id.split(".")[0]) : undefined;
    return parent ? { name: `${parent.name} (sub-technique ${id})`, tactic: parent.tactic } : { name: id, tactic: "Unknown" };
  };
  const addTech = (id: string, sent: SentenceInfo, idx: number, ms: number, me: number, explicit: boolean, matched: string) => {
    let agg = techs.get(id);
    if (!agg) {
      const r = resolve(id);
      agg = { id, name: r.name, tactic: r.tactic, hits: [], firstMatch: new Map() };
      techs.set(id, agg);
    }
    if (agg.hits.some((h) => h.sent.start === sent.start)) {
      const prev = agg.hits.find((h) => h.sent.start === sent.start);
      if (prev && explicit) prev.explicit = true;
    } else {
      agg.hits.push({ sent, ev: makeEvidence(text, sent, ms, me), explicit });
      agg.firstMatch.set(sent.start, matched);
    }
    const list = sentenceTechs.get(idx) ?? [];
    const existing = list.find((t) => t.id === id);
    if (existing) existing.explicit ||= explicit;
    else list.push({ id, explicit });
    sentenceTechs.set(idx, list);
  };

  sentences.forEach((sent, idx) => {
    const idRe = /\bT\d{4}(?:\.\d{3})?\b/g;
    let m: RegExpExecArray | null;
    while ((m = idRe.exec(sent.text))) {
      addTech(m[0], sent, idx, sent.start + m.index, sent.start + m.index + m[0].length, true, m[0]);
    }
    for (const rule of TECHNIQUE_RULES) {
      const km = rule.pattern.exec(sent.text);
      if (km) addTech(rule.id, sent, idx, sent.start + km.index, sent.start + km.index + km[0].length, false, km[0]);
    }
  });

  const techniques: TechniqueFact[] = [];
  const excluded: IntelEvidence["excluded"] = [];
  const keptTech = new Set<string>();
  for (const agg of techs.values()) {
    agg.hits.sort((a, b) => a.sent.start - b.sent.start);
    const advHits = agg.hits.filter((h) => ADVERSARY.has(h.sent.label));
    for (const h of agg.hits.filter((x) => !ADVERSARY.has(x.sent.label)).slice(0, MAX_EVIDENCE)) {
      excluded.push({ techniqueId: agg.id, label: h.sent.label, evidence: h.ev });
    }
    if (advHits.length === 0) continue;
    const explicitObserved = advHits.some((h) => h.explicit);
    const label: EvidenceLabel = explicitObserved ? "observed" : "inferred";
    const confidence = explicitObserved
      ? Math.min(0.95, 0.85 + 0.03 * (advHits.length - 1))
      : Math.min(0.8, 0.55 + 0.05 * (advHits.length - 1));
    techniques.push({
      id: agg.id,
      name: agg.name,
      tactic: agg.tactic,
      label,
      mappedBy: explicitObserved ? "explicit_id" : "keyword",
      evidence: pickEvidence(advHits, true),
      confidence: Number(confidence.toFixed(2)),
    });
    keptTech.add(agg.id);
  }
  techniques.sort((a, b) => a.evidence[0].start - b.evidence[0].start);

  // ---- Actors & malware --------------------------------------------------
  const discoveredMalware = new Set<string>();
  for (const s of sentences) {
    let m: RegExpExecArray | null;
    const re = new RegExp(MALWARE_INTRO.source, "g");
    while ((m = re.exec(s.text))) {
      const name = m[1];
      if (!CAPS_STOPWORDS.has(name) && !name.split(/[ -]/).some((w) => CAPS_STOPWORDS.has(w))) discoveredMalware.add(name);
    }
  }
  const knownMalwareLower = new Set(KNOWN_MALWARE_AND_TOOLS.map((m) => m.toLowerCase()));
  const malwareNames = [...KNOWN_MALWARE_AND_TOOLS, ...[...discoveredMalware].filter((n) => !knownMalwareLower.has(n.toLowerCase()))];

  type ValAgg = { value: string; hits: Hit[] };
  const collect = (findIn: (s: SentenceInfo) => NameHit[], perSentence: Map<number, string[]>) => {
    const map = new Map<string, ValAgg>();
    sentences.forEach((sent, idx) => {
      const seen = new Set<string>();
      for (const h of findIn(sent)) {
        const key = h.value.toLowerCase();
        let agg = map.get(key);
        if (!agg) {
          agg = { value: h.value, hits: [] };
          map.set(key, agg);
        }
        if (seen.has(key)) continue;
        seen.add(key);
        agg.hits.push({ sent, ev: makeEvidence(text, sent, h.start, h.end), explicit: true });
        perSentence.set(idx, [...(perSentence.get(idx) ?? []), agg.value]);
      }
    });
    const values: EvidencedValue[] = [];
    for (const agg of map.values()) {
      const label = aggregateLabel(agg.hits.map((h) => h.sent.label));
      const adv = agg.hits.filter((h) => ADVERSARY.has(h.sent.label)).length;
      let confidence = ADVERSARY.has(label) ? Math.min(0.9, 0.6 + 0.08 * adv) : 0.3;
      if (titleLower.includes(agg.value.toLowerCase())) confidence = Math.min(0.95, confidence + 0.1);
      values.push({ value: agg.value, label, evidence: pickEvidence(agg.hits, false), confidence: Number(confidence.toFixed(2)) });
    }
    return values.sort((a, b) => a.evidence[0].start - b.evidence[0].start);
  };

  const actorsBySentence = new Map<number, string[]>();
  const malwareBySentence = new Map<number, string[]>();
  const actors = collect((s) => findNames(s.text, s.start, KNOWN_ACTORS, ACTOR_PATTERNS), actorsBySentence);
  // Known-list names win over the generic pattern match of the same span.
  for (const a of actors) {
    const canon = KNOWN_ACTORS.find((k) => k.toLowerCase() === a.value.toLowerCase());
    if (canon) a.value = canon;
  }
  const malware = collect((s) => findNames(s.text, s.start, malwareNames, []), malwareBySentence);

  // ---- Relationships (same observed sentence only) ------------------------
  const relationships: RelationshipFact[] = [];
  const relKey = new Map<string, RelationshipFact>();
  const addRel = (rel: Omit<RelationshipFact, "evidence">, ev: Evidence) => {
    const key = `${rel.subject.type}:${rel.subject.value.toLowerCase()}|${rel.predicate}|${rel.object.type}:${rel.object.value.toLowerCase()}`;
    const existing = relKey.get(key);
    if (existing) {
      if (existing.evidence.length < MAX_EVIDENCE) existing.evidence.push(ev);
      existing.confidence = Math.min(0.85, Number((existing.confidence + 0.05).toFixed(2)));
      if (rel.label === "observed") existing.label = "observed";
      return;
    }
    const fact: RelationshipFact = { ...rel, evidence: [ev] };
    relKey.set(key, fact);
    relationships.push(fact);
  };
  sentences.forEach((sent, idx) => {
    if (sent.label !== "observed") return;
    const sActors = [...new Set(actorsBySentence.get(idx) ?? [])];
    const sMalware = [...new Set(malwareBySentence.get(idx) ?? [])];
    const sTechs = (sentenceTechs.get(idx) ?? []).filter((t) => keptTech.has(t.id));
    if (sActors.length + sMalware.length === 0) return;
    const ev = makeEvidence(text, sent);
    const canonActor = (v: string) => KNOWN_ACTORS.find((k) => k.toLowerCase() === v.toLowerCase()) ?? v;
    for (const a of sActors) {
      for (const mw of sMalware) {
        addRel({ subject: { type: "actor", value: canonActor(a) }, predicate: "uses", object: { type: "malware", value: mw }, label: "observed", confidence: 0.75 }, ev);
      }
      for (const t of sTechs) {
        addRel({ subject: { type: "actor", value: canonActor(a) }, predicate: "performed", object: { type: "technique", value: t.id }, label: t.explicit ? "observed" : "inferred", confidence: t.explicit ? 0.8 : 0.6 }, ev);
      }
    }
    for (const mw of sMalware) {
      for (const t of sTechs) {
        addRel({ subject: { type: "malware", value: mw }, predicate: "performed", object: { type: "technique", value: t.id }, label: t.explicit ? "observed" : "inferred", confidence: t.explicit ? 0.75 : 0.6 }, ev);
      }
    }
  });

  // ---- Targeting ----------------------------------------------------------
  const STATUS_RANK: Record<TargetingFact["status"], number> = { compromised: 3, targeted: 2, at_risk: 1, mentioned: 0 };
  const targetMap = new Map<string, TargetingFact>();
  const addTarget = (kind: TargetingFact["kind"], value: string, status: TargetingFact["status"], ev: Evidence) => {
    const key = `${kind}:${value}`;
    const cur = targetMap.get(key);
    const base = status === "compromised" || status === "targeted" ? 0.7 : status === "at_risk" ? 0.5 : 0.3;
    if (!cur) {
      targetMap.set(key, { kind, value, status, evidence: [ev], confidence: base });
      return;
    }
    if (STATUS_RANK[status] > STATUS_RANK[cur.status]) {
      cur.status = status;
      cur.evidence.unshift(ev);
      cur.confidence = base;
    } else if (cur.evidence.length < MAX_EVIDENCE) {
      cur.evidence.push(ev);
    }
    if (cur.evidence.length > MAX_EVIDENCE) cur.evidence.length = MAX_EVIDENCE;
    cur.evidence.sort((a, b) => a.start - b.start);
    cur.confidence = Math.min(0.9, Number((cur.confidence + 0.03).toFixed(2)));
  };
  for (const sent of sentences) {
    if (sent.isRule || sent.label === "reference") continue;
    const observed = sent.label === "observed";
    let status: TargetingFact["status"] = "mentioned";
    if (observed && COMPROMISE_WORDS.test(sent.text)) status = "compromised";
    else if (observed && TARGET_WORDS.test(sent.text)) status = "targeted";
    else if (sent.label === "defensive" || sent.label === "hypothetical" || AT_RISK_WORDS.test(sent.text)) status = "at_risk";
    const scan = (kind: TargetingFact["kind"], table: Array<[string, RegExp]>, statusFor: TargetingFact["status"], guard?: (m: RegExpExecArray) => boolean) => {
      for (const [value, re] of table) {
        const g = new RegExp(re.source, re.flags.includes("g") ? re.flags : re.flags + "g");
        let m: RegExpExecArray | null;
        while ((m = g.exec(sent.text))) {
          if (guard && !guard(m)) continue;
          addTarget(kind, value, statusFor, makeEvidence(text, sent, sent.start + m.index, sent.start + m.index + m[0].length));
          break;
        }
      }
    };
    scan("sector", SECTORS, status);
    scan("geography", GEOGRAPHY, status, (m) => {
      const after = sent.text.slice(m.index + m[0].length, m.index + m[0].length + 12);
      const before = sent.text.slice(Math.max(0, m.index - 24), m.index);
      return !ORIGIN_AFTER.test(after) && !ORIGIN_BEFORE.test(before);
    });
    // Platforms are compromised/targeted only with explicit wording; at_risk for advice.
    scan("platform", PLATFORMS, status);
    // Objectives: "targeted" means the source reports the adversary pursuing it.
    scan("objective", OBJECTIVES, observed ? "targeted" : "mentioned");
  }
  const targeting = [...targetMap.values()];

  // ---- Chain (source order of observed/inferred techniques) --------------
  const byTactic = new Map<string, { techniques: string[]; position: number; evidence: Evidence[] }>();
  for (const t of techniques) {
    if (!ADVERSARY.has(t.label) || t.tactic === "Unknown") continue;
    const pos = Math.min(...t.evidence.map((e) => e.start));
    const cur = byTactic.get(t.tactic) ?? { techniques: [], position: pos, evidence: [] };
    cur.techniques.push(t.id);
    cur.position = Math.min(cur.position, pos);
    cur.evidence.push(t.evidence[0]);
    byTactic.set(t.tactic, cur);
  }
  const steps: ChainStepEvidence[] = [...byTactic.entries()]
    .sort((a, b) => a[1].position - b[1].position)
    .map(([tactic, v], i) => {
      const seen = new Set<number>();
      const evidence = v.evidence
        .sort((a, b) => a.start - b.start)
        .filter((e) => (seen.has(e.start) ? false : (seen.add(e.start), true)))
        .slice(0, MAX_EVIDENCE);
      return { order: i + 1, tactic, techniques: v.techniques, position: v.position, evidence };
    });

  return {
    version: 1,
    rules: EVIDENCE_RULES_VERSION,
    sections,
    techniques,
    actors,
    malware,
    targeting,
    relationships,
    chain: { steps, orderBasis: steps.length >= 2 ? "reported" : "unknown" },
    excluded,
  };
}
