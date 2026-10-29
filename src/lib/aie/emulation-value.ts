/**
 * Emulation value: how much a report gives an attack emulation / simulation team to rebuild.
 *
 * The technical-depth check (./technical-depth) answers "is this technical threat intelligence?".
 * This module answers the next question: "could a red / purple team replay what it describes?".
 * The reports worth most are those that walk through an infection chain step by step, naming the
 * files, paths, registry keys, commands, APIs and encryption the attacker used, in order (e.g.
 * "PowerShell downloads X.msi … msiexec installs it silently … DeElevate64.exe loads the patched
 * DLL … the loader decrypts config.ini with AES-256 and maps the backdoor in memory"). A patch note
 * that names a CVE and the fixed versions passes the depth check but gives an emulation team
 * nothing.
 *
 * Grades, best first:
 *   chain       — a multi-step attack chain with concrete procedures (artifacts in order)
 *   procedures  — concrete procedures (commands, artifacts, techniques) but no full chain
 *   context     — actor / campaign / malware context, indicators or techniques, few procedures
 *   news        — news, patch notes or vulnerability notices without attacker procedures
 *
 * Everything is counted in the article prose only (./technical-depth `articleProse`), and every
 * grade comes with the evidence that earned it: the procedure steps and novelty statements quoted
 * from the text, so an analyst (or the AI reviewer) can check it.
 *
 * Pure module (relative imports of pure modules only) so it runs under `node --test` and in the browser.
 */
import { articleProse, countCommands } from "./technical-depth.ts";

/** Bump when the rules change so stored reports are graded again. */
export const EMULATION_VALUE_VERSION = 1;

export type EmulationGrade = "chain" | "procedures" | "context" | "news";

export const EMULATION_GRADES: EmulationGrade[] = ["chain", "procedures", "context", "news"];

export const EMULATION_GRADE_META: Record<EmulationGrade, { label: string; short: string; description: string; rank: number }> = {
  chain: {
    label: "Attack chain",
    short: "Chain",
    description: "Walks through a multi-step attack chain with the files, commands and tooling used at each step: ready to emulate.",
    rank: 3,
  },
  procedures: {
    label: "Procedures",
    short: "Procedures",
    description: "Concrete attacker procedures (commands, artifacts, techniques) without the full chain.",
    rank: 2,
  },
  context: {
    label: "Context",
    short: "Context",
    description: "Actor, campaign or malware context, indicators or techniques; few procedures to replay.",
    rank: 1,
  },
  news: {
    label: "News / notice",
    short: "News",
    description: "News, patch note or vulnerability notice without attacker procedures.",
    rank: 0,
  },
};

export type EmulationValue = {
  version: number;
  grade: EmulationGrade;
  /** 0–100. */
  score: number;
  /** Plain-language reasons for the grade, most important first. */
  signals: string[];
  /** Procedure steps quoted from the text, in document order (at most 12). */
  steps: string[];
  /** Statements of novelty quoted from the text (new technique, previously undocumented …). */
  novelty: string[];
  /** Distinct artifacts by kind (a few examples each). */
  artifacts: Partial<Record<ArtifactKind, string[]>>;
  stats: {
    procedureSteps: number;
    artifacts: number;
    commands: number;
    chainMarkers: number;
    sequenceMarkers: number;
    behaviours: number;
    techniques: number;
    patchNotice: number;
  };
};

export type ArtifactKind = "file" | "path" | "registry" | "api" | "crypto" | "lolbin" | "network";

export type EmulationInput = {
  title: string;
  text: string;
  /** Kinds of attacker behaviour and technique IDs, when the caller already has them (./technical-depth). */
  behaviours?: number;
  techniques?: number;
};

const MAX_CHARS = 150_000;

// ---------------------------------------------------------------------------
// Artifacts
// ---------------------------------------------------------------------------

const FILE_EXT =
  "exe|dll|ps1|psm1|vbs|vbe|js|jse|hta|lnk|msi|msix|iso|img|vhdx?|bat|cmd|scr|cpl|jar|py|sh|elf|so|dylib|zip|rar|7z|cab|docm|xlsm|one|chm|wsf|xll|sys|dat|bin|ini|tmp|apk|plist|scpt";
const ARTIFACT_RES: Array<[ArtifactKind, RegExp]> = [
  ["registry", /\b(?:HKLM|HKCU|HKCR|HKU|HKEY_[A-Z_]+)\\[^\s"'<>,;)]+/g],
  ["path", /(?:\b[A-Z]:\\|%[A-Za-z_]+%\\?|\\\\[\w.$-]+\\)[^\s"'<>|,;)]*/g],
  ["path", /(?<![\w.])\/(?:tmp|var|etc|usr|home|dev\/shm|Library|Users|opt|private|root|System)\/[^\s"'<>),;]+/g],
  ["file", new RegExp(`\\b[\\w+-][\\w.+-]{0,60}\\.(?:${FILE_EXT})\\b`, "gi")],
  [
    "api",
    /\b(?:VirtualAlloc(?:Ex)?|VirtualProtect(?:Ex)?|WriteProcessMemory|ReadProcessMemory|CreateRemoteThread(?:Ex)?|NtCreateThreadEx|NtMapViewOfSection|NtUnmapViewOfSection|QueueUserAPC|NtQueueApcThread|SetThreadContext|ResumeThread|LoadLibrary(?:Ex)?[AW]?|GetProcAddress|RtlMoveMemory|NtAllocateVirtualMemory|NtWriteVirtualMemory|CreateProcess(?:Internal)?[AW]?|ShellExecute(?:Ex)?[AW]?|WinExec|URLDownloadToFile[AW]?|InternetOpen(?:Url)?[AW]?|HttpSendRequest[AW]?|WinHttp\w+|AmsiScanBuffer|EtwEventWrite|TpAllocWork|TpPostWork|CreateThreadpool\w*|SetWindowsHookEx[AW]?|CryptDecrypt|BCryptDecrypt|RtlDecompressBuffer|NtCreateSection|DeviceIoControl)\b/g,
  ],
  ["crypto", /\b(?:AES(?:-?(?:128|192|256))?(?:-(?:CBC|GCM|ECB|CTR))?|RC4|RC5|XOR(?:-(?:encoded|encrypted|ed))?|ChaCha20|Salsa20|RSA-?\d{3,4}|Base64|Base32|zlib|LZNT1|LZMA|gzip|steganograph(?:y|ic))\b/gi],
  [
    "lolbin",
    /\b(?:msiexec|rundll32|regsvr32|mshta|certutil|bitsadmin|wmic|schtasks|wscript|cscript|installutil|msbuild|odbcconf|forfiles|conhost|dllhost|cmstp|regasm|regsvcs|mavinject|esentutl|expand|extrac32|finger|ftp|curl|wget|7zr?|powershell|pwsh|cmd)(?:\.exe)?\b(?=[\s,.;:)'"]|$)/gi,
  ],
  ["network", /\bhxxps?:\/\/[^\s)\]"']+|\b[\w-]+(?:\[\.\][\w-]+)+/gi],
];

/** Common words that look like file names but are not artifacts. */
const NOT_FILES = /^(?:e\.g|i\.e|node\.js|next\.js|vue\.js|react\.js|asp\.net|vb\.net|\d+(?:\.\d+)+)$/i;

function collectArtifacts(prose: string): { byKind: Partial<Record<ArtifactKind, string[]>>; total: number } {
  const byKind: Partial<Record<ArtifactKind, Set<string>>> = {};
  for (const [kind, re] of ARTIFACT_RES) {
    re.lastIndex = 0;
    for (const m of prose.matchAll(re)) {
      const v = m[0].replace(/[.,:;]+$/, "");
      if (kind === "file" && NOT_FILES.test(v)) continue;
      if (kind === "lolbin" && /^(?:cmd|expand|ftp|finger|curl|wget|7z|7zr)$/i.test(v) && !/\.exe$/i.test(v)) {
        // Ordinary words; only count them as tools next to a switch or a URL.
        const after = prose.slice((m.index ?? 0) + v.length, (m.index ?? 0) + v.length + 12);
        if (!/^\s+(?:[-/]\w|https?:|hxxp)/i.test(after)) continue;
      }
      (byKind[kind] ??= new Set()).add(kind === "crypto" || kind === "lolbin" ? v.toLowerCase() : v);
    }
  }
  const out: Partial<Record<ArtifactKind, string[]>> = {};
  let total = 0;
  for (const [k, set] of Object.entries(byKind) as Array<[ArtifactKind, Set<string>]>) {
    out[k] = [...set].slice(0, 8);
    total += set.size;
  }
  return { byKind: out, total };
}

// ---------------------------------------------------------------------------
// Procedure steps, chain structure, novelty, patch notices
// ---------------------------------------------------------------------------

const ACTION_RE =
  /\b(?:read(?:s|ing)?|download(?:s|ed|ing)?|drop(?:s|ped|ping)?|writ(?:es|ten|ing)|wrote|load(?:s|ed|ing)?|side-?load(?:s|ed|ing)?|execut(?:es|ed|ing)|launch(?:es|ed|ing)?|run(?:s|ning)?|spawn(?:s|ed|ing)?|inject(?:s|ed|ing)?|decrypt(?:s|ed|ing)?|decod(?:es|ed|ing)|deobfuscat(?:es|ed|ing)|extract(?:s|ed|ing)?|unpack(?:s|ed|ing)?|maps?|mapped|install(?:s|ed|ing)?|creat(?:es|ed|ing)|register(?:s|ed|ing)?|connect(?:s|ed|ing)?|beacon(?:s|ed|ing)?|contact(?:s|ed|ing)?|exfiltrat(?:es|ed|ing)|persist(?:s|ed|ing)?|modif(?:y|ies|ied|ying)|abus(?:es|ed|ing)|leverag(?:es|ed|ing)|invok(?:es|ed|ing)|fetch(?:es|ed|ing)?|retriev(?:es|ed|ing)|queries|queried|copies|copied|renam(?:es|ed|ing)|delet(?:es|ed|ing)|disabl(?:es|ed|ing)|hollow(?:s|ed|ing)?|reflectively|transfers? control|hands? (?:off|over))\b/i;

const CHAIN_RE =
  /\b(?:infection chains?|attack chains?|kill chains?|execution (?:chains?|flow)|intrusion (?:chain|timeline)|multi-?stage|(?:first|second|third|final|next)[- ]stage|stage[- ](?:one|two|three|four|[1-9])\b|final payload|(?:route|chain|phase|step|stage) [A-Z1-9]\b|step[- ]by[- ]step)/gi;
const SEQUENCE_RE = /(?:^|[.;:]\s+|\n)\s*(?:then|next|subsequently|afterwards|once|finally|after (?:that|this)|following (?:this|that)|in turn|this (?:in turn|then))\b|\b(?:followed by|which then|that then|and then)\b/gi;

const NOVELTY_RE =
  /\b(?:novel|previously (?:undocumented|unknown|unreported|unseen|unobserved)|new(?:ly)?\s+(?:[\w-]+\s+){0,3}?(?:technique|variant|version|loader|backdoor|implant|malware|method|tool(?:kit|set)?|exploit kit|campaign|family|infection chain|delivery (?:platform|method|chain)|tradecraft|ttps?)|first (?:time|observed|seen|documented|reported)|never (?:been |before )?(?:seen|documented|observed)|zero-?days?|0-?days?|undocumented|not (?:been )?(?:publicly )?(?:documented|reported) before|unique (?:technique|approach|method))\b/i;

const PATCH_RE =
  /\b(?:security (?:update|patch|bulletin|fix)e?s?|patch(?:es|ed)? (?:released|available|for)|released (?:a |an )?(?:patch|fix|update|security update)s?|fixed in (?:version )?|upgrade to (?:version )?|update to (?:version )?|CVSS(?: ?v?[34](?:\.\d)?)?(?: base)? score|affected (?:versions|products|releases)|workarounds?|(?:versions? )?prior to \d|and earlier|or earlier|vendor (?:has )?(?:released|issued)|apply (?:the )?(?:latest )?(?:updates|patches))\b/gi;

function sentences(prose: string): string[] {
  const out: string[] = [];
  for (const line of prose.split("\n")) {
    const l = line.trim();
    if (!l) continue;
    for (const s of l.split(/(?<=[.!?])\s+(?=[A-Z0-9"'(•■▪–-])/)) {
      const t = s.replace(/^[•■▪*–-]+\s*/, "").trim();
      if (t.length >= 12) out.push(t);
    }
  }
  return out;
}

function hasArtifact(s: string): boolean {
  for (const [kind, re] of ARTIFACT_RES) {
    if (kind === "crypto") continue;
    re.lastIndex = 0;
    const m = re.exec(s);
    re.lastIndex = 0;
    if (!m) continue;
    if (kind === "file" && NOT_FILES.test(m[0].replace(/[.,:;]+$/, ""))) continue;
    if (kind === "lolbin" && /^(?:cmd|expand|ftp|finger|curl|wget|7z|7zr|powershell|pwsh)$/i.test(m[0]) && !/\b(?:powershell|pwsh)\b/i.test(m[0])) continue;
    return true;
  }
  return /\bT1\d{3}(?:\.\d{3})?\b/.test(s);
}

/** Attack objects that make a sentence a procedure step even without a file name. */
const PROCEDURE_OBJECT_RE =
  /\b(?:shellcode|PE (?:image|loader|file)|in[- ]memory|reflective(?:ly)?|process hollowing|side-?load(?:s|ed|ing)?|named pipe|scheduled task|run key|mutex|web ?shell|payload|loader|implant|backdoor|C2 server|command-and-control server)\b/i;

/** Numbered step lines ("1. …", "Step 2:", "Stage 3 –"). */
const NUMBERED_STEP_RE = /^\s*(?:\d{1,2}[.)]\s|(?:step|stage|phase)\s+\d{1,2}\b)/gim;

const clip = (s: string, n = 220) => (s.length > n ? `${s.slice(0, n - 1).trimEnd()}…` : s);

// ---------------------------------------------------------------------------
// Assessment
// ---------------------------------------------------------------------------

const BEHAVIOUR_HINTS: RegExp[] = [
  /\b(?:phishing|lure|ClickFix|malvertis|drive-by|SEO poisoning|watering hole)\b/i,
  /\b(?:exploit(?:ed|s|ation)?)\b/i,
  /\b(?:persisten(?:ce|t)|scheduled task|run key|startup folder|service install)/i,
  /\b(?:privilege escalation|UAC bypass|token)\b/i,
  /\b(?:obfuscat|side-?load|injection|hollowing|in-memory|fileless|AMSI|ETW|unhook|anti-(?:analysis|debug|vm))/i,
  /\b(?:credential|LSASS|cookies?|password|kerberoast)/i,
  /\b(?:discovery|reconnaissance|enumerat)/i,
  /\b(?:lateral movement|PsExec|RDP|WinRM|SMB)\b/i,
  /\b(?:C2|command[- ]and[- ]control|beacon|tasking)\b/i,
  /\b(?:exfiltrat|staging|archiv(?:e|ed) (?:the )?data)/i,
  /\b(?:ransomware|encrypt(?:s|ed) (?:files|data)|wiper|destroy)/i,
];

/** Grades a report's emulation value (see the module doc). */
export function assessEmulationValue(input: EmulationInput): EmulationValue {
  const prose = articleProse(`${input.title ?? ""}\n${(input.text ?? "").slice(0, MAX_CHARS)}`);
  const all = sentences(prose);
  const { byKind, total: artifacts } = collectArtifacts(prose);
  const commands = countCommands(prose);

  // Procedure steps: an action plus a concrete artifact (strong) or an attack object (weak). The
  // quoted steps prefer strong ones, in document order, so context sentences do not crowd them out.
  const candidates: Array<{ s: string; strong: boolean }> = [];
  const seenSteps = new Set<string>();
  const novelty: string[] = [];
  for (const s of all) {
    // Table rows ("| cmd | role |") are evidence, not steps.
    if (ACTION_RE.test(s) && !/^\|/.test(s)) {
      const strong = hasArtifact(s);
      if (strong || PROCEDURE_OBJECT_RE.test(s)) {
        const key = s.toLowerCase().slice(0, 120);
        if (!seenSteps.has(key)) {
          seenSteps.add(key);
          candidates.push({ s, strong });
        }
      }
    }
    if (novelty.length < 5 && NOVELTY_RE.test(s) && s.length <= 400) novelty.push(clip(s));
  }
  const procedureSteps = candidates.length;
  const strongSteps = candidates.filter((c) => c.strong);
  const steps = (strongSteps.length >= 4 ? strongSteps : candidates).slice(0, 12).map((c) => clip(c.s));

  const chainMarkers = (prose.match(CHAIN_RE) ?? []).length;
  const sequenceMarkers = (prose.match(SEQUENCE_RE) ?? []).length + (prose.match(NUMBERED_STEP_RE) ?? []).length;
  const patchNotice = (prose.match(PATCH_RE) ?? []).length;
  const behaviours = input.behaviours ?? BEHAVIOUR_HINTS.filter((re) => re.test(prose)).length;
  const techniques = input.techniques ?? new Set(prose.match(/\bT1\d{3}(?:\.\d{3})?\b/g) ?? []).size;

  const score = Math.min(
    100,
    Math.min(36, procedureSteps * 4) +
      Math.min(18, Math.round(artifacts * 1.2)) +
      Math.min(12, commands * 3) +
      Math.min(10, chainMarkers * 3 + sequenceMarkers) +
      Math.min(14, behaviours * 2) +
      Math.min(10, techniques) -
      (procedureSteps <= 1 ? Math.min(20, patchNotice * 4) : 0),
  );

  const signals: string[] = [];
  const plural = (n: number, one: string, many = `${one}s`) => `${n} ${n === 1 ? one : many}`;
  if (procedureSteps) signals.push(`${plural(procedureSteps, "procedure step")} naming files, commands or tooling`);
  if (chainMarkers || sequenceMarkers >= 2) signals.push(chainMarkers ? "describes the chain in stages" : "describes the steps in sequence");
  if (artifacts) signals.push(`${plural(artifacts, "artifact")} (${Object.keys(byKind).join(", ")})`);
  if (commands) signals.push(plural(commands, "attacker command"));
  if (techniques) signals.push(plural(techniques, "ATT&CK technique"));
  if (behaviours) signals.push(`${plural(behaviours, "kind")} of attacker behaviour`);
  if (novelty.length) signals.push("states something new (technique, variant or tooling)");

  let grade: EmulationGrade;
  const chainShape = chainMarkers >= 1 || sequenceMarkers >= 3;
  if (procedureSteps >= 5 && chainShape && artifacts >= 6 && behaviours >= 3) grade = "chain";
  else if ((procedureSteps >= 3 && artifacts >= 4) || commands >= 3 || (techniques >= 6 && procedureSteps >= 1)) grade = "procedures";
  else if (procedureSteps >= 1 || techniques >= 1 || artifacts >= 4 || behaviours >= 4) grade = "context";
  else grade = "news";
  // A vulnerability or patch notice that names a few file names is still a notice.
  // Behaviour words in a notice ("ransomware groups have exploited earlier flaws") are background.
  if (grade !== "news" && patchNotice >= 2 && procedureSteps <= 1 && commands === 0 && techniques === 0 && artifacts < 4) {
    grade = "news";
    signals.unshift("patch / vulnerability notice without attacker procedures");
  }
  if (grade === "news" && !signals.length) signals.push("no attacker procedures, artifacts or techniques described");

  return {
    version: EMULATION_VALUE_VERSION,
    grade,
    score: Math.max(0, score),
    signals,
    steps,
    novelty,
    artifacts: byKind,
    stats: { procedureSteps, artifacts, commands, chainMarkers, sequenceMarkers, behaviours, techniques, patchNotice },
  };
}

/** The AI's grounded verdict (./report-ai-analysis), stored beside the rules' grade. */
export type EmulationAiVerdict = { grade: EmulationGrade; reproducible: "yes" | "partly" | "no"; verifiedSteps: number; at: string };

/** Compact form stored on a report and sent with list items. */
export type EmulationSummary = Pick<EmulationValue, "version" | "grade" | "score" | "signals" | "steps" | "novelty"> & { ai?: EmulationAiVerdict };

/** The grade the Library uses: the AI's grounded grade when there is one, else the rules' grade. */
export function effectiveGrade(v: EmulationSummary | null | undefined): EmulationGrade | null {
  return v ? (v.ai?.grade ?? v.grade) : null;
}

export function summarizeEmulation(v: EmulationValue): EmulationSummary {
  return { version: v.version, grade: v.grade, score: v.score, signals: v.signals.slice(0, 6), steps: v.steps.slice(0, 12), novelty: v.novelty.slice(0, 5) };
}

/** A stored summary read back from the database (anything malformed is dropped). */
export function storedEmulation(v: unknown): EmulationSummary | undefined {
  if (!v || typeof v !== "object") return undefined;
  const o = v as Record<string, unknown>;
  const strings = (x: unknown, n: number) => (Array.isArray(x) ? x.filter((s): s is string => typeof s === "string").slice(0, n) : []);
  const ai = o.ai as Record<string, unknown> | undefined;
  const aiVerdict: EmulationAiVerdict | undefined =
    ai && typeof ai === "object" && isEmulationGrade(ai.grade)
      ? {
          grade: ai.grade,
          reproducible: ai.reproducible === "yes" || ai.reproducible === "partly" ? ai.reproducible : "no",
          verifiedSteps: Number(ai.verifiedSteps) || 0,
          at: typeof ai.at === "string" ? ai.at : "",
        }
      : undefined;
  // Only the AI's verdict (rules not run yet): its grade stands in.
  const grade = isEmulationGrade(o.grade) ? o.grade : aiVerdict?.grade;
  if (!grade) return undefined;
  return {
    ...(aiVerdict ? { ai: aiVerdict } : {}),
    version: Number(o.version) || 0,
    grade,
    score: Math.max(0, Math.min(100, Number(o.score) || 0)),
    signals: strings(o.signals, 6),
    steps: strings(o.steps, 12),
    novelty: strings(o.novelty, 5),
  };
}

export function isEmulationGrade(v: unknown): v is EmulationGrade {
  return typeof v === "string" && (EMULATION_GRADES as string[]).includes(v);
}
