/**
 * Telemetry a report names: Windows event IDs, log sources and the detection content it
 * publishes (KQL, SPL, Sigma, YARA, Suricata/Snort). These are the "expected telemetry" and
 * "required data sources" inputs of a simulation plan.
 *
 * Facts only: every item is something the report itself states, with the sentence that states
 * it. Nothing is inferred from techniques (the Detections tab's ideas do that, labelled as such).
 * Pure and unit-tested.
 */

export type TelemetryEventRef = {
  /** "4688", "Sysmon 1". */
  id: string;
  log: string;
  /** What the event records, when known. */
  meaning?: string;
  quote: string;
};

export type TelemetrySourceRef = { name: string; quote: string };

export type DetectionContentKind = "kql" | "spl" | "sigma" | "yara" | "suricata";
export type DetectionContentRef = { kind: DetectionContentKind; count: number };

export type TelemetryRefs = {
  version: number;
  events: TelemetryEventRef[];
  sources: TelemetrySourceRef[];
  content: DetectionContentRef[];
};

export const TELEMETRY_REFS_VERSION = 1;

const MAX_TEXT = 150_000;

const SECURITY_EVENTS: Record<string, string> = {
  "1102": "audit log cleared",
  "4624": "successful logon",
  "4625": "failed logon",
  "4634": "logoff",
  "4648": "logon with explicit credentials",
  "4662": "directory object accessed",
  "4663": "object accessed",
  "4672": "special privileges assigned",
  "4688": "process created",
  "4697": "service installed",
  "4698": "scheduled task created",
  "4699": "scheduled task deleted",
  "4702": "scheduled task updated",
  "4719": "audit policy changed",
  "4720": "user account created",
  "4722": "user account enabled",
  "4724": "password reset attempt",
  "4728": "member added to global group",
  "4732": "member added to local group",
  "4738": "user account changed",
  "4740": "account locked out",
  "4756": "member added to universal group",
  "4768": "Kerberos TGT requested",
  "4769": "Kerberos service ticket requested",
  "4771": "Kerberos pre-authentication failed",
  "4776": "NTLM credential validation",
  "4794": "DSRM password set",
  "5136": "directory object modified",
  "5140": "network share accessed",
  "5145": "network share object checked",
  "5156": "network connection allowed",
};

const SYSTEM_EVENTS: Record<string, string> = {
  "104": "event log cleared",
  "7034": "service crashed",
  "7036": "service state changed",
  "7040": "service start type changed",
  "7045": "service installed",
};

const POWERSHELL_EVENTS: Record<string, string> = {
  "400": "engine started",
  "800": "pipeline execution",
  "4103": "module logging",
  "4104": "script block logged",
};

const SYSMON_EVENTS: Record<string, string> = {
  "1": "process created",
  "2": "file creation time changed",
  "3": "network connection",
  "5": "process terminated",
  "6": "driver loaded",
  "7": "image loaded",
  "8": "remote thread created",
  "10": "process accessed",
  "11": "file created",
  "12": "registry object added or deleted",
  "13": "registry value set",
  "14": "registry object renamed",
  "15": "alternate data stream created",
  "17": "pipe created",
  "18": "pipe connected",
  "19": "WMI filter",
  "20": "WMI consumer",
  "21": "WMI binding",
  "22": "DNS query",
  "23": "file deleted",
  "25": "process tampering",
  "26": "file deletion logged",
};

const LOG_SOURCES: Array<{ name: string; re: RegExp }> = [
  { name: "Sysmon", re: /\bSysmon\b/ },
  { name: "Windows Security event log", re: /\b(?:Windows\s+)?Security\s+(?:event\s+)?logs?\b|\bSecurity\.evtx\b/i },
  { name: "PowerShell script block / module logging", re: /\bscript\s*block\s+logg\w*|\bmodule\s+logging\b|\bPowerShell\s+(?:Operational|logs?)\b/i },
  { name: "Microsoft Defender XDR advanced hunting", re: /\bDevice(?:Process|Network|File|Registry|Logon|Image|Events)Events\b|\badvanced\s+hunting\b/ },
  { name: "Microsoft Entra ID sign-in logs", re: /\b(?:Entra(?:\s+ID)?|Azure\s+AD)\s+sign-?in\s+logs?\b|\bSigninLogs\b/ },
  { name: "Microsoft Entra ID audit logs", re: /\b(?:Entra(?:\s+ID)?|Azure\s+AD)\s+audit\s+logs?\b|\bAuditLogs\b/ },
  { name: "Microsoft 365 unified audit log", re: /\bunified\s+audit\s+log\b|\bUAL\b|\bPurview\s+audit\b/i },
  { name: "Azure activity log", re: /\bAzure\s+activity\s+logs?\b|\bAzureActivity\b/i },
  { name: "AWS CloudTrail", re: /\bCloudTrail\b/ },
  { name: "AWS VPC Flow Logs", re: /\bVPC\s+flow\s+logs?\b/i },
  { name: "AWS GuardDuty", re: /\bGuardDuty\b/ },
  { name: "Google Cloud audit logs", re: /\b(?:Google\s+)?Cloud\s+Audit\s+Logs?\b/ },
  { name: "Kubernetes audit logs", re: /\bKubernetes\s+audit\s+logs?\b|\bkube-?audit\b/i },
  { name: "Linux auditd", re: /\bauditd\b|\bLinux\s+audit\s+(?:logs?|framework)\b/i },
  { name: "Syslog", re: /(?<![/\w.])syslog(?![\w.])/i },
  { name: "Zeek", re: /\bZeek\b|\bBro\s+logs?\b/ },
  { name: "Suricata / Snort IDS", re: /\bSuricata\b|\bSnort\b/ },
  { name: "DNS logs", re: /\bDNS\s+(?:query\s+)?logs?\b|\bpassive\s+DNS\b/i },
  { name: "Proxy / web gateway logs", re: /\b(?:web\s+)?proxy\s+logs?\b|\bweb\s+gateway\s+logs?\b/i },
  { name: "Firewall logs", re: /\bfirewall\s+logs?\b/i },
  { name: "NetFlow", re: /\bNetFlow\b|\bIPFIX\b/ },
  { name: "Web server access logs", re: /\b(?:IIS|Apache|nginx|web\s+server)\s+(?:access\s+)?logs?\b/i },
  { name: "VPN appliance logs", re: /\bVPN\s+(?:appliance\s+)?logs?\b/i },
  { name: "ESXi logs", re: /\bESXi\s+(?:host\s+)?logs?\b|\bhostd\.log\b|\bshell\.log\b/i },
  { name: "EDR telemetry", re: /\bEDR\s+(?:telemetry|logs?|data)\b/i },
  { name: "Email gateway / message trace", re: /\bmessage\s+trace\b|\bemail\s+gateway\s+logs?\b|\bEmailEvents\b/i },
];

/** The sentence around `index`, trimmed to at most 220 characters. */
function sentenceAt(text: string, index: number, length = 0): string {
  const before = text.lastIndexOf("\n", index);
  const lineStart = before < 0 ? 0 : before + 1;
  const lineEndRaw = text.indexOf("\n", index + length);
  const lineEnd = lineEndRaw < 0 ? text.length : lineEndRaw;
  let start = lineStart;
  for (let i = index - 1; i > lineStart; i--) {
    if (/[.!?]/.test(text[i]) && /\s/.test(text[i + 1] ?? "")) {
      start = i + 2;
      break;
    }
  }
  let end = lineEnd;
  for (let i = index + length; i < lineEnd; i++) {
    if (/[.!?]/.test(text[i]) && (i + 1 >= lineEnd || /\s/.test(text[i + 1]))) {
      end = i + 1;
      break;
    }
  }
  let s = text.slice(start, end).replace(/\s+/g, " ").trim();
  if (s.length > 220) {
    const rel = Math.max(0, index - start - 80);
    s = `${rel > 0 ? "…" : ""}${s.slice(rel, rel + 218).trim()}…`;
  }
  return s;
}

const EVENT_LIST = /\b(?:(Sysmon)\s+)?(?:Event\s?IDs?|EventIDs?|Event\s+codes?|EventCode)\s*[:=#]?\s*((?:\d{1,5})(?:\s*(?:,|\/|and|or|&)\s*\d{1,5}){0,8})/gi;

function eventLog(id: string, context: string, sysmonPrefix: boolean): { log: string; meaning?: string } | null {
  const sysmonNear = sysmonPrefix || /\bSysmon\b/i.test(context);
  if (sysmonNear && SYSMON_EVENTS[id]) return { log: "Sysmon", meaning: SYSMON_EVENTS[id] };
  if (SECURITY_EVENTS[id]) return { log: "Windows Security", meaning: SECURITY_EVENTS[id] };
  if (POWERSHELL_EVENTS[id] && (/\bPowerShell\b/i.test(context) || id === "4103" || id === "4104")) return { log: "PowerShell", meaning: POWERSHELL_EVENTS[id] };
  if (SYSTEM_EVENTS[id]) return { log: "Windows System", meaning: SYSTEM_EVENTS[id] };
  // A small number with no named log is too ambiguous to report.
  if (Number(id) >= 1000) return { log: "Windows event log" };
  return null;
}

function countRe(re: RegExp, text: string, cap = 50): number {
  re.lastIndex = 0;
  let n = 0;
  while (n < cap && re.exec(text)) n++;
  re.lastIndex = 0;
  return n;
}

/** Detection content the text publishes, by kind (rule bodies and queries, not mentions). */
export function countDetectionContent(input: string): DetectionContentRef[] {
  const text = String(input ?? "").slice(0, MAX_TEXT);
  const content: DetectionContentRef[] = [];
  const kql = countRe(/\b(?:Device(?:Process|Network|File|Registry|Logon|Image)Events|DeviceEvents|SigninLogs|AuditLogs|SecurityEvent|CommonSecurityLog|EmailEvents|CloudAppEvents|IdentityLogonEvents|AADSignInEventsBeta|OfficeActivity)\b\s*(?:\n\s*)?\|/g, text);
  if (kql) content.push({ kind: "kql", count: kql });
  const spl = countRe(/\b(?:index|sourcetype)\s*=\s*["']?[\w:-]+["']?[^\n]{0,200}\|\s*(?:stats|table|where|search|eval)\b/g, text);
  if (spl) content.push({ kind: "spl", count: spl });
  const sigma = countRe(/\blogsource:\s*(?:\n|\s)+(?:[\s\S]{0,300}?)\bdetection:\s*[\s\S]{0,1200}?\bcondition:/g, text);
  if (sigma) content.push({ kind: "sigma", count: sigma });
  const yara = countRe(/\brule\s+[A-Za-z_][\w]*\s*(?::\s*[\w\s]+)?\{[\s\S]{0,4000}?\bcondition:/g, text);
  if (yara) content.push({ kind: "yara", count: yara });
  const suricata = countRe(/\balert\s+(?:tcp|udp|http|dns|tls|ip|icmp)\s+\S+\s+\S+\s+->\s+\S+\s+\S+\s+\(/g, text);
  if (suricata) content.push({ kind: "suricata", count: suricata });
  return content;
}

export function extractTelemetryRefs(input: string): TelemetryRefs {
  const text = String(input ?? "").slice(0, MAX_TEXT);
  const events: TelemetryEventRef[] = [];
  const seenEvents = new Set<string>();
  EVENT_LIST.lastIndex = 0;
  for (let m = EVENT_LIST.exec(text); m && events.length < 30; m = EVENT_LIST.exec(text)) {
    const context = text.slice(Math.max(0, m.index - 80), m.index + m[0].length + 80);
    for (const id of m[2].match(/\d{1,5}/g) ?? []) {
      const log = eventLog(id, context, Boolean(m[1]));
      if (!log) continue;
      const key = `${log.log}:${id}`;
      if (seenEvents.has(key)) continue;
      seenEvents.add(key);
      events.push({ id: log.log === "Sysmon" ? `Sysmon ${id}` : id, log: log.log, ...(log.meaning ? { meaning: log.meaning } : {}), quote: sentenceAt(text, m.index, m[0].length) });
    }
  }
  EVENT_LIST.lastIndex = 0;

  const sources: TelemetrySourceRef[] = [];
  for (const src of LOG_SOURCES) {
    // Prefer a sentence of prose over a bare code line (a lone table name says little).
    const re = new RegExp(src.re.source, src.re.flags.includes("g") ? src.re.flags : `${src.re.flags}g`);
    let first: string | null = null;
    let prose: string | null = null;
    let seen = 0;
    for (let m = re.exec(text); m && seen < 12 && !prose; m = re.exec(text), seen++) {
      const q = sentenceAt(text, m.index, m[0].length);
      first ??= q;
      if (q.split(/\s+/).length >= 6 && !/^[|#\-\s]*[\w.]+\s*\|/.test(q)) prose = q;
    }
    if (first) sources.push({ name: src.name, quote: prose ?? first });
  }

  const content = countDetectionContent(text);

  return { version: TELEMETRY_REFS_VERSION, events, sources, content };
}

/** Display nouns: [one, many]. */
export const DETECTION_CONTENT_NOUN: Record<DetectionContentKind, readonly [string, string]> = {
  kql: ["KQL query", "KQL queries"],
  spl: ["SPL search", "SPL searches"],
  sigma: ["Sigma rule", "Sigma rules"],
  yara: ["YARA rule", "YARA rules"],
  suricata: ["Suricata / Snort rule", "Suricata / Snort rules"],
};
