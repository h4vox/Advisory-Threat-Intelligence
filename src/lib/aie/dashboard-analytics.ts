import type {
  ActorReferenceProfile,
  CveReferenceMeta,
  ThreatRegionStats,
  TacticDistributionStats,
  MonitoredActorItem,
  CveVelocityItem,
  ThreatFlowItem,
  AttackHeatmapCell,
} from "./types";

// ---------------------------------------------------------------------------
// Honest dashboard analytics
//
// Every count, percentage and list produced here is derived ONLY from the
// reports passed in. The two static catalogs below are curated *reference*
// metadata (actor background, CVE CVSS/exploit status). They are used solely
// to (a) merge known aliases and (b) attach clearly-labelled reference context
// to entities that were actually observed in reports. They never create
// entries or inflate counts. `computeDashboardAnalytics([])` returns zeros and
// empty lists.
// ---------------------------------------------------------------------------

// Reference actor/tool profiles (curated, NOT observed) used for alias merging
// and labelled background context.
interface ActorProfileDef {
  name: string;
  aliases: string[];
  type: string;
  originCountry: string;
  flag: string;
  defaultBadge: string;
  defaultFocus: string;
  defaultSectors: string[];
}

const KNOWN_ACTOR_PROFILES: ActorProfileDef[] = [
  {
    name: "Volt Typhoon",
    aliases: ["volt typhoon", "bronze silhouette", "vanguard panda", "storm-0391"],
    type: "Nation-State Espionage",
    originCountry: "East Asia (China)",
    flag: "🇨🇳",
    defaultBadge: "APT",
    defaultFocus: "Living-off-the-Land, WMI, PowerShell, Router Proxy",
    defaultSectors: ["Critical Infrastructure", "Ports & Maritime", "Energy", "Telecommunications"],
  },
  {
    name: "Scattered Spider",
    aliases: ["scattered spider", "unc3944", "roast 0ktapus", "storm-0875"],
    type: "E-Crime / Extortion",
    originCountry: "North America / Transnational",
    flag: "🌐",
    defaultBadge: "UNC",
    defaultFocus: "SIM Swapping, Okta SSO Takeover, MFA Push Fatigue",
    defaultSectors: ["Hospitality & Gaming", "Cloud Providers", "Retail", "Financial Technology"],
  },
  {
    name: "Midnight Blizzard",
    aliases: ["midnight blizzard", "apt29", "nobelium", "cozy bear"],
    type: "Foreign Intelligence (SVR)",
    originCountry: "Eastern Europe (Russia)",
    flag: "🇷🇺",
    defaultBadge: "APT",
    defaultFocus: "OAuth Consent Grants, Entra ID Token Replay, Graph API",
    defaultSectors: ["Government & Diplomacy", "Defense Industrial Base", "NGOs & Think Tanks"],
  },
  {
    name: "Lazarus Group",
    aliases: ["lazarus", "hidden cobra", "zinc", "apt38"],
    type: "State-Sponsored / Cybercrime",
    originCountry: "East Asia (DPRK)",
    flag: "🇰🇵",
    defaultBadge: "APT",
    defaultFocus: "Trojanized npm/pip Packages, Cross-Chain Bridges, C2 Tunneling",
    defaultSectors: ["Cryptocurrency & Web3", "Defense Aerospace", "Financial Institutions"],
  },
  {
    name: "Sandworm",
    aliases: ["sandworm", "apt44", "voodoo bear", "blackenergy", "telebots"],
    type: "Military Intelligence (GRU)",
    originCountry: "Eastern Europe (Russia)",
    flag: "🇷🇺",
    defaultBadge: "APT",
    defaultFocus: "OT/SCADA Interruption, C2 Data Wipers, Microcontroller Flashing",
    defaultSectors: ["Energy Grid & Power", "Logistics & Rail", "Government Utilities"],
  },
  {
    name: "LockBit 3.0",
    aliases: ["lockbit", "lockbit 3.0", "lockbit black", "lockbit green"],
    type: "Ransomware-as-a-Service",
    originCountry: "Transnational Cartel",
    flag: "🏴‍☠️",
    defaultBadge: "RaaS",
    defaultFocus: "Shadow Copy Inhibit, PsExec Lateral Spreading, StealBit",
    defaultSectors: ["Healthcare Systems", "Manufacturing", "Education", "Municipalities"],
  },
  {
    name: "Akira Ransomware",
    aliases: ["akira", "akira ransomware"],
    type: "Ransomware Cartel",
    originCountry: "Transnational Cartel",
    flag: "🏴‍☠️",
    defaultBadge: "RaaS",
    defaultFocus: "AuKill Driver Termination, Cisco VPN Compromise, BYOVD",
    defaultSectors: ["Professional Services", "Manufacturing", "Finance"],
  },
  {
    name: "Black Basta",
    aliases: ["black basta", "basta"],
    type: "Extortion Syndicate",
    originCountry: "Transnational Cartel",
    flag: "🏴‍☠️",
    defaultBadge: "RaaS",
    defaultFocus: "Voice Phishing Teams Helpdesk, Quick Assist, Chisel Proxy",
    defaultSectors: ["Healthcare", "Information Technology", "Critical Manufacturing"],
  },
  {
    name: "Mustang Panda",
    aliases: ["mustang panda", "bronze president", "reddelta", "camaro dragon"],
    type: "Cyber Espionage (APT)",
    originCountry: "East Asia (China)",
    flag: "🇨🇳",
    defaultBadge: "APT",
    defaultFocus: "PlugX DLL Side-Loading, USB Worm Propagation, SmugX Lures",
    defaultSectors: ["Foreign Ministries", "Diplomatic Channels", "ASEAN Government"],
  },
  {
    name: "MuddyWater",
    aliases: ["muddywater", "static kitten", "mango sandstorm", "mercury"],
    type: "Cyber Espionage (MOIS)",
    originCountry: "Middle East (Iran)",
    flag: "🇮🇷",
    defaultBadge: "APT",
    defaultFocus: "SimpleHelp RMM Abuse, Ligolo Reverse Tunnel, Macro Phishing",
    defaultSectors: ["Telecommunications", "Aviation & Maritime", "Oil & Petrochemicals"],
  },
  {
    name: "FIN7",
    aliases: ["fin7", "carbanak", "sangria storm", "elbrus"],
    type: "Organized Cybercrime",
    originCountry: "Eastern Europe",
    flag: "🌐",
    defaultBadge: "FIN",
    defaultFocus: "Weaponized Office Documents, Carbanak In-Memory Injection",
    defaultSectors: ["Retail Hospitality", "Financial Services", "Point-of-Sale"],
  },
  {
    name: "Flax Typhoon",
    aliases: ["flax typhoon", "storm-0919", "ethereal panda"],
    type: "Espionage & Subversion",
    originCountry: "East Asia (China)",
    flag: "🇨🇳",
    defaultBadge: "APT",
    defaultFocus: "SoftEther VPN, Disruption-Resistant SOHO Proxy Network",
    defaultSectors: ["Defense Contractors", "Government Agencies", "Higher Education"],
  },
  {
    name: "Cobalt Strike Beacon",
    aliases: ["cobalt strike", "cobaltstrike"],
    type: "Offensive Command & Control",
    originCountry: "Commercial / Dual-Use",
    flag: "🛠️",
    defaultBadge: "TOOL",
    defaultFocus: "Malleable C2 Profiles, Process Hollowing, Named Pipes Staging",
    defaultSectors: ["Enterprise Windows Domains", "Active Directory Forests"],
  },
  {
    name: "Mimikatz",
    aliases: ["mimikatz"],
    type: "Credential Extraction Suite",
    originCountry: "Dual-Use Security Tool",
    flag: "🛠️",
    defaultBadge: "TOOL",
    defaultFocus: "LSASS Process Dumping, Pass-the-Hash, Golden Ticket Forgery",
    defaultSectors: ["Domain Controllers", "Enterprise Workstations"],
  },
  {
    name: "Chisel Tunnel",
    aliases: ["chisel"],
    type: "TCP/UDP Tunneling Utility",
    originCountry: "Open Source Proxy",
    flag: "🛠️",
    defaultBadge: "TOOL",
    defaultFocus: "Encrypted HTTP/WebSocket Tunneling, Firewall Evasion",
    defaultSectors: ["DMZ Gateways", "Internal Segmentation"],
  },
];

// Curated CVE reference metadata (NOT observed from reports; shown as "reference").
interface KnownCveMeta {
  vendorProduct: string;
  cvss: number;
  severity: "critical" | "high" | "medium";
  status: "In the Wild" | "Weaponized" | "PoC Published";
}

const KNOWN_CVE_CATALOG: Record<string, KnownCveMeta> = {
  "CVE-2024-21887": {
    vendorProduct: "Ivanti Connect Secure Command Injection",
    cvss: 9.1,
    severity: "critical",
    status: "In the Wild",
  },
  "CVE-2023-34362": {
    vendorProduct: "Progress MOVEit Transfer SQL Injection",
    cvss: 9.8,
    severity: "critical",
    status: "In the Wild",
  },
  "CVE-2024-3400": {
    vendorProduct: "Palo Alto Networks PAN-OS GlobalProtect Command Injection",
    cvss: 10.0,
    severity: "critical",
    status: "In the Wild",
  },
  "CVE-2024-1709": {
    vendorProduct: "ConnectWise ScreenConnect Authentication Bypass",
    cvss: 10.0,
    severity: "critical",
    status: "In the Wild",
  },
  "CVE-2023-46805": {
    vendorProduct: "Ivanti Policy Secure Authentication Bypass",
    cvss: 8.2,
    severity: "high",
    status: "In the Wild",
  },
  "CVE-2023-22515": {
    vendorProduct: "Atlassian Confluence Broken Access Control",
    cvss: 9.8,
    severity: "critical",
    status: "Weaponized",
  },
  "CVE-2024-27198": {
    vendorProduct: "JetBrains TeamCity Authentication Bypass",
    cvss: 9.8,
    severity: "critical",
    status: "Weaponized",
  },
  "CVE-2023-20198": {
    vendorProduct: "Cisco IOS XE Web UI Privilege Escalation",
    cvss: 10.0,
    severity: "critical",
    status: "In the Wild",
  },
  "CVE-2023-23397": {
    vendorProduct: "Microsoft Outlook NTLM Credential Stealing",
    cvss: 9.8,
    severity: "critical",
    status: "In the Wild",
  },
  "CVE-2024-23897": {
    vendorProduct: "Jenkins CLI Arbitrary File Read",
    cvss: 9.8,
    severity: "critical",
    status: "PoC Published",
  },
};

// Canonical MITRE ATT&CK Enterprise tactics in kill-chain order.
const ENTERPRISE_TACTICS: Array<{ id: string; name: string; aliases: string[] }> = [
  { id: "TA0043", name: "Reconnaissance", aliases: ["reconnaissance", "recon"] },
  { id: "TA0042", name: "Resource Development", aliases: ["resource development"] },
  { id: "TA0001", name: "Initial Access", aliases: ["initial access"] },
  { id: "TA0002", name: "Execution", aliases: ["execution"] },
  { id: "TA0003", name: "Persistence", aliases: ["persistence"] },
  { id: "TA0004", name: "Privilege Escalation", aliases: ["privilege escalation", "priv escalation", "privesc"] },
  { id: "TA0005", name: "Defense Evasion", aliases: ["defense evasion", "defence evasion", "stealth", "defense impairment"] },
  { id: "TA0006", name: "Credential Access", aliases: ["credential access"] },
  { id: "TA0007", name: "Discovery", aliases: ["discovery"] },
  { id: "TA0008", name: "Lateral Movement", aliases: ["lateral movement"] },
  { id: "TA0009", name: "Collection", aliases: ["collection"] },
  { id: "TA0011", name: "Command and Control", aliases: ["command and control", "command & control", "c2", "c&c"] },
  { id: "TA0010", name: "Exfiltration", aliases: ["exfiltration"] },
  { id: "TA0040", name: "Impact", aliases: ["impact"] },
];

const NON_ACTOR_VALUES = new Set(["", "none", "none identified", "unknown", "n/a", "na", "unattributed", "null"]);

function asStringArray(v: unknown): string[] {
  if (!Array.isArray(v)) return [];
  return v.filter((x): x is string => typeof x === "string").map((x) => x.trim()).filter(Boolean);
}

function isMeaningfulName(name: string): boolean {
  return !NON_ACTOR_VALUES.has(name.trim().toLowerCase());
}

function escapeRegExp(s: string): string {
  return s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

/** True when `alias` equals `name` or appears in it as a whole word/phrase (case-insensitive). */
function nameMatchesAlias(name: string, alias: string): boolean {
  const n = name.toLowerCase();
  const a = alias.toLowerCase();
  if (n === a) return true;
  return new RegExp(`(^|[^a-z0-9])${escapeRegExp(a)}([^a-z0-9]|$)`, "i").test(n);
}

function findProfile(name: string): ActorProfileDef | undefined {
  return KNOWN_ACTOR_PROFILES.find(
    (p) => nameMatchesAlias(name, p.name) || p.aliases.some((a) => nameMatchesAlias(name, a)),
  );
}

function resolveTactic(raw: unknown): (typeof ENTERPRISE_TACTICS)[number] | undefined {
  if (typeof raw !== "string") return undefined;
  const t = raw.trim().toLowerCase();
  if (!t) return undefined;
  const idMatch = t.match(/ta\d{4}/i);
  if (idMatch) {
    const byId = ENTERPRISE_TACTICS.find((x) => x.id.toLowerCase() === idMatch[0].toLowerCase());
    if (byId) return byId;
  }
  const normalized = t.replace(/&/g, "and").replace(/\s+/g, " ");
  return ENTERPRISE_TACTICS.find((x) =>
    x.aliases.some((a) => {
      const na = a.replace(/&/g, "and");
      return normalized === na || normalized.includes(na);
    }),
  );
}

/** Parses "T1059.001 - PowerShell", "T1059.001: PowerShell", "T1059" or {id, name}. */
function parseTechnique(raw: unknown): { id: string; name: string } | undefined {
  if (raw && typeof raw === "object") {
    const o = raw as { id?: unknown; name?: unknown };
    const id = typeof o.id === "string" ? o.id.trim() : "";
    const name = typeof o.name === "string" ? o.name.trim() : "";
    if (!id && !name) return undefined;
    return { id: id || name, name: name || id };
  }
  if (typeof raw !== "string") return undefined;
  const str = raw.trim();
  if (!str) return undefined;
  const m = str.match(/^(T\d{4}(?:\.\d{3})?)\s*(?:[-:–—|]\s*)?(.*)$/i);
  if (m) {
    const id = m[1].toUpperCase();
    return { id, name: m[2]?.trim() || id };
  }
  return { id: str, name: str };
}

type ReportLike = {
  id?: string;
  title?: string;
  analysis?: {
    threatActors?: unknown;
    malware?: unknown;
    vulnerabilities?: unknown;
    attackChain?: unknown;
  };
  extractedEntities?: {
    threatActors?: unknown;
    malwareFamilies?: unknown;
    cves?: unknown;
    techniques?: unknown;
  };
};

export function computeDashboardAnalytics(reports: unknown[]): {
  threatRegions: ThreatRegionStats[];
  tacticDistribution: TacticDistributionStats[];
  topThreatActors: MonitoredActorItem[];
  cveVelocity: CveVelocityItem[];
  threatFlows: ThreatFlowItem[];
  attackHeatmap: AttackHeatmapCell[];
} {
  const list: ReportLike[] = Array.isArray(reports)
    ? reports.filter((r): r is ReportLike => !!r && typeof r === "object")
    : [];

  // -------------------------------------------------------------------------
  // 1. Threat actors / toolsets: count reports naming them (aliases merged).
  // -------------------------------------------------------------------------
  type ActorAgg = {
    displayName: string;
    profile?: ActorProfileDef;
    reportIds: Set<string | number>;
    sampleReportId?: string;
    tools: Map<string, { name: string; count: number }>;
  };
  const actorAgg = new Map<string, ActorAgg>();

  list.forEach((r, idx) => {
    const reportKey = r.id ?? idx;
    const actorNames = [
      ...asStringArray(r.analysis?.threatActors),
      ...asStringArray(r.extractedEntities?.threatActors),
    ].filter(isMeaningfulName);
    const malwareNames = [
      ...asStringArray(r.analysis?.malware),
      ...asStringArray(r.extractedEntities?.malwareFamilies),
    ].filter(isMeaningfulName);

    // Resolve names to aggregation keys (profile name or normalized raw name).
    const keysInReport = new Map<string, { display: string; profile?: ActorProfileDef }>();
    for (const n of actorNames) {
      const profile = findProfile(n);
      const key = profile ? `profile:${profile.name}` : `raw:${n.toLowerCase()}`;
      if (!keysInReport.has(key)) keysInReport.set(key, { display: profile?.name ?? n, profile });
    }
    // Malware/tool names count only when they match a curated tool/actor profile.
    for (const n of malwareNames) {
      const profile = findProfile(n);
      if (!profile) continue;
      const key = `profile:${profile.name}`;
      if (!keysInReport.has(key)) keysInReport.set(key, { display: profile.name, profile });
    }

    for (const [key, { display, profile }] of keysInReport) {
      const agg = actorAgg.get(key) ?? {
        displayName: display,
        profile,
        reportIds: new Set<string | number>(),
        tools: new Map<string, { name: string; count: number }>(),
      };
      if (agg.reportIds.has(reportKey)) continue;
      agg.reportIds.add(reportKey);
      if (r.id && !agg.sampleReportId) agg.sampleReportId = r.id;
      const seenTools = new Set<string>();
      for (const m of malwareNames) {
        const tk = m.toLowerCase();
        if (seenTools.has(tk)) continue;
        if (profile && nameMatchesAlias(m, profile.name)) continue;
        if (profile && profile.aliases.some((a) => nameMatchesAlias(m, a))) continue;
        seenTools.add(tk);
        const t = agg.tools.get(tk) ?? { name: m, count: 0 };
        t.count++;
        agg.tools.set(tk, t);
      }
      actorAgg.set(key, agg);
    }
  });

  const topThreatActors: MonitoredActorItem[] = Array.from(actorAgg.values())
    .filter((a) => a.reportIds.size > 0)
    .map((a): MonitoredActorItem => {
      const reference: ActorReferenceProfile | undefined = a.profile
        ? {
            type: a.profile.type,
            originCountry: a.profile.originCountry,
            flag: a.profile.flag,
            focus: a.profile.defaultFocus,
            badge: a.profile.defaultBadge,
            targetSectors: a.profile.defaultSectors.slice(0, 3),
          }
        : undefined;
      return {
        name: a.displayName,
        reportCount: a.reportIds.size,
        sampleReportId: a.sampleReportId,
        badge: reference?.badge ?? "ACTOR",
        associatedTools: Array.from(a.tools.values())
          .sort((x, y) => y.count - x.count || x.name.localeCompare(y.name))
          .slice(0, 3)
          .map((t) => t.name),
        reference,
      };
    })
    .sort((a, b) => b.reportCount - a.reportCount || a.name.localeCompare(b.name))
    .slice(0, 20);

  // -------------------------------------------------------------------------
  // 2. CVEs: count reports referencing each CVE id.
  // -------------------------------------------------------------------------
  const cveAgg = new Map<
    string,
    { reportIds: Set<string | number>; sampleTitle?: string; sampleId?: string; actors: Set<string> }
  >();
  const CVE_RE = /CVE-\d{4}-\d{4,7}/gi;

  list.forEach((r, idx) => {
    const reportKey = r.id ?? idx;
    const ids = new Set<string>();
    for (const raw of [
      ...asStringArray(r.extractedEntities?.cves),
      ...asStringArray(r.analysis?.vulnerabilities),
    ]) {
      for (const m of raw.match(CVE_RE) ?? []) ids.add(m.toUpperCase());
    }
    if (typeof r.title === "string") {
      for (const m of r.title.match(CVE_RE) ?? []) ids.add(m.toUpperCase());
    }
    const actors = [
      ...asStringArray(r.analysis?.threatActors),
      ...asStringArray(r.extractedEntities?.threatActors),
    ].filter(isMeaningfulName);

    for (const cveId of ids) {
      const entry = cveAgg.get(cveId) ?? { reportIds: new Set<string | number>(), actors: new Set<string>() };
      if (entry.reportIds.has(reportKey)) continue;
      entry.reportIds.add(reportKey);
      if (!entry.sampleId && r.id) {
        entry.sampleId = r.id;
        entry.sampleTitle = r.title;
      }
      for (const a of actors) entry.actors.add(findProfile(a)?.name ?? a);
      cveAgg.set(cveId, entry);
    }
  });

  const cveVelocity: CveVelocityItem[] = Array.from(cveAgg.entries())
    .map(([cveId, e]): CveVelocityItem => {
      const meta = KNOWN_CVE_CATALOG[cveId];
      const reference: CveReferenceMeta | undefined = meta
        ? { vendorProduct: meta.vendorProduct, cvss: meta.cvss, severity: meta.severity, exploitStatus: meta.status }
        : undefined;
      return {
        cveId,
        reportCount: e.reportIds.size,
        sampleReportId: e.sampleId,
        sampleReportTitle: e.sampleTitle,
        actors: Array.from(e.actors).slice(0, 3),
        reference,
      };
    })
    .sort((a, b) => b.reportCount - a.reportCount || b.cveId.localeCompare(a.cveId))
    .slice(0, 24);

  // -------------------------------------------------------------------------
  // 3. Geography: reports carry no geography field, so nothing is claimed.
  // -------------------------------------------------------------------------
  const threatRegions: ThreatRegionStats[] = [];

  // -------------------------------------------------------------------------
  // 4/5. ATT&CK tactics + techniques from analysis.attackChain.
  // -------------------------------------------------------------------------
  type TacticAgg = {
    steps: number;
    reportIds: Set<string | number>;
    techniques: Map<string, { name: string; count: number }>;
  };
  const tacticAgg = new Map<string, TacticAgg>();
  const getTactic = (id: string): TacticAgg => {
    let t = tacticAgg.get(id);
    if (!t) {
      t = { steps: 0, reportIds: new Set(), techniques: new Map() };
      tacticAgg.set(id, t);
    }
    return t;
  };
  const addTechnique = (agg: TacticAgg, rawTech: unknown) => {
    const tech = parseTechnique(rawTech);
    if (!tech) return;
    const key = tech.id.toUpperCase();
    const cur = agg.techniques.get(key) ?? { name: tech.name, count: 0 };
    cur.count++;
    if (cur.name === tech.id && tech.name !== tech.id) cur.name = tech.name;
    agg.techniques.set(key, cur);
  };

  list.forEach((r, idx) => {
    const reportKey = r.id ?? idx;
    const chain = Array.isArray(r.analysis?.attackChain) ? (r.analysis?.attackChain as unknown[]) : [];
    if (chain.length > 0) {
      for (const rawStep of chain) {
        if (!rawStep || typeof rawStep !== "object") continue;
        const step = rawStep as { tactic?: unknown; techniques?: unknown };
        const tactic = resolveTactic(step.tactic);
        if (!tactic) continue;
        const agg = getTactic(tactic.id);
        agg.steps++;
        agg.reportIds.add(reportKey);
        if (Array.isArray(step.techniques)) for (const t of step.techniques) addTechnique(agg, t);
      }
      return;
    }
    // Fallback for reports without an attack chain: extracted techniques with a tactic.
    const extracted = Array.isArray(r.extractedEntities?.techniques)
      ? (r.extractedEntities?.techniques as unknown[])
      : [];
    for (const rawTech of extracted) {
      if (!rawTech || typeof rawTech !== "object") continue;
      const tactic = resolveTactic((rawTech as { tactic?: unknown }).tactic);
      if (!tactic) continue;
      const agg = getTactic(tactic.id);
      agg.steps++;
      agg.reportIds.add(reportKey);
      addTechnique(agg, rawTech);
    }
  });

  const maxSteps = Math.max(0, ...Array.from(tacticAgg.values()).map((t) => t.steps));
  const pctOf = (n: number) => (maxSteps > 0 ? Math.round((n / maxSteps) * 100) : 0);

  const tacticDistribution: TacticDistributionStats[] = ENTERPRISE_TACTICS.map((t) => {
    const agg = tacticAgg.get(t.id);
    const count = agg?.steps ?? 0;
    return { name: t.name, id: t.id, count, reportCount: agg?.reportIds.size ?? 0, pct: pctOf(count) };
  })
    .filter((t) => t.count > 0)
    .sort((a, b) => b.count - a.count);

  const attackHeatmap: AttackHeatmapCell[] = ENTERPRISE_TACTICS.flatMap((t) => {
    const agg = tacticAgg.get(t.id);
    if (!agg || agg.steps === 0) return [];
    const topTechniques = Array.from(agg.techniques.entries())
      .map(([id, v]) => ({ id, name: v.name, count: v.count }))
      .sort((a, b) => b.count - a.count || a.id.localeCompare(b.id))
      .slice(0, 3);
    return [
      {
        tacticId: t.id,
        tacticName: t.name,
        techniqueCount: agg.techniques.size,
        hitCount: agg.steps,
        intensity: pctOf(agg.steps),
        topTechniques,
      },
    ];
  });

  // -------------------------------------------------------------------------
  // 6. Threat flows: no report field supports origin -> vector -> target
  //    correlation, so nothing is fabricated.
  // -------------------------------------------------------------------------
  const threatFlows: ThreatFlowItem[] = [];

  return {
    threatRegions,
    tacticDistribution,
    topThreatActors,
    cveVelocity,
    threatFlows,
    attackHeatmap,
  };
}
