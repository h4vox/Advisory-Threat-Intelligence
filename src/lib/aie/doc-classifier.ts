/**
 * Multi-label document-type classifier (AIE Web Extraction spec §26) and
 * source provenance (tier + confidence, spec §42 / §66).
 *
 * Signals, strongest first:
 *   1. structured payload kind (ATT&CK, atomic, emulation plan, flow, KEV)
 *   2. URL and title patterns (AA2x-xxx, /advisories/, "incident", "campaign")
 *   3. content signals (CVE density, DFIR timeline wording, malware analysis wording)
 *   4. legacy classification / resourceKind from qualifyContent
 *   5. the source registry's `yields` as a prior when nothing else decides
 * Every label carries the reason it was assigned.
 *
 * Pure module (relative imports only) so it runs under `node --test`.
 */
import type { DocType, QualityReason, SourceConfidenceClass, SourceTier, StructuredIntel, TrustLevel } from "./types.ts";
import { SOURCE_CONFIDENCE } from "./types.ts";

export type ClassifyInput = {
  title: string;
  url: string;
  text?: string;
  /** Registry yields of the source the document came from. */
  sourceYields?: DocType[];
  sourceTier?: SourceTier;
  classification?: string;
  resourceKind?: string;
  structuredKind?: StructuredIntel["kind"];
};

export type DocTypeSignal = { docType: DocType; score: number; reason: string };

export type ClassifyResult = { docTypes: DocType[]; signals: DocTypeSignal[] };

const STRUCTURED_KIND: Record<StructuredIntel["kind"], DocType[]> = {
  attack_group: ["MITRE_GROUP"],
  attack_software: ["MITRE_SOFTWARE"],
  attack_campaign: ["MITRE_CAMPAIGN", "CAMPAIGN_REPORT"],
  atomic_test: ["ATOMIC_TEST"],
  emulation_plan: ["ADVERSARY_EMULATION_PLAN"],
  attack_flow: ["ATTACK_FLOW"],
  kev: ["KEV_ENTRY"],
};

const LEGACY: Record<string, DocType> = {
  MALWARE_ANALYSIS: "MALWARE_REPORT",
  VULNERABILITY_ADVISORY: "VULNERABILITY_ADVISORY",
  CAMPAIGN_INTEL: "CAMPAIGN_REPORT",
  CAMPAIGN_REPORT: "CAMPAIGN_REPORT",
  DETECTION_GUIDANCE: "DETECTION_RESEARCH",
  DETECTION_RESEARCH: "DETECTION_RESEARCH",
  SIGMA_RULES: "DETECTION_RESEARCH",
  INTRUSION_REPORT: "INCIDENT_REPORT",
  ATTACK_CHAIN_REPORT: "INCIDENT_REPORT",
  FULL_ATTACK_CHAIN: "INCIDENT_REPORT",
  THREAT_ACTOR_DOSSIER: "THREAT_REPORT",
  THREAT_REPORT: "THREAT_REPORT",
  ADVERSARY_EMULATION: "PURPLE_TEAM_REPORT",
  PURPLE_TEAM: "PURPLE_TEAM_REPORT",
};

const ADVISORY_HOSTS = /(^|\.)(cisa\.gov|ncsc\.gov\.uk|cyber\.gov\.au|cert\.europa\.eu|ic3\.gov|nsa\.gov|cert\.ssi\.gouv\.fr|bsi\.bund\.de|jpcert\.or\.jp|cccs\.gc\.ca|cyber\.gc\.ca)$/i;

function count(re: RegExp, text: string): number {
  const m = text.match(new RegExp(re.source, re.flags.includes("g") ? re.flags : `${re.flags}g`));
  return m ? m.length : 0;
}

function hostOf(url: string): string {
  try {
    return new URL(url).hostname.replace(/^www\./, "").toLowerCase();
  } catch {
    return "";
  }
}

/** Classifies a document into one or more DocTypes (max 4), strongest first. */
export function classifyDocument(input: ClassifyInput): ClassifyResult {
  const signals: DocTypeSignal[] = [];
  const add = (docType: DocType, score: number, reason: string) => signals.push({ docType, score, reason });
  const title = input.title ?? "";
  const url = input.url ?? "";
  const text = (input.text ?? "").slice(0, 200_000);
  const tl = title.toLowerCase();
  const host = hostOf(url);
  const path = (() => {
    try {
      return new URL(url).pathname.toLowerCase();
    } catch {
      return url.toLowerCase();
    }
  })();

  // 1. Structured payloads decide outright.
  if (input.structuredKind) {
    for (const t of STRUCTURED_KIND[input.structuredKind] ?? []) add(t, 10, `Structured ${input.structuredKind.replace(/_/g, " ")} record`);
  }

  // 2. Advisory identifiers and publishers.
  if (/\baa\d{2}-\d{3}[a-z]?\b/i.test(title) || /\/aa\d{2}-\d{3}[a-z]?\b/i.test(path)) add("THREAT_ADVISORY", 6, "Joint advisory id (AA2x-xxx)");
  if (/#?stopransomware/i.test(title) || /stopransomware/.test(path)) add("THREAT_ADVISORY", 5, "#StopRansomware advisory");
  if (/\b(cybersecurity|joint|security|threat) advisory\b/i.test(title) || /\/(cybersecurity-)?advisor(y|ies)\//.test(path)) {
    add("THREAT_ADVISORY", 4, "Advisory in title/URL");
  }
  if (ADVISORY_HOSTS.test(host)) add("THREAT_ADVISORY", 3, `Government CERT publisher (${host})`);

  // 3a. Vulnerability density.
  const cves = new Set((text.match(/\bCVE-\d{4}-\d{4,7}\b/gi) ?? []).map((c) => c.toUpperCase()));
  const titleCve = /\bCVE-\d{4}-\d{4,7}\b/i.test(title);
  const vulnWords = count(/\b(vulnerabilit(y|ies)|exploit(ed|ation)?|patch(ed|es)?|zero-day|0-day|remote code execution|rce)\b/i, text);
  if (titleCve || /\b(vulnerabilit|zero-day|0-day|exploited|patch)/i.test(title)) add("VULNERABILITY_ADVISORY", 5, titleCve ? "CVE in title" : "Vulnerability wording in title");
  if (cves.size >= 3 && vulnWords >= 3) add("VULNERABILITY_ADVISORY", 4, `${cves.size} CVEs with exploitation wording`);
  else if (cves.size >= 1 && vulnWords >= 6) add("VULNERABILITY_ADVISORY", 2, `CVE with sustained exploitation wording`);

  // 3b. DFIR / incident wording.
  const dfirHits = count(
    /\b(time to ransom|ttr|dwell time|initial access broker|day \d+|hands-on-keyboard|we observed the threat actor|the threat actor (then|next)|forensic|dfir|incident response|timeline of (the )?(intrusion|attack)|lateral movement to)\b/i,
    text,
  );
  const incidentHits = count(/\b(intrusion|incident|breach(ed)?|compromise[ds]?|victim (environment|network|organization))\b/i, text);
  if (/\b(dfir|intrusion|incident response|case study)\b/i.test(title) || host === "thedfirreport.com") add("DFIR_REPORT", 5, "DFIR / intrusion report title or publisher");
  if (dfirHits >= 4) add("DFIR_REPORT", 3 + Math.min(2, dfirHits / 6), `${dfirHits} DFIR timeline signals`);
  if (/\b(incident|breach|intrusion|compromise)\b/i.test(title)) add("INCIDENT_REPORT", 4, "Incident wording in title");
  if (incidentHits >= 8) add("INCIDENT_REPORT", 2 + Math.min(2, incidentHits / 15), `${incidentHits} incident/intrusion mentions`);

  // 3c. Malware family analysis.
  const malwareHits = count(
    /\b(sample|payload|loader|backdoor|stealer|infostealer|rat\b|dropper|implant|unpack(ed|ing)?|decrypt(s|ed|ion)?|obfuscat(ed|ion)|reverse[- ]engineer(ed|ing)?|c2 (protocol|configuration|server)|string decryption|sha-?256|malware family|variant)\b/i,
    text,
  );
  if (/\b(malware|loader|backdoor|stealer|ransomware|rat|botnet|implant|trojan|wiper|variant|analysis of)\b/i.test(title)) {
    add("MALWARE_REPORT", 3.5, "Malware wording in title");
  }
  if (malwareHits >= 8) add("MALWARE_REPORT", 3 + Math.min(2, malwareHits / 20), `${malwareHits} malware-analysis signals`);

  // 3d. Campaigns.
  const campaignHits = count(/\b(campaign|operation [A-Z][a-z]+|cluster|activity group)\b/i, text);
  if (/\b(campaign|operation)\b/i.test(title)) add("CAMPAIGN_REPORT", 4.5, "Campaign wording in title");
  if (campaignHits >= 4) add("CAMPAIGN_REPORT", 2 + Math.min(2, campaignHits / 10), `${campaignHits} campaign mentions`);

  // 3e. Detection / hunting / purple team.
  const detectHits = count(/\b(sigma|yara|kql|splunk|spl query|detection rule|detection opportunit(y|ies)|detection engineering|eql|elastic rule)\b/i, text);
  if (/\b(detect(ion|ing)?|sigma|yara)\b/i.test(title)) add("DETECTION_RESEARCH", 3.5, "Detection wording in title");
  if (detectHits >= 4) add("DETECTION_RESEARCH", 2 + Math.min(2, detectHits / 10), `${detectHits} detection-content signals`);
  const huntHits = count(/\b(threat hunt(ing)?|hunting quer(y|ies)|hunt for|hypothesis)\b/i, text);
  if (/\bhunt(ing)?\b/i.test(title)) add("THREAT_HUNTING_REPORT", 4, "Hunting wording in title");
  if (huntHits >= 3) add("THREAT_HUNTING_REPORT", 2 + Math.min(2, huntHits / 6), `${huntHits} threat-hunting signals`);
  if (/\b(purple team|adversary emulation|emulation plan|red team)\b/i.test(tl) || count(/\b(purple team(ing)?|adversary emulation|emulation plan)\b/i, text) >= 3) {
    add("PURPLE_TEAM_REPORT", 3.5, "Purple-team / emulation wording");
  }
  if (/\batomic red team\b/i.test(tl)) add("ATOMIC_TEST", 3, "Atomic Red Team in title");
  if (/\battack flow\b/i.test(tl)) add("ATTACK_FLOW", 3, "Attack Flow in title");

  // 4. Legacy qualifier output.
  for (const legacy of [input.classification, input.resourceKind]) {
    const mapped = legacy ? LEGACY[legacy] : undefined;
    if (mapped) add(mapped, 1.5, `Qualifier classification ${legacy}`);
  }

  // 5. Source prior.
  const yields = input.sourceYields ?? [];
  if (yields.length) {
    add(yields[0], 1.2, "Primary type for this source");
    for (const y of yields.slice(1)) add(y, 0.6, "Source commonly publishes this type");
    if (input.sourceTier === 1 && yields.includes("THREAT_ADVISORY")) add("THREAT_ADVISORY", 2.5, "Tier-1 advisory publisher");
  }

  // Aggregate: sum per type, keep the strongest reason.
  const agg = new Map<DocType, { score: number; best: DocTypeSignal }>();
  for (const s of signals) {
    const cur = agg.get(s.docType);
    if (!cur) agg.set(s.docType, { score: s.score, best: s });
    else {
      cur.score += s.score;
      if (s.score > cur.best.score) cur.best = s;
    }
  }
  const ranked = [...agg.entries()].sort((a, b) => b[1].score - a[1].score);
  const top = ranked[0]?.[1].score ?? 0;
  const threshold = input.structuredKind ? 10 : Math.max(2.4, top * 0.35);
  let docTypes = ranked.filter(([, v]) => v.score >= threshold).map(([t]) => t).slice(0, 4);
  if (docTypes.length === 0) docTypes = [ranked[0]?.[0] ?? "THREAT_REPORT"];
  // A narrative report with no narrative type gets the generic THREAT_REPORT label.
  const NARRATIVE: DocType[] = ["THREAT_ADVISORY", "INCIDENT_REPORT", "DFIR_REPORT", "MALWARE_REPORT", "VULNERABILITY_ADVISORY", "CAMPAIGN_REPORT", "DETECTION_RESEARCH", "THREAT_HUNTING_REPORT", "PURPLE_TEAM_REPORT"];
  if (!input.structuredKind && !docTypes.some((t) => NARRATIVE.includes(t) || t === "THREAT_REPORT")) docTypes.unshift("THREAT_REPORT");
  return {
    docTypes: docTypes.slice(0, 4),
    signals: ranked.map(([docType, v]) => ({ docType, score: Math.round(v.score * 10) / 10, reason: v.best.reason })),
  };
}

// ---------------------------------------------------------------------------
// Source provenance
// ---------------------------------------------------------------------------

export type ProvenanceSource = {
  id?: string;
  name?: string;
  tier?: SourceTier;
  trustLevel?: TrustLevel;
  confidenceClass?: SourceConfidenceClass;
  yields?: DocType[];
  isDiscovered?: boolean;
};

/** Spec §42 confidence class for a source (explicit registry value wins). */
export function confidenceClassFor(source: ProvenanceSource | undefined | null): SourceConfidenceClass {
  if (!source) return "UNKNOWN";
  if (source.confidenceClass) return source.confidenceClass;
  if (source.isDiscovered) return source.trustLevel === "reputable" ? "SECONDARY_RESEARCH" : "COMMUNITY";
  switch (source.trustLevel) {
    case "official":
      return source.tier === 1 ? "OFFICIAL_PRIMARY" : "TRUSTED_VENDOR";
    case "high":
      return source.tier === 2 ? "RESEARCH_ORG" : "TRUSTED_VENDOR";
    case "reputable":
      return "SECONDARY_RESEARCH";
    case "community":
      return "COMMUNITY";
    default:
      return "UNKNOWN";
  }
}

export function tierFor(source: ProvenanceSource | undefined | null): SourceTier {
  if (source?.tier) return source.tier;
  if (!source || source.isDiscovered) return 4;
  return source.trustLevel === "community" || source.trustLevel === "unverified" ? 4 : 3;
}

export type ReportProvenance = {
  docTypes: DocType[];
  sourceTier: SourceTier;
  sourceConfidence: number;
  qualityReasons: QualityReason[];
};

/**
 * docTypes + tier + confidence for a crawled/ingested report.
 * sourceConfidence = class weight × (qualityScore / 100), explained in an
 * appended quality reason (delta 0: the quality score itself is unchanged).
 */
export function annotateReportProvenance(input: {
  source: ProvenanceSource | undefined | null;
  title: string;
  url: string;
  text: string;
  qualityScore: number;
  qualityReasons: QualityReason[];
  classification?: string;
  resourceKind?: string;
}): ReportProvenance {
  const cls = confidenceClassFor(input.source);
  const tier = tierFor(input.source);
  const weight = SOURCE_CONFIDENCE[cls];
  const quality = Math.max(0, Math.min(100, input.qualityScore)) / 100;
  const sourceConfidence = Math.round(weight * quality * 100) / 100;
  const { docTypes, signals } = classifyDocument({
    title: input.title,
    url: input.url,
    text: input.text,
    sourceYields: input.source?.yields,
    sourceTier: tier,
    classification: input.classification,
    resourceKind: input.resourceKind,
  });
  const why = signals
    .filter((s) => docTypes.includes(s.docType))
    .map((s) => `${s.docType} (${s.reason})`)
    .join("; ");
  const qualityReasons = [
    ...input.qualityReasons.filter((r) => !r.label.startsWith("Source confidence") && !r.label.startsWith("Document type")),
    { label: `Source confidence ${cls} ×${weight.toFixed(2)} (tier ${tier}) × quality ${quality.toFixed(2)} = ${sourceConfidence.toFixed(2)}`, delta: 0 },
    { label: `Document type: ${why || docTypes.join(", ")}`, delta: 0 },
  ];
  return { docTypes, sourceTier: tier, sourceConfidence, qualityReasons };
}
