import type { CrawlConfig, ResourceKind } from "./types";

export type ResourceClassification =
  | "ADVERSARY_EMULATION"
  | "ADVERSARY_SIMULATION"
  | "INTRUSION_REPORT"
  | "ATTACK_CHAIN_REPORT"
  | "MALWARE_ANALYSIS"
  | "THREAT_ACTOR_REPORT"
  | "CAMPAIGN_REPORT"
  | "VULNERABILITY_REPORT"
  | "DETECTION_RESEARCH"
  | "THREAT_HUNTING_RESEARCH"
  | "PURPLE_TEAM"
  | "MITRE_RESEARCH"
  | "SECURITY_ADVISORY"
  | "THREAT_REPORT"
  | "GENERIC_NEWS"
  | "OTHER";

export type QualificationResult = {
  qualified: boolean;
  score: number;
  classification: ResourceClassification;
  resourceKind: ResourceKind;
  reasons: string[];
  rejectionReason?: string;
  isIndexOrGeneric: boolean;
  simulationScore: number;
  procedureDensity: number;
  evidenceScore: number;
  isEmergingTechnique: boolean;
  noveltyRationale?: string;
  noiseClusterScore: number;
  evidenceDetails: {
    commands: string[];
    registryKeys: string[];
    filePaths: string[];
    eventIds: string[];
  };
};

// Index / Non-resource URL patterns to reject
const GENERIC_PATH_PATTERNS = [
  /^\/?$/,
  /^\/(reports|news|blog|articles|posts|feed|archive|category|tag|topics|authors?|pages?)(\/page\/\d+|\/?)$/i,
  /\/category\/[^\/]+\/?$/i,
  /\/categories\/[^\/]+\/?$/i,
  /\/tag\/[^\/]+\/?$/i,
  /\/tags\/[^\/]+\/?$/i,
  /\/author\/[^\/]+\/?$/i,
  /\/topic\/[^\/]+\/?$/i,
  /\/archives?\/?$/i,
  /\/feed\/?$/i,
  /\/rss\/?$/i,
  /\/wp-json\//i,
  /\/privacy-policy/i,
  /\/terms-of-service/i,
  /\/contact-?us?/i,
  /\/about-?us?/i,
  /\/login|\/signup|\/register|\/auth/i,
  /\/search\/?/i,
  /\/newsletter/i,
  /\/subscribe/i,
  /\/events?\//i,
  /\/webinars?\//i,
  /\/careers?\//i,
  /\/pricing\/?/i,
  /\/cart|\/checkout/i,
];

// Single resource URL indicators
const RESOURCE_PATH_PATTERNS = [
  /\/\d{4}\/\d{2}\/[a-z0-9_-]+/i, // e.g. /2026/04/article-slug
  /\/\d{4}\/\d{2}\/\d{2}\/[a-z0-9_-]+/i,
  /\/(reports|blog|posts|threat-intel|research|advisories|analysis|bulletins)\/[a-z0-9_-]{6,}/i,
  /\/[a-z0-9_-]+-(ransomware|malware|intrusion|apt\d+|cve-\d+|exploit|loader|c2|attack-chain|campaign)/i,
  /\.pdf$/i,
];

export function isCandidateResourceUrl(
  urlStr: string,
  isFromFeed = false,
): { isResource: boolean; reason: string } {
  if (isFromFeed) {
    return { isResource: true, reason: "Verified RSS/Atom feed article entry" };
  }

  try {
    const url = new URL(urlStr);
    const path = url.pathname;

    for (const pattern of GENERIC_PATH_PATTERNS) {
      if (pattern.test(path)) {
        return { isResource: false, reason: "Matches generic index/tag/category/navigation pattern" };
      }
    }

    const segments = path.split("/").filter(Boolean);
    if (segments.length === 0) {
      return { isResource: false, reason: "Root domain is an index page" };
    }

    if (segments.length === 1 && segments[0].length < 4) {
      return { isResource: false, reason: "Short single segment is likely a top-level category" };
    }

    for (const pattern of RESOURCE_PATH_PATTERNS) {
      if (pattern.test(path)) {
        return { isResource: true, reason: "Matches verified resource permalink pattern" };
      }
    }

    return { isResource: segments.length >= 1, reason: "Permitted candidate article link" };
  } catch {
    return { isResource: false, reason: "Invalid URL string" };
  }
}

// Concrete technical evidence extraction regexes
const COMMAND_REGEX =
  /(?:(?:powershell(?:\.exe)?|cmd(?:\.exe)?|wmic|schtasks|vssadmin|rundll32|certutil|bitsadmin|reg(?:\.exe)?|psexec|whoami|nltest|net\s+(?:user|group|localgroup|view|use)|procdump|mimikatz|rubeus|adfind|powerview|chisel|rclone|megasync|curl|mshta|cscript|wscript|sc(?:\.exe)?|wevtutil|nltest)\b[^\r\n]{4,140})/gi;

const REGISTRY_REGEX =
  /\b(?:HKLM|HKCU|HKEY_LOCAL_MACHINE|HKEY_CURRENT_USER)\\[a-zA-Z0-9_\\]{4,100}\b/gi;

const FILEPATH_REGEX =
  /(?:[a-zA-Z]:\\(?:Windows|Users|ProgramData|AppData|Temp)\\[a-zA-Z0-9_.\\]{4,100}|\/(?:etc|tmp|dev\/shm|var\/tmp|opt)\/[a-zA-Z0-9_.\/]{3,100})/gi;

const EVENT_ID_REGEX =
  /\b(?:Event\s*ID\s*(?:4688|4624|4672|7045|1102|4720|4726|4738|8007)|Sysmon\s*(?:Event\s*)?(?:1|3|7|8|10|11|12|13|22))\b/gi;

export function extractTechnicalEvidence(text: string, title = "") {
  const combined = `${title}\n${text}`;
  const rawCommands = combined.match(COMMAND_REGEX) || [];
  const commands = Array.from(
    new Set(
      rawCommands
        .map((c) => c.trim().replace(/^[`'"]+|[`'"]+$/g, ""))
        .filter((c) => c.length > 8 && !c.includes("<") && !c.includes(">")),
    ),
  ).slice(0, 15);

  const rawRegistry = combined.match(REGISTRY_REGEX) || [];
  const registryKeys = Array.from(new Set(rawRegistry.map((r) => r.trim()))).slice(0, 10);

  const rawPaths = combined.match(FILEPATH_REGEX) || [];
  const filePaths = Array.from(new Set(rawPaths.map((p) => p.trim()))).slice(0, 10);

  const rawEvents = combined.match(EVENT_ID_REGEX) || [];
  const eventIds = Array.from(new Set(rawEvents.map((e) => e.trim()))).slice(0, 8);

  const hasCve = /\bCVE-\d{4}-\d{4,7}\b/i.test(combined);
  const hasAttckId = /\bT1\d{3}(?:\.\d{3})?\b/i.test(combined);
  const hasIocSignal = /\b(?:[a-f0-9]{32}|[a-f0-9]{64}|(?:[0-9]{1,3}\.){3}[0-9]{1,3})\b/i.test(text);

  return {
    commands,
    registryKeys,
    filePaths,
    eventIds,
    hasCve,
    hasAttckId,
    hasIocSignal,
    totalEvidenceCount: commands.length + registryKeys.length + filePaths.length + eventIds.length,
  };
}

// Emerging technique and novel adversary behavior patterns
const NOVEL_TRADE_PATTERNS = [
  { name: "BYOVD Driver Weaponization", pattern: /\b(?:bring your own vulnerable driver|byovd|gdrv\.sys|mhyprot2|procexp\.sys|vulnerable signed driver|kill edr driver)\b/i },
  { name: "Direct Syscall & EDR Unhooking", pattern: /\b(?:direct syscalls|hells gate|halos gate|unhooking|ntallocatevirtualmemory|ntwritevirtualmemory|syscall stub)\b/i },
  { name: "AMSI & ETW Patching", pattern: /\b(?:amsi bypass|amsiscanbuffer|patching etw|etweventwrite|disable amsi)\b/i },
  { name: "Cloud & Entra ID Identity Theft", pattern: /\b(?:aadrefreshtoken|primary refresh token|prt extraction|roadrecon|entra id token|device registration service)\b/i },
  { name: "Living-Off-The-Cloud Execution", pattern: /\b(?:living off the cloud|lotc|azure automation runbook|aws lambda execution|github actions runner abuse)\b/i },
  { name: "Process Tampering & Early Cascade", pattern: /\b(?:process hollowing|process doppelganging|process herpaderping|early cascade injection|mockingjay)\b/i },
  { name: "Shadow Coercion & Relay", pattern: /\b(?:petitpotam|shadowcoercion|dfscoerce|webclient relay|adcs esc\d+)\b/i },
];

export function detectEmergingTechniques(text: string) {
  for (const item of NOVEL_TRADE_PATTERNS) {
    if (item.pattern.test(text)) {
      return {
        isEmerging: true,
        rationale: `Detected novel/emerging procedure: ${item.name}`,
      };
    }
  }
  return { isEmerging: false };
}

// Commercial and marketing noise patterns
const MARKETING_CLUSTERS = [
  /\b(?:request|schedule|book)\s+(?:a\s+)?demo\b/i,
  /\b(?:start\s+your\s+)?free\s+trial\b/i,
  /\bpricing\s+plans?\b/i,
  /\bgartner\s+(?:magic\s+quadrant|peer\s+insights)\b/i,
  /\bnamed\s+a\s+leader\s+in\b/i,
  /\bour\s+platform\s+(?:protects|empowers|secures|delivers)\b/i,
  /\bcontact\s+(?:sales|our\s+sales\s+team)\b/i,
  /\bdownload\s+(?:our\s+)?(?:solution\s+brief|datasheet|whitepaper\s+overview)\b/i,
  /\bwebinar\s+registration\b/i,
  /\bannual\s+(?:revenue|growth|quarterly\s+earnings)\b/i,
  /\bcyber\s+insurance\s+policy\b/i,
  /\bhiring\s+(?:security\s+engineers|account\s+executives)\b/i,
  /\bpress\s+release\s+distribution\b/i,
  /\bannounces\s+appointment\s+of\b/i,
];

export function detectMarketingNoiseCluster(text: string, title = "") {
  const combined = `${title}\n${text}`;
  let hits = 0;
  const matchedPhrases: string[] = [];

  for (const re of MARKETING_CLUSTERS) {
    if (re.test(combined)) {
      hits++;
      const m = combined.match(re);
      if (m?.[0]) matchedPhrases.push(m[0].trim());
    }
  }

  // Check if this is an academic/conference paper footnote (which is NOT pure marketing)
  const isResearchFootnote = /\b(?:black hat|def con|usenix|ieee|rsa conference)\b/i.test(combined);

  return {
    clusterScore: hits,
    matchedPhrases,
    isPureMarketing: hits >= 2 && !isResearchFootnote,
  };
}

const HIGH_SIGNAL_TECHNICAL_TERMS = [
  "initial access",
  "lateral movement",
  "credential access",
  "persistence",
  "privilege escalation",
  "defense evasion",
  "command and control",
  "exfiltration",
  "powershell",
  "cobalt strike",
  "mimikatz",
  "ntds.dit",
  "lsass",
  "process injection",
  "ransomware",
  "infostealer",
  "webshell",
  "rootkit",
  "c2 server",
  "attack chain",
  "infection chain",
  "kill chain",
  "execution flow",
  "ttps",
  "mitre att&ck",
  "atomic red team",
  "adversary emulation",
  "emulation plan",
  "sigma rule",
  "yara rule",
  "threat hunting",
  "incident response",
  "post-compromise",
  "threat actor",
  "apt",
  "zero-day",
  "remote code execution",
  "reverse shell",
  "beacon",
  "payload",
  "dropper",
  "cve-",
  "vulnerability",
  "exploit",
  "iocs",
  "hashes",
  "sha256",
];

export function qualifyContent(
  text: string,
  title: string,
  url: string,
  config?: Partial<CrawlConfig>,
  isFromFeed = false,
): QualificationResult {
  const reasons: string[] = [];
  const fullText = `${title}\n${text}`.toLowerCase();
  const wordCount = text.split(/\s+/).filter(Boolean).length;

  const minScore = config?.minQualityScore ?? 0.40;
  const minWords = config?.minWordCount ?? 120;
  const strictness = config?.strictnessMode ?? "balanced";

  // 1. URL candidate verification
  const urlCheck = isCandidateResourceUrl(url, isFromFeed);
  if (!urlCheck.isResource) {
    return {
      qualified: false,
      score: 0.1,
      simulationScore: 0.05,
      procedureDensity: 0,
      evidenceScore: 0,
      isEmergingTechnique: false,
      noiseClusterScore: 0,
      classification: "GENERIC_NEWS",
      resourceKind: "CAMPAIGN_INTEL",
      reasons: [urlCheck.reason],
      rejectionReason: `REJECTED: ${urlCheck.reason}`,
      isIndexOrGeneric: true,
      evidenceDetails: { commands: [], registryKeys: [], filePaths: [], eventIds: [] },
    };
  }

  // 2. Extract technical evidence details
  const evidence = extractTechnicalEvidence(text, title);
  const matchedTerms = HIGH_SIGNAL_TECHNICAL_TERMS.filter((term) => fullText.includes(term));
  const emerging = detectEmergingTechniques(text);
  const marketing = detectMarketingNoiseCluster(text, title);

  // 3. Robust False-Negative Prevention for concise or rapid-response advisories
  // If a report contains real execution commands, registry keys, CVEs, or IOCs, NEVER reject solely on length!
  const hasSubstantialEvidence =
    evidence.commands.length > 0 ||
    evidence.registryKeys.length > 0 ||
    evidence.eventIds.length > 0 ||
    evidence.hasCve ||
    evidence.hasIocSignal;

  if (wordCount < minWords && !hasSubstantialEvidence) {
    return {
      qualified: false,
      score: 0.15,
      simulationScore: 0.05,
      procedureDensity: 0,
      evidenceScore: 0,
      isEmergingTechnique: false,
      noiseClusterScore: marketing.clusterScore,
      classification: "OTHER",
      resourceKind: "VULNERABILITY_ADVISORY",
      reasons: [`Document too short (<${minWords} words) with no procedural or technical evidence`],
      rejectionReason: `REJECTED: Document too short (<${minWords} words) with zero technical evidence`,
      isIndexOrGeneric: false,
      evidenceDetails: evidence,
    };
  }

  // 4. Cluster-based marketing & noise filtering
  if (config?.rejectMarketingNoise !== false && marketing.isPureMarketing && evidence.totalEvidenceCount === 0) {
    return {
      qualified: false,
      score: 0.18,
      simulationScore: 0.05,
      procedureDensity: 0,
      evidenceScore: 0,
      isEmergingTechnique: false,
      noiseClusterScore: marketing.clusterScore,
      classification: "GENERIC_NEWS",
      resourceKind: "CAMPAIGN_INTEL",
      reasons: [`Commercial sales/marketing page (${marketing.matchedPhrases.slice(0, 2).join(", ")})`],
      rejectionReason: `REJECTED: Commercial sales/marketing page with zero technical evidence`,
      isIndexOrGeneric: false,
      evidenceDetails: evidence,
    };
  }

  // 5. Granular Classification & Intelligent ResourceKind mapping
  let classification: ResourceClassification = "THREAT_REPORT";
  let resourceKind: ResourceKind = "CAMPAIGN_INTEL";

  if (
    /adversary emulation|emulation plan|micro-emulation|attackiq|caldera|atomic red team|procedure execution/i.test(fullText) ||
    evidence.commands.length >= 3
  ) {
    classification = "ADVERSARY_EMULATION";
    resourceKind = "PROCEDURE_DEEPDIVE";
    reasons.push("Adversary emulation scenario / procedure execution blueprint");
  } else if (/purple team|attack simulation|breach and attack/i.test(fullText)) {
    classification = "PURPLE_TEAM";
    resourceKind = "PROCEDURE_DEEPDIVE";
    reasons.push("Purple-team simulation & emulation procedures");
  } else if (/attack chain|infection chain|kill chain|execution flow|stage 1|stage 2|lateral movement.*exfiltration/i.test(fullText)) {
    classification = "ATTACK_CHAIN_REPORT";
    resourceKind = "FULL_ATTACK_CHAIN";
    reasons.push("End-to-end multi-stage intrusion attack chain");
  } else if (/incident response|intrusion analysis|dfir|intrusion report|timeline of intrusion/i.test(fullText)) {
    classification = "INTRUSION_REPORT";
    resourceKind = "FULL_ATTACK_CHAIN";
    reasons.push("Chronological intrusion investigation & timeline");
  } else if (/malware analysis|reverse engineering|payload analysis|loader|infostealer|c2 protocol|decompil|disassembly/i.test(fullText)) {
    classification = "MALWARE_ANALYSIS";
    resourceKind = "MALWARE_ANALYSIS";
    reasons.push("Reverse-engineering malware & tooling teardown");
  } else if (/sigma rule|yara rule|detection engineering|hunting query|kql|splunk query|mitigation guidance/i.test(fullText) || evidence.eventIds.length > 0) {
    classification = "DETECTION_RESEARCH";
    resourceKind = "DETECTION_GUIDANCE";
    reasons.push("Defensive detection rules & hunting engineering");
  } else if (evidence.hasCve || /vulnerability analysis|proof of concept|exploit analysis|zero-day advisory/i.test(fullText)) {
    classification = "VULNERABILITY_REPORT";
    resourceKind = "VULNERABILITY_ADVISORY";
    reasons.push("Vulnerability exploitation & advisory research");
  } else if (/threat actor|apt\d+|sandworm|fin\d+|lazarus|scattered spider|volt typhoon|unc\d+|state-sponsored/i.test(fullText)) {
    classification = "THREAT_ACTOR_REPORT";
    resourceKind = "THREAT_ACTOR_DOSSIER";
    reasons.push("Targeted threat actor dossier & campaign tracking");
  }

  // 6. Calculate Adversary Simulation Score ($0.0 - 1.0$)
  // How useful is this document for purple teaming and adversary emulation?
  let simulationScore = 0.25;
  if (evidence.commands.length >= 4) {
    simulationScore += 0.35;
    reasons.push(`Dense execution commands (${evidence.commands.length} found)`);
  } else if (evidence.commands.length >= 1) {
    simulationScore += 0.20;
    reasons.push(`Actionable execution commands (${evidence.commands.length} found)`);
  }

  if (evidence.registryKeys.length > 0 || evidence.filePaths.length > 0) {
    simulationScore += 0.15;
    reasons.push("System persistence / artifact paths identified");
  }

  if (evidence.eventIds.length > 0) {
    simulationScore += 0.15;
    reasons.push(`Specific telemetry event IDs (${evidence.eventIds.join(", ")})`);
  }

  if (/initial access.*execution.*lateral movement/i.test(fullText) || /attack chain|kill chain/i.test(fullText)) {
    simulationScore += 0.15;
    reasons.push("Multi-phase sequential attack progression");
  }

  if (emerging.isEmerging) {
    simulationScore += 0.15;
    reasons.push(emerging.rationale!);
  }

  // Subtract minor penalty for marketing footer in otherwise technical report
  if (marketing.matchedPhrases.length > 0) {
    simulationScore = Math.max(0.1, simulationScore - 0.05);
  }
  simulationScore = Math.min(1.0, Math.round(simulationScore * 100) / 100);

  // 7. General Quality Score calculation
  let score = isFromFeed ? 0.50 : 0.40;

  if (wordCount >= 1000) score += 0.20;
  else if (wordCount >= 400) score += 0.10;

  if (matchedTerms.length >= 6) {
    score += 0.25;
    reasons.push(`High density of threat terms (${matchedTerms.length})`);
  } else if (matchedTerms.length >= 3) {
    score += 0.14;
  } else if (matchedTerms.length >= 1) {
    score += 0.08;
  }

  if (evidence.hasAttckId) {
    score += 0.12;
    reasons.push("MITRE ATT&CK technique IDs detected");
  }

  if (evidence.hasCve) {
    score += 0.10;
    reasons.push("CVE vulnerability references detected");
  }

  if (evidence.hasIocSignal) {
    score += 0.10;
    reasons.push("Technical IOC artifacts (hashes/IPs) detected");
  }

  if (simulationScore >= 0.60) {
    score += 0.15;
    reasons.push(`High adversary emulation replay value (${Math.round(simulationScore * 100)}%)`);
  }

  if (emerging.isEmerging) {
    score += 0.12;
  }

  score = Math.min(1.0, Math.round(score * 100) / 100);

  // 8. Strictness mode evaluation
  let qualified = false;
  if (strictness === "permissive") {
    qualified =
      score >= Math.min(minScore, 0.30) ||
      simulationScore >= 0.40 ||
      hasSubstantialEvidence ||
      isFromFeed;
  } else if (strictness === "strict") {
    qualified =
      (score >= 0.65 || simulationScore >= 0.60) &&
      (evidence.totalEvidenceCount >= 1 || matchedTerms.length >= 2);
  } else {
    // Balanced (default)
    qualified =
      (score >= minScore || simulationScore >= 0.50) &&
      (matchedTerms.length >= 1 || hasSubstantialEvidence || isFromFeed);
  }

  // 9. Config constraint enforcement
  if (config?.requireIocs && !evidence.hasIocSignal && score < 0.75) {
    qualified = false;
    reasons.push("Missing required IOCs (enforced by settings)");
  }
  if (config?.requireAttck && !evidence.hasAttckId && score < 0.75) {
    qualified = false;
    reasons.push("Missing required MITRE ATT&CK technique IDs (enforced by settings)");
  }

  // 10. Target resource types filter
  if (qualified && config?.targetResourceTypes && config.targetResourceTypes.length > 0) {
    if (!config.targetResourceTypes.includes(resourceKind)) {
      qualified = false;
      return {
        qualified: false,
        score,
        simulationScore,
        procedureDensity: evidence.commands.length,
        evidenceScore: evidence.totalEvidenceCount,
        isEmergingTechnique: emerging.isEmerging,
        noveltyRationale: emerging.rationale,
        noiseClusterScore: marketing.clusterScore,
        classification,
        resourceKind,
        reasons,
        rejectionReason: `REJECTED: Resource kind ${resourceKind} is not in target resource types whitelist`,
        isIndexOrGeneric: false,
        evidenceDetails: evidence,
      };
    }
  }

  return {
    qualified,
    score,
    simulationScore,
    procedureDensity: evidence.commands.length,
    evidenceScore: evidence.totalEvidenceCount,
    isEmergingTechnique: emerging.isEmerging,
    noveltyRationale: emerging.rationale,
    noiseClusterScore: marketing.clusterScore,
    classification,
    resourceKind,
    reasons,
    rejectionReason: qualified
      ? undefined
      : `REJECTED: Quality (${Math.round(score * 100)}%) and simulation score (${Math.round(simulationScore * 100)}%) below threshold (${Math.round(minScore * 100)}%)`,
    isIndexOrGeneric: false,
    evidenceDetails: evidence,
  };
}
