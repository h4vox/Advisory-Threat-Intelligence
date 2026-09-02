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
  // Feed entries point directly to canonical articles
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

const DEFAULT_GENERIC_TERMS = [
  "market trends",
  "cybersecurity market",
  "cyber insurance",
  "privacy policy",
  "hiring security engineers",
  "press release",
  "product launch",
  "gartner magic quadrant",
  "webinar registration",
  "annual revenue",
  "terms of service",
  "discount code",
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

  const urlCheck = isCandidateResourceUrl(url, isFromFeed);
  if (!urlCheck.isResource) {
    return {
      qualified: false,
      score: 0.1,
      classification: "GENERIC_NEWS",
      resourceKind: "CAMPAIGN_INTEL",
      reasons: [urlCheck.reason],
      rejectionReason: `REJECTED: ${urlCheck.reason}`,
      isIndexOrGeneric: true,
    };
  }

  // Length check (Allow concise security advisories if they contain CVEs or IOCs)
  const hasCve = /\bCVE-\d{4}-\d{4,7}\b/i.test(fullText);
  const hasIocSignal = /\b(?:[a-f0-9]{32}|[a-f0-9]{64}|(?:[0-9]{1,3}\.){3}[0-9]{1,3})\b/i.test(text);

  if (wordCount < minWords && !hasCve && !hasIocSignal) {
    return {
      qualified: false,
      score: 0.15,
      classification: "OTHER",
      resourceKind: "VULNERABILITY_ADVISORY",
      reasons: [`Document too short (<${minWords} words) with no CVE or IOC evidence`],
      rejectionReason: `REJECTED: Document too short (<${minWords} words)`,
      isIndexOrGeneric: false,
    };
  }

  // Check custom or default noise terms
  const noiseTerms = config?.noiseKeywords
    ? config.noiseKeywords.split(",").map((k) => k.trim().toLowerCase()).filter(Boolean)
    : DEFAULT_GENERIC_TERMS;

  const matchedNoise = noiseTerms.filter((term) => fullText.includes(term));
  const matchedTerms = HIGH_SIGNAL_TECHNICAL_TERMS.filter((term) => fullText.includes(term));

  if (config?.rejectMarketingNoise !== false && matchedNoise.length >= 3 && matchedTerms.length <= 1) {
    return {
      qualified: false,
      score: 0.2,
      classification: "GENERIC_NEWS",
      resourceKind: "CAMPAIGN_INTEL",
      reasons: ["Marketing, business news, or non-technical cybersecurity promotional page"],
      rejectionReason: "REJECTED: Marketing or non-technical business news",
      isIndexOrGeneric: false,
    };
  }

  // Granular Classification & Intelligent ResourceKind mapping
  let classification: ResourceClassification = "THREAT_REPORT";
  let resourceKind: ResourceKind = "CAMPAIGN_INTEL";

  if (
    /adversary emulation|emulation plan|micro-emulation|attackiq|caldera|atomic red team|procedure execution|command-line/i.test(fullText)
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
  } else if (/sigma rule|yara rule|detection engineering|hunting query|kql|splunk query|mitigation guidance/i.test(fullText)) {
    classification = "DETECTION_RESEARCH";
    resourceKind = "DETECTION_GUIDANCE";
    reasons.push("Defensive detection rules & hunting engineering");
  } else if (hasCve || /vulnerability analysis|proof of concept|exploit analysis|zero-day advisory/i.test(fullText)) {
    classification = "VULNERABILITY_REPORT";
    resourceKind = "VULNERABILITY_ADVISORY";
    reasons.push("Vulnerability exploitation & advisory research");
  } else if (/threat actor|apt\d+|sandworm|fin\d+|lazarus|scattered spider|volt typhoon|unc\d+|state-sponsored/i.test(fullText)) {
    classification = "THREAT_ACTOR_REPORT";
    resourceKind = "THREAT_ACTOR_DOSSIER";
    reasons.push("Targeted threat actor dossier & campaign tracking");
  }

  // Scoring calculation
  let score = isFromFeed ? 0.50 : 0.38; // Feed articles start with higher baseline curation

  if (wordCount >= 1000) score += 0.22;
  else if (wordCount >= 400) score += 0.12;

  if (matchedTerms.length >= 6) {
    score += 0.28;
    reasons.push(`High density of attack telemetry terms (${matchedTerms.length})`);
  } else if (matchedTerms.length >= 3) {
    score += 0.16;
    reasons.push(`Moderate threat terms (${matchedTerms.length})`);
  } else if (matchedTerms.length >= 1) {
    score += 0.08;
  }

  if (/\bT1\d{3}(?:\.\d{3})?\b/.test(text)) {
    score += 0.12;
    reasons.push("MITRE ATT&CK technique IDs detected");
  }

  if (hasCve) {
    score += 0.12;
    reasons.push("CVE vulnerability references detected");
  }

  if (hasIocSignal) {
    score += 0.10;
    reasons.push("Technical IOC artifacts (hashes/IPs) detected");
  }

  score = Math.min(1.0, Math.round(score * 100) / 100);

  // Strictness mode evaluation
  let qualified = false;
  if (strictness === "permissive") {
    qualified = score >= Math.min(minScore, 0.30) && (matchedTerms.length >= 1 || hasCve || hasIocSignal);
  } else if (strictness === "strict") {
    qualified = score >= Math.max(minScore, 0.55) && matchedTerms.length >= 2;
  } else {
    // Balanced (default)
    qualified = score >= minScore && (matchedTerms.length >= 1 || hasCve || hasIocSignal);
  }

  // Check required signal constraints from config
  if (config?.requireIocs && !hasIocSignal) {
    qualified = false;
    reasons.push("Missing required IOCs (enforced by settings)");
  }
  if (config?.requireAttck && !/\bT1\d{3}(?:\.\d{3})?\b/.test(text)) {
    qualified = false;
    reasons.push("Missing required MITRE ATT&CK technique IDs (enforced by settings)");
  }

  // Target resource types filter
  if (qualified && config?.targetResourceTypes && config.targetResourceTypes.length > 0) {
    if (!config.targetResourceTypes.includes(resourceKind)) {
      qualified = false;
      return {
        qualified: false,
        score,
        classification,
        resourceKind,
        reasons,
        rejectionReason: `REJECTED: Resource kind ${resourceKind} is not in target resource types whitelist`,
        isIndexOrGeneric: false,
      };
    }
  }

  return {
    qualified,
    score,
    classification,
    resourceKind,
    reasons,
    rejectionReason: qualified ? undefined : `REJECTED: Score (${score}) below threshold (${minScore}) or insufficient TTP depth`,
    isIndexOrGeneric: false,
  };
}
