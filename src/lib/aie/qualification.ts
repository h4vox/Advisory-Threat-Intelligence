import type { QualityReason } from "./types";

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
  reasons: string[];
  rejectionReason?: string;
  isIndexOrGeneric: boolean;
};

// Index / Non-resource URL patterns (Requirement §3 & §17)
const GENERIC_PATH_PATTERNS = [
  /^\/?$/,
  /^\/(reports|news|blog|articles|posts|feed|archive|category|tag|topics|authors?|pages?)(\/page\/\d+|\/?)$/i,
  /\/category\/[^\/]+\/?$/i,
  /\/tag\/[^\/]+\/?$/i,
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
];

// Single resource URL indicators
const RESOURCE_PATH_PATTERNS = [
  /\/\d{4}\/\d{2}\/[a-z0-9_-]+/i, // e.g. /2026/04/article-slug
  /\/\d{4}\/\d{2}\/\d{2}\/[a-z0-9_-]+/i,
  /\/(reports|blog|posts|threat-intel|research|advisories)\/[a-z0-9_-]{8,}/i,
  /\/[a-z0-9_-]+-(ransomware|malware|intrusion|apt\d+|cve-\d+|exploit|loader|c2|attack-chain)/i,
  /\.pdf$/i,
];

export function isCandidateResourceUrl(urlStr: string): { isResource: boolean; reason: string } {
  try {
    const url = new URL(urlStr);
    const path = url.pathname;

    for (const pattern of GENERIC_PATH_PATTERNS) {
      if (pattern.test(path)) {
        return { isResource: false, reason: "Matches generic index/tag/category/navigation pattern" };
      }
    }

    if (url.searchParams.has("replytocom") || url.searchParams.has("share") || url.searchParams.has("utm_source")) {
      // url contains query noise, clean it
    }

    // Check if path has sufficient depth or slug length for a specific resource
    const segments = path.split("/").filter(Boolean);
    if (segments.length === 0) {
      return { isResource: false, reason: "Root domain is an index page" };
    }

    if (segments.length === 1 && segments[0].length < 6) {
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
  "privilege escalation",
  "reverse shell",
];

const GENERIC_NEWS_TERMS = [
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
];

export function qualifyContent(
  text: string,
  title: string,
  url: string,
): QualificationResult {
  const reasons: string[] = [];
  const fullText = `${title}\n${text}`.toLowerCase();
  const wordCount = text.split(/\s+/).filter(Boolean).length;

  const urlCheck = isCandidateResourceUrl(url);
  if (!urlCheck.isResource) {
    return {
      qualified: false,
      score: 0.1,
      classification: "GENERIC_NEWS",
      reasons: [urlCheck.reason],
      rejectionReason: `REJECTED: ${urlCheck.reason}`,
      isIndexOrGeneric: true,
    };
  }

  // Length check
  if (wordCount < 120) {
    return {
      qualified: false,
      score: 0.15,
      classification: "OTHER",
      reasons: ["Document too short (<120 words) to contain actionable technical intelligence"],
      rejectionReason: "REJECTED: Document too short / stub content",
      isIndexOrGeneric: false,
    };
  }

  // Check technical term density
  const matchedTerms = HIGH_SIGNAL_TECHNICAL_TERMS.filter((term) => fullText.includes(term));
  const matchedGeneric = GENERIC_NEWS_TERMS.filter((term) => fullText.includes(term));

  if (matchedGeneric.length >= 3 && matchedTerms.length <= 1) {
    return {
      qualified: false,
      score: 0.25,
      classification: "GENERIC_NEWS",
      reasons: ["Marketing, business news, or non-technical cybersecurity press release"],
      rejectionReason: "REJECTED: Low technical depth / generic business news",
      isIndexOrGeneric: false,
    };
  }

  // Classification identification
  let classification: ResourceClassification = "THREAT_REPORT";

  if (
    /adversary emulation|emulation plan|micro-emulation|attackiq|caldera|atomic red team/i.test(fullText)
  ) {
    classification = "ADVERSARY_EMULATION";
    reasons.push("Adversary emulation scenario / CTID emulation plan format");
  } else if (/purple team|attack simulation|breach and attack/i.test(fullText)) {
    classification = "PURPLE_TEAM";
    reasons.push("Purple-team / attack simulation methodology");
  } else if (/incident response|intrusion analysis|dfir|intrusion report|timeline of intrusion/i.test(fullText)) {
    classification = "INTRUSION_REPORT";
    reasons.push("Detailed multi-stage intrusion investigation");
  } else if (/attack chain|infection chain|kill chain|execution path|stage 1|stage 2/i.test(fullText)) {
    classification = "ATTACK_CHAIN_REPORT";
    reasons.push("Chronological attack chain structure");
  } else if (/malware analysis|reverse engineering|payload analysis|loader|rat|infostealer|c2 protocol/i.test(fullText)) {
    classification = "MALWARE_ANALYSIS";
    reasons.push("Deep malware technical teardown");
  } else if (/threat actor|apt\d+|sandworm|fin\d+|lazarus|scattered spider|volt typhoon|unc\d+/i.test(fullText)) {
    classification = "THREAT_ACTOR_REPORT";
    reasons.push("Targeted threat group / adversary tracking");
  } else if (/cve-\d{4}-\d+|vulnerability analysis|proof of concept|exploit analysis/i.test(fullText)) {
    classification = "VULNERABILITY_REPORT";
    reasons.push("Vulnerability exploitation & weaponization research");
  } else if (/sigma rule|yara rule|detection engineering|hunting query|kql|splunk query/i.test(fullText)) {
    classification = "DETECTION_RESEARCH";
    reasons.push("Defensive detection & hunting rules");
  } else if (/mitre att&ck|technique mapping|t1\d{3}/i.test(fullText)) {
    classification = "MITRE_RESEARCH";
    reasons.push("MITRE ATT&CK enterprise research");
  }

  // Scoring calculation
  let score = 0.4;
  if (wordCount >= 1000) score += 0.2;
  else if (wordCount >= 500) score += 0.1;

  if (matchedTerms.length >= 6) {
    score += 0.3;
    reasons.push(`High density of attack telemetry terms (${matchedTerms.length})`);
  } else if (matchedTerms.length >= 3) {
    score += 0.18;
    reasons.push(`Moderate threat terms (${matchedTerms.length})`);
  }

  if (/\bT1\d{3}(?:\.\d{3})?\b/.test(text)) {
    score += 0.1;
    reasons.push("MITRE ATT&CK technique IDs detected");
  }

  if (/\bCVE-\d{4}-\d{4,7}\b/i.test(text)) {
    score += 0.08;
    reasons.push("CVE vulnerability references detected");
  }

  score = Math.min(1.0, Math.round(score * 100) / 100);
  const qualified = score >= 0.55 && matchedTerms.length >= 2;

  return {
    qualified,
    score,
    classification,
    reasons,
    rejectionReason: qualified ? undefined : "REJECTED: Insufficient adversary tradecraft/TTP depth",
    isIndexOrGeneric: false,
  };
}
