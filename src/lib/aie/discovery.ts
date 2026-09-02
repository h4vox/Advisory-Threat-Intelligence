import { isCandidateResourceUrl } from "./qualification";
import type { DiscoveredSourceRecord, DiscoveryGraphEdge, ResourceKind } from "./types";

export type OutlinkKind = "citation" | "pdf_document" | "repository" | "research_paper" | "internal_article";

export type DiscoveredLink = {
  url: string;
  canonicalUrl: string;
  title: string;
  domain: string;
  sourceId?: string;
  publisher?: string;
  discoveryMethod: "crawl_source" | "search_discovery" | "rss_feed" | "outlink_citation" | "pdf_reference" | "repo_reference";
  discoveryQuery?: string;
  parentUrl?: string;
  parentSource?: string;
  discoveryPath: string[];
  depth: number;
  priorityScore: number;
  outlinkKind: OutlinkKind;
  anchorContext?: string;
  isExternalDomain: boolean;
};

// High-confidence CTI, CERT, and Security Research domain registries
const TRUSTED_CTI_DOMAINS = new Set([
  "thedfirreport.com",
  "unit42.paloaltonetworks.com",
  "cloud.google.com",
  "mandiant.com",
  "cisa.gov",
  "sentinelone.com",
  "redcanary.com",
  "huntress.com",
  "bleepingcomputer.com",
  "darkreading.com",
  "vx-underground.org",
  "securityintelligence.com",
  "talosintelligence.com",
  "microsoft.com",
  "crowdstrike.com",
  "trendmicro.com",
  "securelist.com",
  "welivesecurity.com",
  "krebsonsecurity.com",
  "citizenlab.ca",
  "bellingcat.com",
  "cert.europa.eu",
  "ncsc.gov.uk",
  "center-for-threat-informed-defense.github.io",
  "attack.mitre.org",
  "github.com",
  "arxiv.org",
]);

const STRICT_BLOCKED_DOMAINS = new Set([
  "facebook.com",
  "instagram.com",
  "twitter.com",
  "x.com",
  "linkedin.com",
  "youtube.com",
  "tiktok.com",
  "pinterest.com",
  "reddit.com",
  "google.com",
  "bing.com",
  "yahoo.com",
  "amazon.com",
  "apple.com",
  "microsoft.com/en-us/store",
  "doubleclick.net",
  "googletagmanager.com",
  "google-analytics.com",
  "cloudflare.com",
  "gravatar.com",
  "wordpress.org",
  "w3.org",
]);

export function isBlacklistedDomain(domain: string, userBlocklist?: string[]): boolean {
  const clean = domain.toLowerCase().replace(/^www\./, "");
  if (STRICT_BLOCKED_DOMAINS.has(clean)) return true;
  for (const blocked of STRICT_BLOCKED_DOMAINS) {
    if (clean.endsWith(`.${blocked}`)) return true;
  }
  if (userBlocklist && userBlocklist.length > 0) {
    for (const b of userBlocklist) {
      const bClean = b.toLowerCase().trim().replace(/^www\./, "");
      if (clean === bClean || clean.endsWith(`.${bClean}`)) return true;
    }
  }
  return false;
}

export function evaluateDomainTrust(domain: string): { trustScore: number; reason: string; isKnownCti: boolean } {
  const clean = domain.toLowerCase().replace(/^www\./, "");

  if (isBlacklistedDomain(clean)) {
    return { trustScore: 0.0, reason: "Blacklisted non-technical / social domain", isKnownCti: false };
  }

  // Exact known CTI domain match
  if (TRUSTED_CTI_DOMAINS.has(clean)) {
    return { trustScore: 0.92, reason: "Verified authoritative CTI & threat research domain", isKnownCti: true };
  }

  // TLD and sub-domain evaluation
  if (clean.endsWith(".gov") || clean.endsWith(".mil") || clean.startsWith("cert.") || clean.includes("cert-")) {
    return { trustScore: 0.95, reason: "Official government or CERT / CSIRT domain", isKnownCti: true };
  }

  if (clean.endsWith(".edu") || clean === "arxiv.org" || clean.includes("researchgate")) {
    return { trustScore: 0.88, reason: "Academic research / preprint repository", isKnownCti: false };
  }

  if (clean === "github.com" || clean.endsWith(".github.io")) {
    return { trustScore: 0.82, reason: "Technical repository / open-source security research", isKnownCti: false };
  }

  // Heuristic domain name evaluation for CTI keywords
  const ctiKeywordsInDomain = [
    "security",
    "threat",
    "intel",
    "cyber",
    "infosec",
    "dfir",
    "incident",
    "malware",
    "virus",
    "research",
    "labs?",
    "cert",
    "soc",
  ];
  let keywordHits = 0;
  for (const kw of ctiKeywordsInDomain) {
    if (new RegExp(`\\b${kw}|${kw}\\b`, "i").test(clean)) {
      keywordHits++;
    }
  }

  if (keywordHits >= 2) {
    return { trustScore: 0.78, reason: `Domain contains multiple security telemetry terms (${clean})`, isKnownCti: true };
  } else if (keywordHits === 1) {
    return { trustScore: 0.65, reason: `Domain contains security research keywords (${clean})`, isKnownCti: false };
  }

  return { trustScore: 0.45, reason: "Unverified external domain", isKnownCti: false };
}

export function extractOutlinksAndCitations(
  html: string,
  baseUrlStr: string,
  options: {
    sourceId?: string;
    publisher?: string;
    discoveryMethod?: DiscoveredLink["discoveryMethod"];
    discoveryQuery?: string;
    parentPath?: string[];
    depth?: number;
    allowExternalDomains?: boolean;
    domainAllowlist?: string[];
    domainBlocklist?: string[];
  } = {},
): {
  discoveredLinks: DiscoveredLink[];
  newDiscoveredSources: DiscoveredSourceRecord[];
  graphEdges: Omit<DiscoveryGraphEdge, "id" | "createdAt">[];
} {
  const discoveredLinks: DiscoveredLink[] = [];
  const newDiscoveredSources: DiscoveredSourceRecord[] = [];
  const graphEdges: Omit<DiscoveryGraphEdge, "id" | "createdAt">[] = [];
  const seenUrls = new Set<string>();

  try {
    const baseUrl = new URL(baseUrlStr);
    const host = baseUrl.hostname.toLowerCase().replace(/^www\./, "");
    const depth = options.depth ?? 1;
    const parentPath = options.parentPath || [baseUrlStr];

    const linkRegex = /<a\s+(?:[^>]*?\s+)?href=(["'])(.*?)\1[^>]*>([\s\S]*?)<\/a>/gi;
    let match: RegExpExecArray | null;

    while ((match = linkRegex.exec(html)) !== null) {
      const rawHref = match[2]?.trim();
      const rawAnchorText = match[3]?.replace(/<[^>]+>/g, " ").replace(/\s+/g, " ").trim() || "";

      if (
        !rawHref ||
        rawHref.startsWith("javascript:") ||
        rawHref.startsWith("mailto:") ||
        rawHref.startsWith("tel:") ||
        rawHref.startsWith("#") ||
        rawHref.startsWith("data:")
      ) {
        continue;
      }

      let resolved: URL;
      try {
        resolved = new URL(rawHref, baseUrl);
      } catch {
        continue;
      }

      resolved.hash = "";
      // Strip tracking/query parameters
      const trackingParams = [
        "utm_source",
        "utm_medium",
        "utm_campaign",
        "utm_content",
        "utm_term",
        "ref",
        "share",
        "replytocom",
        "fbclid",
        "gclid",
        "msclkid",
      ];
      for (const p of trackingParams) {
        resolved.searchParams.delete(p);
      }

      const targetHost = resolved.hostname.toLowerCase().replace(/^www\./, "");
      const isExternal = targetHost !== host && !targetHost.endsWith(`.${host}`);

      // Check blocklist
      if (isBlacklistedDomain(targetHost, options.domainBlocklist)) {
        continue;
      }

      // Check allowlist if specified
      if (options.domainAllowlist && options.domainAllowlist.length > 0) {
        const allowed = options.domainAllowlist.some((d) => targetHost === d || targetHost.endsWith(`.${d}`));
        if (!allowed) continue;
      }

      // External domain restriction toggle check
      if (isExternal && options.allowExternalDomains === false) {
        continue;
      }

      const cleanUrl = resolved.toString();
      if (seenUrls.has(cleanUrl) || cleanUrl === baseUrlStr) continue;

      // Determine outlink kind
      let outlinkKind: OutlinkKind = "internal_article";
      let relationship: DiscoveryGraphEdge["relationship"] = "LINKS_TO";

      if (/\.pdf$/i.test(resolved.pathname)) {
        outlinkKind = "pdf_document";
        relationship = "DOWNLOADS_PDF";
      } else if (targetHost === "github.com" || targetHost === "gitlab.com") {
        outlinkKind = "repository";
        relationship = "REFERENCES_REPO";
      } else if (targetHost === "arxiv.org" || targetHost.includes("researchgate") || /\.edu$/i.test(targetHost)) {
        outlinkKind = "research_paper";
        relationship = "CITES";
      } else if (isExternal) {
        outlinkKind = "citation";
        relationship = "CITES";
      }

      // Pre-filter candidate resource URLs
      const check = isCandidateResourceUrl(cleanUrl);
      if (!check.isResource && outlinkKind !== "pdf_document" && outlinkKind !== "repository") {
        continue;
      }

      seenUrls.add(cleanUrl);

      // Score domain trust and candidate priority
      const trust = evaluateDomainTrust(targetHost);
      let priorityScore = trust.trustScore;

      if (outlinkKind === "pdf_document") priorityScore += 0.15;
      if (outlinkKind === "citation") priorityScore += 0.10;
      if (/advisory|cve|incident|attack|ransomware|malware|threat/i.test(cleanUrl)) priorityScore += 0.15;

      priorityScore = Math.min(1.0, Math.round(priorityScore * 100) / 100);

      // Register candidate link
      const discoveredLink: DiscoveredLink = {
        url: cleanUrl,
        canonicalUrl: cleanUrl,
        title: rawAnchorText || cleanUrl.split("/").filter(Boolean).pop()?.replace(/-/g, " ") || "Discovered resource",
        domain: targetHost,
        sourceId: options.sourceId,
        publisher: options.publisher || host,
        discoveryMethod: isExternal ? "outlink_citation" : options.discoveryMethod ?? "crawl_source",
        discoveryQuery: options.discoveryQuery,
        parentUrl: baseUrlStr,
        parentSource: host,
        discoveryPath: [...parentPath, cleanUrl],
        depth,
        priorityScore,
        outlinkKind,
        anchorContext: rawAnchorText,
        isExternalDomain: isExternal,
      };
      discoveredLinks.push(discoveredLink);

      // Record graph edge
      graphEdges.push({
        from: baseUrlStr,
        to: cleanUrl,
        relationship,
        label: rawAnchorText.slice(0, 60) || relationship,
      });

      // If new external source with credibility, promote to DiscoveredSource
      if (isExternal && trust.trustScore >= 0.60) {
        newDiscoveredSources.push({
          id: `src_disc_${targetHost.replace(/[^a-z0-9]/gi, "_").slice(0, 30)}`,
          domain: targetHost,
          name: targetHost.charAt(0).toUpperCase() + targetHost.slice(1),
          homepageUrl: `${resolved.protocol}//${targetHost}/`,
          parentSource: host,
          parentUrl: baseUrlStr,
          discoveryPath: [...parentPath],
          trustScore: trust.trustScore,
          resourceCount: 1,
          status: "discovered",
          firstDiscoveredAt: new Date().toISOString(),
          lastSeenAt: new Date().toISOString(),
        });
      }
    }
  } catch (err) {
    console.error("[discovery] failed to extract outlinks and citations:", err);
  }

  return { discoveredLinks, newDiscoveredSources, graphEdges };
}

// Search templates for CTI search discovery
const SEARCH_QUERY_TEMPLATES = [
  '"APT attack chain" cybersecurity report',
  '"ransomware intrusion" technical report',
  '"MITRE ATT&CK" adversary emulation plan',
  '"initial access" threat actor technical report',
  '"credential theft" intrusion report DFIR',
  '"malware analysis" "command and control" technical report',
  '"threat actor" "TTPs" incident response',
  '"adversary emulation" simulation scenario purple team',
  '"zero-day" exploitation in the wild analysis',
  '"lateral movement" active directory intrusion writeup',
];

export function generateSearchQueries(keywords?: string): string[] {
  if (!keywords || !keywords.trim()) {
    return SEARCH_QUERY_TEMPLATES.slice(0, 6);
  }

  const customKeywords = keywords.split(",").map((k) => k.trim()).filter(Boolean);
  const queries: string[] = [];

  for (const kw of customKeywords) {
    queries.push(`${kw} threat intelligence technical report`);
    queries.push(`${kw} attack chain execution procedures`);
  }

  return Array.from(new Set([...queries, ...SEARCH_QUERY_TEMPLATES])).slice(0, 10);
}

// Curated live/offline resilience knowledge pool
export const DISCOVERY_KNOWLEDGE_POOL: {
  url: string;
  title: string;
  sourceSlug: string;
  publisher: string;
  category: string;
  sampleText: string;
}[] = [
  {
    url: "https://thedfirreport.com/2026/04/22/bissa-scanner-exposed-ai-assisted-mass-exploitation-and-credential-harvesting/",
    title: "Bissa Scanner Exposed: AI-Assisted Mass Exploitation and Credential Harvesting",
    sourceSlug: "dfir",
    publisher: "The DFIR Report",
    category: "INTRUSION_REPORT",
    sampleText: `In this intrusion, threat actors leveraged automated AI-assisted scanning scripts to locate unauthenticated ActiveMQ and VPN endpoints. Upon Initial Access via CVE-2023-46604, the adversary executed encoded PowerShell (T1059.001) to download AdaptixC2 and Bumblebee loaders. Defense Evasion was conducted by stopping Windows Defender (T1562.001) and tampering with event logs via wevtutil (T1070.001). Credential dumping was observed against LSASS memory using Mimikatz sekurlsa::logonpasswords (T1003.001) and NTDS.dit extraction. The intrusion pivoted across subnets via SMB Admin shares (T1021.002) and deployed Akira Ransomware (T1486). Indicators include IP 185.220.101.44, C2 domain update-service-cdn[.]com, and SHA256 8f4e9124a91b48d61993425f18c642b109e99a89643194a37f5d688849b29401. Citations: https://cisa.gov/news-events/cybersecurity-advisories/aa23-319a and technical advisory at https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/`,
  },
  {
    url: "https://unit42.paloaltonetworks.com/threat-actor-scattered-spider-cloud-intrusion/",
    title: "Scattered Spider Multi-Cloud Intrusion and Identity Subversion Analysis",
    sourceSlug: "unit42",
    publisher: "Unit 42",
    category: "THREAT_ACTOR_REPORT",
    sampleText: `Unit 42 researchers analyzed a targeted cloud intrusion conducted by threat actor Scattered Spider (UNC3944 / Star Blizzard). The actor gained initial access via help desk social engineering and SIM swapping to obtain valid Okta session tokens (T1078.002). Upon MFA bypass, the actor created persistence via rogue Azure AD application registrations with high-privilege MS Graph API permissions (T1098). Lateral movement was achieved using AWS IAM role assumption and Chisel SOCKS5 reverse tunneling (T1572). Sensitive databases in AWS S3 and Azure Blob storage were exfiltrated (T1567.002) using automated Rclone scripts. Detections and Sigma rules focus on anomalous Azure service principal credentials and non-standard Rclone user-agents. Referenced research: https://mandiant.com/resources/blog/unc3944-sms-phishing-sim-swapping-scattered-spider and technical paper at https://arxiv.org/abs/2309.04321.`,
  },
  {
    url: "https://cloud.google.com/blog/topics/threat-intelligence/sandworm-substations-grid-intrusion/",
    title: "Sandworm Disruptive ICS Substation Intrusion Campaign Writeup",
    sourceSlug: "mandiant",
    publisher: "Google Threat Intelligence",
    category: "ATTACK_CHAIN_REPORT",
    sampleText: `Mandiant / GTIG investigated an intrusion attributed to Sandworm (APT44 / TeleBots / Seashell Blizzard) targeting regional electrical substations. The threat actor gained initial access through an exposed remote access gateway. They established persistence with custom Linux backdoors and deployed C2 beacons over HTTPS (T1071.001). To achieve operational impact, the adversary executed custom wiper payloads (T1485) and issued unauthorized IEC-60870-5-104 industrial protocol commands to trip electrical breakers. Defensive mitigation requires micro-segmentation between IT and OT networks and strict deep packet inspection of industrial telemetry. Whitepaper PDF: https://cert.europa.eu/publications/security-advisories/cert-eu-sandworm-substation-threat-bulletin.pdf.`,
  },
  {
    url: "https://center-for-threat-informed-defense.github.io/adversary-emulation-library/lockbit3/",
    title: "CTID Adversary Emulation Plan: LockBit 3.0 (Black)",
    sourceSlug: "ctid",
    publisher: "Center for Threat-Informed Defense",
    category: "ADVERSARY_EMULATION",
    sampleText: `The Center for Threat-Informed Defense (CTID) published the full LockBit 3.0 Adversary Emulation Plan. The scenario models the end-to-end operational flow of affiliate intrusions: Initial Access via CVE-2023-34362 (MOVEit Transfer exploit), followed by Execution via Command Shell cmd.exe /c and PowerShell download cradles. Credential access utilizes Procdump for LSASS and Kerberoasting against domain service accounts (T1558.003). Lateral movement is executed using PsExec and WMI against target servers. Impact phase automates Volume Shadow Copy deletion via vssadmin.exe delete shadows /all /quiet and high-speed multi-threaded encryption of local drives. Atomic Red Team and CALDERA execution scripts are provided: https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1003.001/T1003.001.md.`,
  },
  {
    url: "https://www.sentinelone.com/labs/stealthy-edr-evasion-and-kernel-callback-tampering/",
    title: "BYOVD Exploitation: Stealthy EDR Evasion and Kernel Callback Tampering",
    sourceSlug: "sentinellabs",
    publisher: "SentinelLABS",
    category: "MALWARE_ANALYSIS",
    sampleText: `SentinelLABS analyzed a Bring Your Own Vulnerable Driver (BYOVD) attack chain utilized by BlackCat (ALPHV) and Play Ransomware. The attackers dropped a signed vulnerable kernel driver (gdrv.sys / CVE-2018-19320) onto the victim endpoint. By executing raw kernel write primitives, the payload zeroed out EDR process notification callbacks in the PspCreateProcessNotifyRoutine array (T1562.001). With security agents blind to process creation events, the adversary spawned unmonitored Mimikatz instances (T1003.001) and performed unhindered credential dumping. Hunting queries focus on unsigned or known vulnerable driver load events (Sysmon EventID 6). Associated rules: https://github.com/SigmaHQ/sigma/blob/master/rules/windows/driver_load/driver_load_gdrv_byovd.yml.`,
  },
  {
    url: "https://www.cisa.gov/news-events/cybersecurity-advisories/aa26-088a-volt-typhoon-infrastructure",
    title: "AA26-088A: Volt Typhoon Living-off-the-Land Exploitation of Critical Infrastructure",
    sourceSlug: "cisa",
    publisher: "CISA",
    category: "SECURITY_ADVISORY",
    sampleText: `CISA, NSA, and FBI released an updated joint cybersecurity advisory regarding PRC state-sponsored actor Volt Typhoon (Vanguard Panda). The threat actor emphasizes stealth Living-off-the-Land (LotL) techniques to evade detection. Initial access utilizes zero-day vulnerabilities in edge network appliances (FortiOS, Cisco, Ivanti). Upon entry, Volt Typhoon strictly avoids custom malware, relying entirely on native administrative utilities: net user, ping, tracert, wmic, and certutil. To establish covert C2, the actor routes traffic through compromised SOHO routers and proxy networks (KV-botnet). Full PDF Advisory available at: https://www.cisa.gov/sites/default/files/2026-04/aa26-088a-volt-typhoon-infrastructure-analysis.pdf.`,
  },
  {
    url: "https://posts.specterops.io/bloodhound-active-directory-tiering-and-attack-path-analysis/",
    title: "Purple Teaming Active Directory: Attack Path Analysis and Domain Tiering",
    sourceSlug: "specterops",
    publisher: "SpecterOps",
    category: "PURPLE_TEAM",
    sampleText: `This research examines modern adversary attack paths across Hybrid Active Directory and Entra ID environments. Adversaries frequently identify non-obvious ACL abuse paths (GenericAll, WriteDacl) to elevate from unprivileged domain users to Tier 0 Domain Admins without generating typical IOC alerts. By combining BloodHound graph analysis with purple-team simulation, organizations can systematically identify and remediate attack paths. Techniques covered include Kerberoasting (T1558.003), AS-REP Roasting, and shadow credentials via msDS-KeyCredentialLink injection (T1098). Referencing: https://github.com/SpecterOps/BloodHound.`,
  },
];
