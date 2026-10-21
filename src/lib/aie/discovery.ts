import { deriveCrawlPattern, isCandidateResourceUrl, matchesCrawlPattern } from "./qualification";
import { isSafeCrawlPatternString, isSafePublicUrlString } from "./security";
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
  "elastic.co",
  "research.checkpoint.com",
  "checkpoint.com",
  "volexity.com",
  "group-ib.com",
  "sygnia.co",
  "dragos.com",
  "rapid7.com",
  "qualys.com",
  "blog.qualys.com",
  "news.sophos.com",
  "sophos.com",
  "intezer.com",
  "cybereason.com",
  "blackberry.com",
  "recordedfuture.com",
  "proofpoint.com",
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
  // Non-CTI administrative, immigration, and civil government portals
  "uscis.gov",
  "ice.gov",
  "e-verify.gov",
  "edit.dhs.gov",
  "dhs.gov",
  "irs.gov",
  "state.gov",
  "treasury.gov",
  "justice.gov",
  "whitehouse.gov",
  "sec.gov",
  "usa.gov",
  // General media / news networks without dedicated technical threat research
  "cnn.com",
  "bbc.com",
  "nytimes.com",
  "wsj.com",
  "reuters.com",
  "bloomberg.com",
  "forbes.com",
]);

export function isBlacklistedDomain(domain: string, userBlocklist?: string[]): boolean {
  const clean = domain.toLowerCase().replace(/^www\./, "");

  // Authoritative CTI domains (e.g. cloud.google.com, mandiant.com) must NEVER be blocked
  if (TRUSTED_CTI_DOMAINS.has(clean)) return false;
  for (const trusted of TRUSTED_CTI_DOMAINS) {
    if (clean === trusted || clean.endsWith(`.${trusted}`)) return false;
  }
  if (clean === "cloud.google.com" || clean.endsWith(".cloud.google.com")) return false;

  if (STRICT_BLOCKED_DOMAINS.has(clean)) return true;
  for (const blocked of STRICT_BLOCKED_DOMAINS) {
    if (clean === blocked || clean.endsWith(`.${blocked}`)) return true;
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

  // Authoritative cybersecurity-specific government & CERT domains
  const isCyberGov =
    clean === "cisa.gov" ||
    clean.endsWith(".cisa.gov") ||
    clean === "csrc.nist.gov" ||
    clean === "ncsc.gov.uk" ||
    clean.endsWith(".ncsc.gov.uk") ||
    clean.startsWith("cert.") ||
    clean.includes("cert-");

  if (isCyberGov) {
    return { trustScore: 0.95, reason: "Official cybersecurity authority / CERT domain", isKnownCti: true };
  }

  if (clean.endsWith(".mil") || clean.endsWith(".gov")) {
    return { trustScore: 0.50, reason: "Unverified generic government domain", isKnownCti: false };
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
      // SSRF guard: drop outlinks to private/internal hosts or non-http(s) schemes before they are recorded.
      if (!isSafePublicUrlString(cleanUrl)) continue;

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

      // Score domain trust and candidate priority based on simulation value potential
      const trust = evaluateDomainTrust(targetHost);
      let priorityScore = trust.trustScore;

      // Bonus for evidence and simulation indicators in URL and anchor text
      const candidateContext = `${cleanUrl} ${rawAnchorText}`.toLowerCase();
      if (outlinkKind === "pdf_document") priorityScore += 0.20;
      if (outlinkKind === "citation" && trust.trustScore >= 0.85) priorityScore += 0.15;
      if (targetHost === "github.com" && /sigma|yara|atomic|caldera|adversary|poc/i.test(candidateContext)) {
        priorityScore += 0.20;
      }

      // High adversary simulation keywords in candidate anchor/slug
      if (
        /adversary|emulation|simulation|attack-chain|kill-chain|intrusion|powershell|lsass|mimikatz|c2|beacon|ransomware|lateral|credential|persistence|zero-day|cve-\d+/i.test(
          candidateContext,
        )
      ) {
        priorityScore += 0.25;
      }

      // Hard skip for marketing, commercial trials, product app pages, store paths, print duplicates, and index-heavy paths
      if (/tag\/|category\/|author\/|webinar|event|news-release|press-release|free-trial|trial|request-demo|demo|\/apps\/|\/forms\/whitepapers|we-live-progress|culture-at-speed|skanowanie|\?pdf=print|\?f%5B|\/products\/|\/solutions\/|\/pricing\/|\/business-security\/|\/business\//i.test(cleanUrl)) {
        continue;
      }

      priorityScore = Math.max(0.1, Math.min(1.0, Math.round(priorityScore * 100) / 100));

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
        const crawlPattern = deriveCrawlPattern(cleanUrl);
        const baseEndpoint = crawlPattern.replace(/\/\*+$/, "");
        const sourceHomepage = baseEndpoint.startsWith("http") ? baseEndpoint : `${resolved.protocol}//${targetHost}/`;
        // SSRF guard: never persist a discovered source that points at an internal/private host.
        if (
          !isSafePublicUrlString(targetHost) ||
          !isSafePublicUrlString(sourceHomepage) ||
          !isSafeCrawlPatternString(crawlPattern)
        ) {
          console.warn(`[discovery] skipping unsafe discovered source candidate: ${targetHost.slice(0, 120)}`);
          continue;
        }
        newDiscoveredSources.push({
          id: `src_disc_${targetHost.replace(/[^a-z0-9]/gi, "_").slice(0, 30)}`,
          domain: targetHost,
          name: targetHost.charAt(0).toUpperCase() + targetHost.slice(1),
          homepageUrl: sourceHomepage,
          crawlPattern,
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

// Synthetic knowledge pool removed: the crawler ingests only real fetched intelligence, never
// hardcoded sample text. Kept empty so the crawler import stays valid.
export const DISCOVERY_KNOWLEDGE_POOL: {
  url: string;
  title: string;
  sourceSlug: string;
  publisher: string;
  category: string;
  sampleText: string;
}[] = [
];
