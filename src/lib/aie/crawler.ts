import { analyzeThreatIntelligence, extractStructuredEntities } from "./attack-chain";
import {
  DISCOVERY_KNOWLEDGE_POOL,
  evaluateDomainTrust,
  extractOutlinksAndCitations,
  generateSearchQueries,
} from "./discovery";
import {
  canonicalizeUrl,
  computeHammingDistance,
  computeSimHash64,
  harvestIocs,
  htmlToText,
  MAX_BYTES,
  scoreQuality,
  sha256Hex,
  toIsoString,
} from "./extract";
import { parseRssOrAtomXml } from "./feeds";
import { buildPristineDocumentHtml } from "./pdf";
import { isCandidateResourceUrl, qualifyContent } from "./qualification";
import type {
  CrawlConfig,
  CrawlJob,
  CrawlJobItem,
  CrawlPipelineStage,
  CrawlTrigger,
  DiscoveredResource,
  SourceRecord,
} from "./types";
import { getSql } from "@/lib/db";
import { isMongoConfigured } from "../mongodb/client.server";
import {
  mongoFindReportByCanonical,
  mongoGetCrawlConfig,
  mongoInsertCrawlJob,
  mongoInsertCrawlJobItem,
  mongoInsertDiscoveredSource,
  mongoInsertGraphEdge,
  mongoInsertIngestEvent,
  mongoInsertReport,
  mongoListReports,
  mongoGetExistingReportsDedupIndex,
  mongoListSources,
  mongoSeedSources,
  mongoUpdateCrawlConfig,
  mongoUpdateCrawlJob,
  mongoUpdateSourceLastIngest,
  mongoUpsertDiscoveredResource,
  ensureMongoIndexes,
} from "../mongodb/repository.server";
import { SOURCE_SEED } from "./catalog";

function newId(prefix: string) {
  return `${prefix}_${crypto.randomUUID().replace(/-/g, "").slice(0, 16)}`;
}

// Active job cancellation tokens
const activeJobs = new Map<string, { cancel: boolean; pause: boolean }>();

interface FrontierItem {
  url: string;
  canonicalUrl: string;
  depth: number;
  priorityScore: number;
  parentUrl: string | null;
  parentSource: string | null;
  discoveryPath: string[];
  discoveryMethod: "seed_source" | "rss_feed" | "outlink_citation" | "pdf_reference" | "repo_reference" | "search_expansion";
  sourceId?: string;
  sourceSlug?: string;
  publisher?: string;
  domain: string;
  preloadedText?: string;
  title?: string;
}

export async function getOrCreateCrawlConfig(): Promise<CrawlConfig> {
  if (isMongoConfigured()) {
    try {
      return await mongoGetCrawlConfig();
    } catch (err) {
      console.warn("[mongodb] getOrCreateCrawlConfig fallback:", err);
    }
  }

  const sql = await getSql();
  const rows = await sql<CrawlConfig[]>`select * from crawl_config limit 1`;
  if (rows.length > 0) return rows[0];

  const defaultConfig: CrawlConfig = {
    id: "cfg_default",
    enabled: true,
    paused: false,
    frequencyMinutes: 360,
    startHour: "09:00",
    maxResourcesPerRun: 60,
    maxResourcesPerJob: 60,
    maxResourcesPerDomain: 8,
    maxDepth: 3,
    discoveryBreadth: "balanced",
    allowExternalDomains: true,
    domainAllowlist: [],
    domainBlocklist: [],
    rateLimitMs: 150,
    concurrency: 2,
    maxPdfDownloads: 10,
    autoIngest: true,
    autoAnalyze: true,
    generatePdf: true,
    rssDiscovery: true,
    htmlDiscovery: true,
    searchDiscovery: true,
    recursiveDiscovery: true,
    keywords: 'ransomware, "attack chain", "initial access", "lateral movement", "MITRE ATT&CK", "adversary emulation"',
    noiseKeywords: "webinar, discount, pricing, subscribe, careers, terms of service, privacy policy",
    minQualityScore: 0.35,
    minWordCount: 100,
    strictnessMode: "balanced",
    requireIocs: false,
    requireAttck: false,
    rejectMarketingNoise: true,
    dedupMethod: "smart_hybrid",
    activeSources: [],
    targetResourceTypes: [
      "FULL_ATTACK_CHAIN",
      "CAMPAIGN_INTEL",
      "PROCEDURE_DEEPDIVE",
      "MALWARE_ANALYSIS",
      "DETECTION_GUIDANCE",
      "VULNERABILITY_ADVISORY",
      "THREAT_ACTOR_DOSSIER",
    ],
    dateRangeDays: null,
    lastRunAt: null,
    nextRunAt: new Date(Date.now() + 6 * 60 * 60 * 1000).toISOString(),
  };

  await sql`
    insert into crawl_config (
      id, enabled, paused, frequency_minutes, start_hour, max_resources_per_run,
      max_depth, auto_ingest, auto_analyze, search_discovery, recursive_discovery,
      keywords, date_range_days, last_run_at, next_run_at
    ) values (
      ${defaultConfig.id}, ${defaultConfig.enabled}, ${defaultConfig.paused},
      ${defaultConfig.frequencyMinutes}, ${defaultConfig.startHour}, ${defaultConfig.maxResourcesPerRun},
      ${defaultConfig.maxDepth}, ${defaultConfig.autoIngest}, ${defaultConfig.autoAnalyze},
      ${defaultConfig.searchDiscovery}, ${defaultConfig.recursiveDiscovery}, ${defaultConfig.keywords},
      ${defaultConfig.dateRangeDays}, ${defaultConfig.lastRunAt}, ${defaultConfig.nextRunAt}
    )
  `;

  return defaultConfig;
}

export async function executeCrawlJob(
  jobId: string,
  triggerType: CrawlTrigger = "MANUAL",
  targetedQuery?: string,
): Promise<CrawlJob> {
  const sql = await getSql();
  const config = isMongoConfigured() ? await mongoGetCrawlConfig() : await getOrCreateCrawlConfig();

  const jobControl = { cancel: false, pause: false };
  activeJobs.set(jobId, jobControl);

  const breadth = config.discoveryBreadth || "balanced";
  let maxDepth = config.maxDepth || 3;
  if (breadth === "focused") maxDepth = 1;
  else if (breadth === "wide") maxDepth = Math.max(maxDepth, 4);

  const maxTotalResources = targetedQuery
    ? Math.max(config.maxResourcesPerJob || config.maxResourcesPerRun || 120, 100)
    : Math.max(config.maxResourcesPerJob || config.maxResourcesPerRun || 120, breadth === "wide" ? 180 : 120);
  const maxPerDomain = breadth === "wide" ? Math.max(config.maxResourcesPerDomain || 16, 16) : config.maxResourcesPerDomain || 12;
  const maxPdfDownloads = config.maxPdfDownloads || 10;

  const initialJob: CrawlJob = {
    id: jobId,
    status: "running",
    triggerType,
    startedAt: new Date().toISOString(),
    completedAt: null,
    sourceCount: 0,
    discoveredCount: 0,
    evaluatedCount: 0,
    qualifiedCount: 0,
    ingestedCount: 0,
    duplicateCount: 0,
    failedCount: 0,
    rejectedCount: 0,
    updatedCount: 0,
    skippedCount: 0,
    newSourcesCount: 0,
    pdfGeneratedCount: 0,
    errorSummary: "",
    currentStage: "discovered",
  };

  if (isMongoConfigured()) {
    try {
      await mongoInsertCrawlJob(initialJob);
    } catch (err) {
      console.warn("[mongodb] insert crawl job:", err);
    }
  }

  await sql`
    update crawl_jobs
    set status = 'running', started_at = now()
    where id = ${jobId}
  `;

  console.log(`[crawler] STARTING job ${jobId} (trigger=${triggerType}, query="${targetedQuery || ""}")`);

  let discoveredCount = 0;
  let evaluatedCount = 0;
  let qualifiedCount = 0;
  let ingestedCount = 0;
  let duplicateCount = 0;
  let failedCount = 0;
  let rejectedCount = 0;
  let skippedCount = 0;
  let newSourcesCount = 0;
  let pdfGeneratedCount = 0;
  let sources: SourceRecord[] = [];
  let jobFailed = false;
  let jobErrorSummary = "";

  try {
    if (isMongoConfigured()) {
      try {
        await ensureMongoIndexes();
      } catch {
        /* ignore index errors */
      }
    }

    // 1. Get enabled sources and merge updated SOURCE_SEED definitions
    const seedMap = new Map<string, SourceRecord>();
    for (const s of SOURCE_SEED) {
      seedMap.set(s.id, {
        ...s,
        feedUrl: s.feedUrl || `${s.homepageUrl.replace(/\/+$/, "")}/feed/`,
        lastIngestAt: null,
      });
    }

    if (isMongoConfigured()) {
      try {
        const allSources = await mongoListSources();
        for (const s of allSources) {
          const seed = seedMap.get(s.id);
          seedMap.set(s.id, {
            ...s,
            feedUrl: seed?.feedUrl || s.feedUrl || `${s.homepageUrl.replace(/\/+$/, "")}/feed/`,
          });
        }
      } catch (err) {
        console.warn("[mongodb] list sources fallback:", err);
      }
    }

    sources = Array.from(seedMap.values()).filter((s) => s.enabled !== false);
    if (isMongoConfigured()) {
      try {
        await mongoSeedSources(sources);
      } catch {
        /* ignore seed errors */
      }
    }

    // Apply whitelist if configured
    if (config.activeSources && config.activeSources.length > 0) {
      sources = sources.filter((s) => config.activeSources.includes(s.id) || config.activeSources.includes(s.slug));
    }

    if (isMongoConfigured()) {
      try {
        await mongoUpdateCrawlJob(jobId, { sourceCount: sources.length });
      } catch {
        /* ignore */
      }
    }

    try {
      await sql`update crawl_jobs set source_count = ${sources.length} where id = ${jobId}`;
    } catch {
      /* ignore sql fallback error */
    }

    // 2. Query existing storage for smart deduplication
    const storedCanonicalUrls = new Set<string>();
    const storedHashes = new Set<string>();
    const storedSimhashes: Array<{ id: string; simhash: string; title: string }> = [];

    if (isMongoConfigured()) {
      try {
        const existingReports = await mongoGetExistingReportsDedupIndex();
        for (const r of existingReports) {
          if (r.canonicalUrl) storedCanonicalUrls.add(r.canonicalUrl);
          if (r.textHash) storedHashes.add(r.textHash);
          if (r.title || r.excerpt) {
            storedSimhashes.push({
              id: r.id,
              simhash: computeSimHash64(`${r.title} ${r.excerpt || ""}`),
              title: r.title,
            });
          }
        }
      } catch {
        /* fallback to sql */
      }
    }

    try {
      const sqlExisting = await sql<{ canonical_url: string; text_hash: string }>`
        select canonical_url, text_hash from reports
      `;
      for (const r of sqlExisting) {
        if (r.canonical_url) storedCanonicalUrls.add(r.canonical_url);
        if (r.text_hash) storedHashes.add(r.text_hash);
      }
    } catch {
      /* ignore sql fallback */
    }

    // 3. Initialize the Priority Frontier Queue
    const frontierQueue: FrontierItem[] = [];
    const enqueuedUrls = new Set<string>();
    const domainVisitCounts = new Map<string, number>();

    const enqueue = (item: FrontierItem) => {
      if (enqueuedUrls.has(item.canonicalUrl)) return;
      enqueuedUrls.add(item.canonicalUrl);
      frontierQueue.push(item);
      discoveredCount++;
    };

    // Phase A: Seed Continuous Feeds (RSS & Atom)
    if (config.rssDiscovery !== false) {
      await Promise.allSettled(
        sources.map(async (source) => {
          if (!source.enabled) return;
          const feedTarget = source.feedUrl || `${source.homepageUrl.replace(/\/+$/, "")}/feed/`;
          try {
            const controller = new AbortController();
            const timeout = setTimeout(() => controller.abort(), 4500);

            const feedRes = await fetch(feedTarget, {
              signal: controller.signal,
              headers: {
                "user-agent": "AIE-Autonomous-Threat-Crawler/3.0 (+https://aie-intel.internal; cti-discovery-graph)",
                accept: "application/rss+xml, application/atom+xml, text/xml, */*",
              },
            }).catch(() => null);

            clearTimeout(timeout);

            if (feedRes && feedRes.ok) {
              const xml = await feedRes.text();
              const feedItems = parseRssOrAtomXml(xml);

              for (const item of feedItems) {
                try {
                  const canonical = canonicalizeUrl(item.url);
                  const domain = new URL(canonical).hostname.replace(/^www\./, "");
                  enqueue({
                    url: item.url,
                    canonicalUrl: canonical,
                    depth: 0,
                    priorityScore: 0.90,
                    parentUrl: feedTarget,
                    parentSource: source.name,
                    discoveryPath: [source.homepageUrl, item.url],
                    discoveryMethod: "rss_feed",
                    sourceId: source.id,
                    sourceSlug: source.slug,
                    publisher: source.name,
                    domain,
                    title: item.title,
                    preloadedText: item.rawContent || item.summary,
                  });
                } catch {
                  /* skip invalid */
                }
              }
            }
          } catch {
            /* silent fallback */
          }
        }),
      );
    }

    // Phase B: Seed Homepage Permalinks
    if (config.htmlDiscovery !== false) {
      await Promise.allSettled(
        sources.map(async (source) => {
          if (!source.enabled) return;
          try {
            const controller = new AbortController();
            const timeout = setTimeout(() => controller.abort(), 4500);

            const res = await fetch(source.homepageUrl, {
              signal: controller.signal,
              headers: {
                "user-agent": "AIE-Autonomous-Threat-Crawler/3.0 (+https://aie-intel.internal; cti-discovery-graph)",
                accept: "text/html,application/xhtml+xml,text/plain",
              },
            }).catch(() => null);

            clearTimeout(timeout);

            if (res && res.ok) {
              const html = await res.text();
              const { discoveredLinks, newDiscoveredSources, graphEdges } = extractOutlinksAndCitations(
                html,
                source.homepageUrl,
                {
                  sourceId: source.id,
                  publisher: source.name,
                  discoveryMethod: "crawl_source",
                  depth: 1,
                  allowExternalDomains: config.allowExternalDomains !== false,
                  domainAllowlist: config.domainAllowlist,
                  domainBlocklist: config.domainBlocklist,
                },
              );

              // Persist newly discovered sources and edges into MongoDB
              if (isMongoConfigured()) {
                for (const src of newDiscoveredSources) {
                  await mongoInsertDiscoveredSource(src);
                  newSourcesCount++;
                }
                for (const edge of graphEdges) {
                  await mongoInsertGraphEdge({ ...edge, jobId });
                }
              }

              for (const link of discoveredLinks) {
                // Filter out non-technical site navigation, legal, and boilerplate links
                if (/privacy|terms|contact|about|cookie|careers|login|signin|register|legal|jobs|pricing|subscribe|donate/i.test(link.canonicalUrl)) {
                  continue;
                }
                enqueue({
                  url: link.url,
                  canonicalUrl: link.canonicalUrl,
                  depth: 1,
                  priorityScore: link.priorityScore,
                  parentUrl: source.homepageUrl,
                  parentSource: source.name,
                  discoveryPath: link.discoveryPath,
                  discoveryMethod: link.isExternalDomain ? "outlink_citation" : "seed_source",
                  sourceId: source.id,
                  sourceSlug: source.slug,
                  publisher: link.publisher || source.name,
                  domain: link.domain,
                  title: link.title,
                });
              }

              // Deep Source Exploration: Crawl dedicated research archives if configured
              if (source.researchArchives && source.researchArchives.length > 0) {
                for (const archiveUrl of source.researchArchives) {
                  if (archiveUrl === source.homepageUrl) continue;
                  try {
                    const archRes = await fetch(archiveUrl, {
                      headers: {
                        "user-agent": "AIE-Autonomous-Threat-Crawler/3.0 (+https://aie-intel.internal; cti-discovery-graph)",
                        accept: "text/html,application/xhtml+xml,text/plain",
                      },
                    }).catch(() => null);
                    if (archRes && archRes.ok) {
                      const archHtml = await archRes.text();
                      const archLinks = extractOutlinksAndCitations(archHtml, archiveUrl, {
                        sourceId: source.id,
                        publisher: source.name,
                        discoveryMethod: "crawl_source",
                        depth: 1,
                        allowExternalDomains: config.allowExternalDomains !== false,
                        domainAllowlist: config.domainAllowlist,
                        domainBlocklist: config.domainBlocklist,
                      });
                      for (const l of archLinks.discoveredLinks) {
                        enqueue({
                          url: l.url,
                          canonicalUrl: l.canonicalUrl,
                          depth: 1,
                          priorityScore: l.priorityScore + 0.05,
                          parentUrl: archiveUrl,
                          parentSource: source.name,
                          discoveryPath: l.discoveryPath,
                          discoveryMethod: "seed_source",
                          sourceId: source.id,
                          sourceSlug: source.slug,
                          publisher: l.publisher || source.name,
                          domain: l.domain,
                          title: l.title,
                        });
                      }
                    }
                  } catch {
                    /* ignore */
                  }
                }
              }

              // Deep Pagination: Explore page 2 for high-trust sources if breadth is balanced/wide
              if ((breadth === "wide" || maxDepth >= 3) && source.paginationPattern) {
                const page2Url = source.paginationPattern.replace("{n}", "2");
                try {
                  const p2Res = await fetch(page2Url, {
                    headers: {
                      "user-agent": "AIE-Autonomous-Threat-Crawler/3.0 (+https://aie-intel.internal)",
                    },
                  }).catch(() => null);
                  if (p2Res && p2Res.ok) {
                    const p2Html = await p2Res.text();
                    const p2Links = extractOutlinksAndCitations(p2Html, page2Url, {
                      sourceId: source.id,
                      publisher: source.name,
                      discoveryMethod: "crawl_source",
                      depth: 2,
                    });
                    for (const l of p2Links.discoveredLinks) {
                      enqueue({
                        url: l.url,
                        canonicalUrl: l.canonicalUrl,
                        depth: 2,
                        priorityScore: l.priorityScore,
                        parentUrl: page2Url,
                        parentSource: source.name,
                        discoveryPath: l.discoveryPath,
                        discoveryMethod: "seed_source",
                        sourceId: source.id,
                        sourceSlug: source.slug,
                        publisher: l.publisher || source.name,
                        domain: l.domain,
                        title: l.title,
                      });
                    }
                  }
                } catch {
                  /* ignore */
                }
              }
            }
          } catch {
            /* silent */
          }
        }),
      );
    }

    // Phase C: Real-Time Web & Graph Search Discovery
    if (config.searchDiscovery !== false || targetedQuery) {
      const activeKeywords = (targetedQuery || config.keywords || "").trim();

      // Execute live search against CTI indices & open web if active query is present
      if (activeKeywords.length > 0) {
        const searchTerms = [
          `"${activeKeywords}" threat intelligence technical analysis`,
          `"${activeKeywords}" attack chain indicators of compromise`,
          `${activeKeywords} cve technical writeup advisory filetype:html OR filetype:pdf`,
        ];

        for (const term of searchTerms) {
          try {
            const controller = new AbortController();
            const timeout = setTimeout(() => controller.abort(), 6000);

            const searchUrl = `https://html.duckduckgo.com/html/?q=${encodeURIComponent(term)}`;
            const res = await fetch(searchUrl, {
              signal: controller.signal,
              headers: {
                "user-agent":
                  "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36",
                accept: "text/html,application/xhtml+xml,text/plain",
              },
            }).catch(() => null);

            clearTimeout(timeout);

            if (res && res.ok) {
              const html = await res.text();
              const uddgMatches = [...html.matchAll(/\/l\/\?kh=-1&amp;uddg=([^"&]+)/g)];
              for (const m of uddgMatches) {
                try {
                  const targetUrl = decodeURIComponent(m[1]);
                  const urlObj = new URL(targetUrl);
                  const domain = urlObj.hostname.toLowerCase().replace(/^www\./, "");
                  const blocked = [
                    "duckduckgo.com",
                    "bing.com",
                    "google.com",
                    "youtube.com",
                    "wikipedia.org",
                    "facebook.com",
                    "twitter.com",
                    "x.com",
                    "linkedin.com",
                    "instagram.com",
                  ];
                  if (blocked.some((b) => domain.includes(b))) continue;

                  const check = isCandidateResourceUrl(targetUrl);
                  if (
                    check.isResource ||
                    targetUrl.endsWith(".pdf") ||
                    /cve|threat|attack|ransomware|malware|incident|advisory|report/i.test(targetUrl)
                  ) {
                    const canonical = canonicalizeUrl(targetUrl);
                    enqueue({
                      url: targetUrl,
                      canonicalUrl: canonical,
                      depth: 0,
                      priorityScore: 0.99,
                      parentUrl: null,
                      parentSource: `Live CTI Web Discovery (${activeKeywords})`,
                      discoveryPath: [targetUrl],
                      discoveryMethod: "search_expansion",
                      sourceId: "src_web_search",
                      publisher: domain,
                      domain,
                      title:
                        targetUrl.split("/").filter(Boolean).pop()?.replace(/[-_]/g, " ") ||
                        `Live CTI: ${activeKeywords}`,
                    });
                  }
                } catch {
                  /* skip invalid URL */
                }
              }
            }
          } catch {
            /* ignore live search network errors */
          }
        }
      }

      // Also enqueue curated knowledge pool
      for (const item of DISCOVERY_KNOWLEDGE_POOL) {
        try {
          const canonical = canonicalizeUrl(item.url);
          const domain = new URL(canonical).hostname.replace(/^www\./, "");
          const matchingSource = sources.find((s) => s.slug === item.sourceSlug) || sources[0];

          enqueue({
            url: item.url,
            canonicalUrl: canonical,
            depth: 0,
            priorityScore: 0.95,
            parentUrl: null,
            parentSource: matchingSource?.name || "Verified Intelligence Pool",
            discoveryPath: [item.url],
            discoveryMethod: "search_expansion",
            sourceId: matchingSource?.id || "src_dfir",
            sourceSlug: item.sourceSlug,
            publisher: item.publisher,
            domain,
            title: item.title,
            preloadedText: item.sampleText,
          });
        } catch {
          /* skip */
        }
      }
    }

    // 4. MAIN FRONTIER PROCESSING LOOP
    // Dynamically pops the highest-priority resource and explores outbound relationships
    while (frontierQueue.length > 0 && evaluatedCount < maxTotalResources) {
      if (jobControl.cancel) break;

      // Sort by priority descending to dequeue the most technically relevant resource
      frontierQueue.sort((a, b) => b.priorityScore - a.priorityScore);
      const current = frontierQueue.shift()!;

      // Enforce per-domain limit on seed source homepage crawling to prevent getting trapped in site navigation,
      // but allow citation outlinks and live search discovery to explore external domains freely
      const currentDomainCount = domainVisitCounts.get(current.domain) || 0;
      if (currentDomainCount >= maxPerDomain && current.depth > 0 && current.discoveryMethod === "seed_source") {
        continue;
      }

      evaluatedCount++;
      domainVisitCounts.set(current.domain, currentDomainCount + 1);

      // Log progress to MongoDB in real time
      if (isMongoConfigured() && evaluatedCount % 5 === 0) {
        await mongoUpdateCrawlJob(jobId, {
          discoveredCount,
          evaluatedCount,
          qualifiedCount,
          ingestedCount,
          duplicateCount,
          failedCount,
          rejectedCount,
          skippedCount,
          newSourcesCount,
          pdfGeneratedCount,
          currentUrl: current.url,
          currentStage: "evaluated",
        });
      }

      // 4.1 Deduplication Check
      let isDuplicate = false;
      if (config.dedupMethod === "canonical_url" || config.dedupMethod === "both" || config.dedupMethod === "smart_hybrid") {
        if (storedCanonicalUrls.has(current.canonicalUrl)) {
          isDuplicate = true;
        }
      }

      if (isDuplicate) {
        duplicateCount++;
        const itemId = newId("itm");
        const jobItem: CrawlJobItem = {
          id: itemId,
          jobId,
          sourceId: current.sourceId || null,
          url: current.url,
          canonicalUrl: current.canonicalUrl,
          title: current.title || "Untitled",
          classification: "THREAT_REPORT",
          decision: "DUPLICATE",
          reason: "Canonical URL already acquired in knowledge base",
          stage: "duplicate",
          discoveryMethod: current.discoveryMethod,
          discoveryQuery: "",
          parentUrl: current.parentUrl,
          depth: current.depth,
          publisher: current.publisher || current.domain,
          discoveryPath: current.discoveryPath,
          createdAt: new Date().toISOString(),
        };

        if (isMongoConfigured()) {
          await mongoInsertCrawlJobItem(jobItem);
        }
        await sql`
          insert into crawl_job_items (
            id, job_id, source_id, url, canonical_url, title, classification,
            decision, reason, discovery_method, discovery_query, depth, publisher
          ) values (
            ${itemId}, ${jobId}, ${current.sourceId ?? null}, ${current.url}, ${current.canonicalUrl},
            ${current.title ?? 'Untitled'}, 'THREAT_REPORT', 'DUPLICATE',
            'Canonical URL already acquired in knowledge base',
            ${current.discoveryMethod}, '', ${current.depth}, ${current.publisher ?? current.domain}
          )
        `;

        // Deep Graph Expansion: Even if canonical report is already acquired,
        // extract its outbound citations to discover fresh external threat papers and repositories!
        if (config.recursiveDiscovery !== false && current.depth < maxDepth) {
          try {
            let storedHtml = "";
            if (isMongoConfigured()) {
              const existing = await mongoFindReportByCanonical(current.canonicalUrl);
              storedHtml = existing?.rawHtml || existing?.extractedText || "";
            }
            if (storedHtml && storedHtml.length > 200) {
              const { discoveredLinks, newDiscoveredSources, graphEdges } = extractOutlinksAndCitations(
                storedHtml,
                current.canonicalUrl,
                {
                  sourceId: current.sourceId,
                  publisher: current.publisher,
                  parentPath: current.discoveryPath,
                  depth: current.depth + 1,
                  allowExternalDomains: config.allowExternalDomains !== false,
                  domainAllowlist: config.domainAllowlist,
                  domainBlocklist: config.domainBlocklist,
                },
              );

              if (isMongoConfigured()) {
                for (const newSrc of newDiscoveredSources) {
                  await mongoInsertDiscoveredSource(newSrc);
                  newSourcesCount++;
                }
                for (const edge of graphEdges) {
                  await mongoInsertGraphEdge({ ...edge, jobId });
                }
              }

              for (const outlink of discoveredLinks) {
                enqueue({
                  url: outlink.url,
                  canonicalUrl: outlink.canonicalUrl,
                  depth: current.depth + 1,
                  priorityScore: outlink.priorityScore,
                  parentUrl: current.canonicalUrl,
                  parentSource: current.publisher || current.domain,
                  discoveryPath: outlink.discoveryPath,
                  discoveryMethod: outlink.isExternalDomain ? "outlink_citation" : "seed_source",
                  sourceId: current.sourceId,
                  publisher: outlink.publisher,
                  domain: outlink.domain,
                  title: outlink.title,
                });
              }
            }
          } catch {
            /* ignore outlink expansion error */
          }
        }

        continue;
      }

      // 4.2 Content Acquisition
      let textContent = current.preloadedText || "";
      let docTitle = current.title || "Threat Intelligence Report";
      let contentType = "text/html";
      let rawBytes: Uint8Array | string = current.preloadedText || "";
      let fetchedHtmlBody = "";

      const currentWordCount = textContent.split(/\s+/).filter(Boolean).length;
      const needsFullArticleFetch = currentWordCount < 300;

      if (needsFullArticleFetch) {
        try {
          // Polite rate limit delay
          if (config.rateLimitMs > 0) {
            await new Promise((r) => setTimeout(r, Math.min(config.rateLimitMs, 250)));
          }

          const controller = new AbortController();
          const timeout = setTimeout(() => controller.abort(), 8000);

          const res = await fetch(current.canonicalUrl, {
            signal: controller.signal,
            headers: {
              "user-agent": "AIE-Autonomous-Threat-Crawler/3.0 (+research; public-cti; threat-emulation-engine)",
              accept: "text/html,application/xhtml+xml,application/pdf,text/plain",
            },
          });
          clearTimeout(timeout);

          if (res.ok) {
            const buf = new Uint8Array(await res.arrayBuffer());
            rawBytes = buf;
            contentType = (res.headers.get("content-type") ?? "text/html").split(";")[0].trim();

            if (contentType.includes("pdf")) {
              textContent = `PDF Document Evidence: ${current.title || current.canonicalUrl}. Raw cryptographic evidence and technical content preserved.`;
            } else {
              const body = new TextDecoder("utf-8", { fatal: false }).decode(buf);
              fetchedHtmlBody = body;
              const extracted = htmlToText(body);
              if (extracted.text && extracted.text.length > textContent.length) {
                textContent = extracted.text;
              }
              if (extracted.title && extracted.title !== "Untitled report") {
                docTitle = extracted.title;
              }
            }
          }
        } catch (fetchErr) {
          // If we already had preloadedText, keep it; otherwise track failure
          if (!textContent) {
            failedCount++;
            const itemId = newId("itm");
            const errMsg = fetchErr instanceof Error ? fetchErr.message : "Fetch failed";
            const jobItem: CrawlJobItem = {
              id: itemId,
              jobId,
              sourceId: current.sourceId || null,
              url: current.url,
              canonicalUrl: current.canonicalUrl,
              title: current.title || "Fetch Failure",
              classification: "OTHER",
              decision: "FAILED",
              reason: errMsg,
              stage: "failed",
              discoveryMethod: current.discoveryMethod,
              discoveryQuery: "",
              parentUrl: current.parentUrl,
              depth: current.depth,
              publisher: current.publisher || current.domain,
              discoveryPath: current.discoveryPath,
              createdAt: new Date().toISOString(),
            };

            if (isMongoConfigured()) {
              await mongoInsertCrawlJobItem(jobItem);
            }
            continue;
          }
        }
      }


      // Check Content Hash Deduplication
      const textHash = sha256Hex(textContent);
      if (
        (config.dedupMethod === "content_hash" || config.dedupMethod === "both" || config.dedupMethod === "smart_hybrid") &&
        storedHashes.has(textHash)
      ) {
        duplicateCount++;
        continue;
      }

      // Check Near-Duplicate & Syndication with SimHash
      if (config.dedupMethod === "smart_hybrid" || config.dedupMethod === "content_hash" || config.dedupMethod === "both") {
        const candidateSimhash = computeSimHash64(`${docTitle} ${textContent.slice(0, 3000)}`);
        const nearDuplicate = storedSimhashes.find(
          (s) => computeHammingDistance(s.simhash, candidateSimhash) <= 3,
        );
        if (nearDuplicate) {
          duplicateCount++;
          console.log(`[crawler] SYNDICATED / NEAR-DUPLICATE of ${nearDuplicate.id}: "${docTitle.slice(0, 60)}"`);
          const itemId = newId("itm");
          const jobItem: CrawlJobItem = {
            id: itemId,
            jobId,
            sourceId: current.sourceId || null,
            url: current.url,
            canonicalUrl: current.canonicalUrl,
            title: docTitle,
            classification: "THREAT_REPORT",
            decision: "DUPLICATE",
            reason: `Syndicated or near-duplicate reproduction of canonical report ${nearDuplicate.id} ("${nearDuplicate.title.slice(0, 50)}")`,
            stage: "duplicate",
            discoveryMethod: current.discoveryMethod,
            discoveryQuery: "",
            parentUrl: current.parentUrl,
            depth: current.depth,
            publisher: current.publisher || current.domain,
            discoveryPath: current.discoveryPath,
            createdAt: new Date().toISOString(),
          };
          if (isMongoConfigured()) {
            await mongoInsertCrawlJobItem(jobItem);
          }
          continue;
        }
      }

      // Check dateRangeDays filter if configured
      if (config.dateRangeDays && config.dateRangeDays > 0) {
        const pubDateMatch = textContent.slice(0, 1500).match(/\b(202[0-6])[-/](0[1-9]|1[0-2])[-/](0[1-9]|[12]\d|3[01])\b/);
        if (pubDateMatch) {
          const parsedPubDate = new Date(pubDateMatch[0]).getTime();
          const cutoff = Date.now() - config.dateRangeDays * 24 * 60 * 60 * 1000;
          if (!isNaN(parsedPubDate) && parsedPubDate < cutoff) {
            skippedCount++;
            continue;
          }
        }
      }

      // Check maxPdfDownloads limit
      const isPdf = contentType.includes("pdf") || /\.pdf$/i.test(current.canonicalUrl);
      if (isPdf && pdfGeneratedCount >= (config.maxPdfDownloads || 10)) {
        skippedCount++;
        continue;
      }

      // 4.3 Recursive Citation & Graph Outlink Exploration
      // When a report contains links to new domains or papers, expand outward!
      if (
        config.recursiveDiscovery !== false &&
        current.depth < maxDepth &&
        fetchedHtmlBody &&
        discoveredCount < maxTotalResources * 2
      ) {
        const { discoveredLinks, newDiscoveredSources, graphEdges } = extractOutlinksAndCitations(
          fetchedHtmlBody,
          current.canonicalUrl,
          {
            sourceId: current.sourceId,
            publisher: current.publisher,
            parentPath: current.discoveryPath,
            depth: current.depth + 1,
            allowExternalDomains: config.allowExternalDomains !== false,
            domainAllowlist: config.domainAllowlist,
            domainBlocklist: config.domainBlocklist,
          },
        );

        if (isMongoConfigured()) {
          for (const newSrc of newDiscoveredSources) {
            await mongoInsertDiscoveredSource(newSrc);
            newSourcesCount++;
          }
          for (const edge of graphEdges) {
            await mongoInsertGraphEdge({ ...edge, jobId });
          }
        }

        // Push discovered citations, PDFs, and external research papers into the frontier!
        for (const outlink of discoveredLinks) {
          enqueue({
            url: outlink.url,
            canonicalUrl: outlink.canonicalUrl,
            depth: current.depth + 1,
            priorityScore: outlink.priorityScore,
            parentUrl: current.canonicalUrl,
            parentSource: current.publisher || current.domain,
            discoveryPath: outlink.discoveryPath,
            discoveryMethod: outlink.isExternalDomain ? "outlink_citation" : "seed_source",
            sourceId: current.sourceId,
            publisher: outlink.publisher,
            domain: outlink.domain,
            title: outlink.title,
          });
        }
      }

      // 4.4 Heuristic Qualification & Noise Elimination
      const isFeedEntry = current.discoveryMethod === "rss_feed";
      const qual = qualifyContent(textContent, docTitle, current.canonicalUrl, config, isFeedEntry);

      if (!qual.qualified) {
        rejectedCount++;
        const itemId = newId("itm");
        const rejectMsg = qual.rejectionReason || "Below qualification threshold";

        const jobItem: CrawlJobItem = {
          id: itemId,
          jobId,
          sourceId: current.sourceId || null,
          url: current.url,
          canonicalUrl: current.canonicalUrl,
          title: docTitle,
          classification: qual.classification,
          decision: "REJECTED",
          reason: rejectMsg,
          stage: "rejected",
          discoveryMethod: current.discoveryMethod,
          discoveryQuery: "",
          parentUrl: current.parentUrl,
          depth: current.depth,
          publisher: current.publisher || current.domain,
          qualityScore: qual.score,
          simulationScore: qual.simulationScore,
          isEmergingTechnique: qual.isEmergingTechnique,
          noveltyRationale: qual.noveltyRationale,
          resourceKind: qual.resourceKind,
          discoveryPath: current.discoveryPath,
          createdAt: new Date().toISOString(),
        };

        if (isMongoConfigured()) {
          await mongoInsertCrawlJobItem(jobItem);
          await mongoUpsertDiscoveredResource({
            id: newId("dsc"),
            canonicalUrl: current.canonicalUrl,
            url: current.url,
            sourceId: current.sourceId || null,
            title: docTitle,
            publisher: current.publisher || current.domain,
            classification: qual.classification,
            resourceKind: qual.resourceKind,
            discoveryMethod: current.discoveryMethod,
            discoveryQuery: "",
            parentSource: current.parentSource || current.domain,
            parentUrl: current.parentUrl,
            sourceDomain: current.domain,
            contentType,
            status: "rejected",
            rejectReason: rejectMsg,
            qualityScore: qual.score,
            simulationScore: qual.simulationScore,
            isEmergingTechnique: qual.isEmergingTechnique,
            noveltyRationale: qual.noveltyRationale,
            discoveryPath: current.discoveryPath,
          });
        }

        try {
          await sql`
            insert into crawl_job_items (
              id, job_id, source_id, url, canonical_url, title, classification,
              decision, reason, discovery_method, discovery_query, depth, publisher
            ) values (
              ${itemId}, ${jobId}, ${current.sourceId ?? null}, ${current.url}, ${current.canonicalUrl},
              ${docTitle}, ${qual.classification}, 'REJECTED', ${rejectMsg},
              ${current.discoveryMethod}, '', ${current.depth}, ${current.publisher ?? current.domain}
            )
          `;

          await sql`
            insert into discovered_resources (
              id, canonical_url, url, source_id, title, publisher, classification,
              discovery_method, discovery_query, parent_source, source_domain,
              content_type, status, reject_reason, quality_score
            ) values (
              ${newId("dsc")}, ${current.canonicalUrl}, ${current.url}, ${current.sourceId ?? null}, ${docTitle},
              ${current.publisher ?? current.domain}, ${qual.classification}, ${current.discoveryMethod},
              '', ${current.parentSource ?? current.domain}, ${current.domain},
              ${contentType}, 'rejected', ${rejectMsg}, ${qual.score}
            )
            on conflict (canonical_url) do update
            set status = 'rejected', reject_reason = excluded.reject_reason, updated_at = now()
          `;
        } catch {
          /* ignore sql fallback error */
        }
        continue;
      }

      qualifiedCount++;

      // 4.5 Structured Entity Extraction, ATT&CK Analysis & PDF Generation
      const { score, reasons, wordCount } = scoreQuality(textContent, docTitle);
      const iocs = harvestIocs(textContent);
      const rawHash = sha256Hex(rawBytes || textContent);
      const reportId = newId("rpt");

      let intelAnalysis = null;
      let extractedEntities = undefined;
      if (config.autoAnalyze) {
        intelAnalysis = analyzeThreatIntelligence(textContent, docTitle, qual.classification);
        extractedEntities = extractStructuredEntities(textContent, docTitle, qual.classification, intelAnalysis);
      }

      // High-Fidelity PDF & HTML Layout Generation
      let pristineHtml = "";
      if (config.generatePdf !== false) {
        pristineHtml = buildPristineDocumentHtml(fetchedHtmlBody || textContent, {
          id: reportId,
          title: docTitle,
          url: current.url,
          canonicalUrl: current.canonicalUrl,
          publisher: current.publisher || current.domain,
          author: current.publisher || current.domain,
          publishedAt: new Date().toISOString().slice(0, 10),
          ingestedAt: new Date().toISOString(),
          classification: qual.classification,
          rawHash,
          textHash,
          qualityScore: score,
          wordCount,
          iocs,
          analysis: intelAnalysis,
        });
        pdfGeneratedCount++;
      }

      // 4.6 Ingestion vs Human Review Queue
      if (config.autoIngest) {
        ingestedCount++;
        storedCanonicalUrls.add(current.canonicalUrl);
        storedHashes.add(textHash);
        console.log(`[crawler] INGESTED: "${docTitle.slice(0, 60)}" (${qual.resourceKind}, score: ${score}, ${iocs.length} IOCs) -> ${current.domain}`);

        // Persist to MongoDB Atlas
        if (isMongoConfigured()) {
          try {
            await mongoInsertReport({
              id: reportId,
              sourceId: current.sourceId || "src_expanded",
              sourceName: current.publisher || current.domain,
              title: docTitle,
              url: current.url,
              canonicalUrl: current.canonicalUrl,
              publishedAt: new Date().toISOString().slice(0, 10),
              contentType,
              status: "acquired",
              rawHash,
              textHash,
              qualityScore: score,
              qualityReasons: reasons,
              wordCount,
              extractedText: textContent,
              iocs,
              ingestOrigin: current.depth > 0 ? "citation_expansion" : "crawl",
              ingestedAt: new Date().toISOString(),
              publisher: current.publisher || current.domain,
              author: current.publisher || current.domain,
              classification: qual.classification,
              resourceKind: qual.resourceKind,
              extractedEntities,
              discoveryMethod: current.discoveryMethod,
              discoveryQuery: "",
              parentSource: current.parentSource || current.domain,
              sourceDomain: current.domain,
              version: 1,
              rawHtml: pristineHtml,
              pdfUrl: "",
              analysis: intelAnalysis,
              discoveryPath: current.discoveryPath,
              simulationScore: qual.simulationScore,
              isEmergingTechnique: qual.isEmergingTechnique,
              noveltyRationale: qual.noveltyRationale,
            });

            storedSimhashes.push({
              id: reportId,
              simhash: computeSimHash64(`${docTitle} ${textContent.slice(0, 3000)}`),
              title: docTitle,
            });

            if (current.sourceId) {
              await mongoUpdateSourceLastIngest(current.sourceId);
            }

            await mongoInsertIngestEvent({
              id: newId("evt"),
              reportId,
              url: current.url,
              outcome: "acquired",
              detail: `[${qual.resourceKind}] quality ${score} (sim: ${qual.simulationScore}) · ${wordCount} words · ${iocs.length} IOCs · Depth ${current.depth} (${current.domain})`,
              createdAt: new Date().toISOString(),
            });

            await mongoUpsertDiscoveredResource({
              id: newId("dsc"),
              canonicalUrl: current.canonicalUrl,
              url: current.url,
              sourceId: current.sourceId || null,
              title: docTitle,
              publisher: current.publisher || current.domain,
              classification: qual.classification,
              resourceKind: qual.resourceKind,
              discoveryMethod: current.discoveryMethod,
              discoveryQuery: "",
              parentSource: current.parentSource || current.domain,
              parentUrl: current.parentUrl,
              sourceDomain: current.domain,
              contentType,
              status: "ingested",
              qualityScore: score,
              simulationScore: qual.simulationScore,
              isEmergingTechnique: qual.isEmergingTechnique,
              noveltyRationale: qual.noveltyRationale,
              reportId,
              discoveryPath: current.discoveryPath,
            });
          } catch (mongoErr) {
            console.warn("[mongodb] report persistence error:", mongoErr);
          }
        }

        // Persist to SQL store (optional fallback)
        try {
          await sql`
            insert into reports (
              id, source_id, title, url, canonical_url, published_at, content_type,
              status, raw_hash, text_hash, quality_score, quality_reasons, word_count,
              extracted_text, iocs_json, ingest_origin, publisher, author,
              classification, discovery_method, discovery_query, parent_source,
              source_domain, version, analysis_json, raw_html
            ) values (
              ${reportId}, ${current.sourceId ?? 'src_dfir'}, ${docTitle}, ${current.url}, ${current.canonicalUrl},
              ${new Date().toISOString().slice(0, 10)}, ${contentType}, 'acquired',
              ${rawHash}, ${textHash}, ${score}, ${JSON.stringify(reasons)}, ${wordCount},
              ${textContent}, ${JSON.stringify(iocs)}, ${current.depth > 0 ? 'citation_expansion' : 'crawl'},
              ${current.publisher ?? current.domain}, ${current.publisher ?? current.domain},
              ${qual.classification}, ${current.discoveryMethod}, '', ${current.parentSource ?? current.domain},
              ${current.domain}, 1, ${JSON.stringify(intelAnalysis)}, ${pristineHtml}
            )
          `;

          await sql`
            insert into discovered_resources (
              id, canonical_url, url, source_id, title, publisher, classification,
              discovery_method, discovery_query, parent_source, source_domain,
              content_type, status, quality_score, report_id
            ) values (
              ${newId("dsc")}, ${current.canonicalUrl}, ${current.url}, ${current.sourceId ?? null}, ${docTitle},
              ${current.publisher ?? current.domain}, ${qual.classification}, ${current.discoveryMethod},
              '', ${current.parentSource ?? current.domain}, ${current.domain},
              ${contentType}, 'ingested', ${score}, ${reportId}
            )
            on conflict (canonical_url) do update
            set status = 'ingested', quality_score = ${score}, report_id = ${reportId}, updated_at = now()
          `;
        } catch {
          /* ignore SQL fallback error */
        }

        const itemId = newId("itm");
        const jobItem: CrawlJobItem = {
          id: itemId,
          jobId,
          sourceId: current.sourceId || null,
          url: current.url,
          canonicalUrl: current.canonicalUrl,
          title: docTitle,
          classification: qual.classification,
          decision: "INGESTED",
          reason: `Qualified (${qual.resourceKind}): quality ${score} with ${iocs.length} IOCs · Depth ${current.depth}`,
          stage: "ingested",
          discoveryMethod: current.discoveryMethod,
          discoveryQuery: "",
          parentUrl: current.parentUrl,
          depth: current.depth,
          publisher: current.publisher || current.domain,
          qualityScore: score,
          resourceKind: qual.resourceKind,
          discoveryPath: current.discoveryPath,
          createdAt: new Date().toISOString(),
        };

        if (isMongoConfigured()) {
          await mongoInsertCrawlJobItem(jobItem);
        }
        try {
          await sql`
            insert into crawl_job_items (
              id, job_id, source_id, url, canonical_url, title, classification,
              decision, reason, discovery_method, discovery_query, depth, publisher
            ) values (
              ${itemId}, ${jobId}, ${current.sourceId ?? null}, ${current.url}, ${current.canonicalUrl},
              ${docTitle}, ${qual.classification}, 'INGESTED',
              ${`Qualified (${qual.resourceKind}): quality ${score} with ${iocs.length} IOCs · Depth ${current.depth}`},
              ${current.discoveryMethod}, '', ${current.depth}, ${current.publisher ?? current.domain}
            )
          `;
        } catch {
          /* ignore */
        }
      } else {
        // Auto-ingest is OFF: Hold in queue with explicit state for analyst review
        skippedCount++;
        const itemId = newId("itm");
        const jobItem: CrawlJobItem = {
          id: itemId,
          jobId,
          sourceId: current.sourceId || null,
          url: current.url,
          canonicalUrl: current.canonicalUrl,
          title: docTitle,
          classification: qual.classification,
          decision: "AWAITING_APPROVAL",
          reason: `Qualified (${qual.resourceKind}): quality ${score}. Auto-ingest is disabled in settings; held in Discovery Queue for approval.`,
          stage: "qualified",
          discoveryMethod: current.discoveryMethod,
          discoveryQuery: "",
          parentUrl: current.parentUrl,
          depth: current.depth,
          publisher: current.publisher || current.domain,
          qualityScore: score,
          resourceKind: qual.resourceKind,
          discoveryPath: current.discoveryPath,
          createdAt: new Date().toISOString(),
        };

        if (isMongoConfigured()) {
          await mongoInsertCrawlJobItem(jobItem);
          await mongoUpsertDiscoveredResource({
            id: newId("dsc"),
            canonicalUrl: current.canonicalUrl,
            url: current.url,
            sourceId: current.sourceId || null,
            title: docTitle,
            publisher: current.publisher || current.domain,
            classification: qual.classification,
            resourceKind: qual.resourceKind,
            discoveryMethod: current.discoveryMethod,
            discoveryQuery: "",
            parentSource: current.parentSource || current.domain,
            parentUrl: current.parentUrl,
            sourceDomain: current.domain,
            contentType,
            status: "awaiting_approval",
            qualityScore: score,
            discoveryPath: current.discoveryPath,
          });
        }

        try {
          await sql`
            insert into crawl_job_items (
              id, job_id, source_id, url, canonical_url, title, classification,
              decision, reason, discovery_method, discovery_query, depth, publisher
            ) values (
              ${itemId}, ${jobId}, ${current.sourceId ?? null}, ${current.url}, ${current.canonicalUrl},
              ${docTitle}, ${qual.classification}, 'AWAITING_APPROVAL',
              'Qualified by engine; held in Discovery Queue for manual ingestion approval',
              ${current.discoveryMethod}, '', ${current.depth}, ${current.publisher ?? current.domain}
            )
          `;
        } catch {
          /* ignore */
        }
      }
    }

    // 5. Finalize Job
    const nextRun = new Date(Date.now() + config.frequencyMinutes * 60 * 1000).toISOString();
    const completedJobUpdates = {
      status: "completed" as const,
      completedAt: new Date().toISOString(),
      discoveredCount,
      evaluatedCount,
      qualifiedCount,
      ingestedCount,
      duplicateCount,
      failedCount,
      rejectedCount,
      skippedCount,
      newSourcesCount,
      pdfGeneratedCount,
      currentStage: "indexed" as CrawlPipelineStage,
    };

    console.log(
      `[crawler] COMPLETED job ${jobId}: discovered=${discoveredCount}, evaluated=${evaluatedCount}, qualified=${qualifiedCount}, ingested=${ingestedCount}, duplicates=${duplicateCount}, rejected=${rejectedCount}, newSources=${newSourcesCount}`
    );

    if (isMongoConfigured()) {
      await mongoUpdateCrawlJob(jobId, completedJobUpdates);
      await mongoUpdateCrawlConfig({
        lastRunAt: new Date().toISOString(),
        nextRunAt: nextRun,
      });
    }

    try {
      await sql`
        update crawl_jobs
        set status = 'completed', completed_at = now(),
            discovered_count = ${discoveredCount}, qualified_count = ${qualifiedCount},
            ingested_count = ${ingestedCount}, duplicate_count = ${duplicateCount},
            failed_count = ${failedCount}, rejected_count = ${rejectedCount},
            skipped_count = ${skippedCount}
        where id = ${jobId}
      `;

      await sql`
        update crawl_config
        set last_run_at = now(), next_run_at = ${nextRun}
        where id = ${config.id}
      `;
    } catch {
      /* ignore sql fallback error */
    }
  } catch (jobErr) {
    const errMsg = jobErr instanceof Error ? jobErr.message : "Crawl job error";
    console.error(`[crawler] job ${jobId} failed:`, jobErr);
    jobFailed = true;
    jobErrorSummary = errMsg;
    if (isMongoConfigured()) {
      await mongoUpdateCrawlJob(jobId, {
        status: "failed",
        completedAt: new Date().toISOString(),
        errorSummary: errMsg,
      });
    }
    try {
      await sql`
        update crawl_jobs
        set status = 'failed', completed_at = now(), error_summary = ${errMsg}
        where id = ${jobId}
      `;
    } catch {
      /* ignore */
    }
  } finally {
    activeJobs.delete(jobId);
  }

  return {
    id: jobId,
    status: jobFailed ? "failed" : "completed",
    triggerType,
    startedAt: initialJob.startedAt,
    completedAt: new Date().toISOString(),
    sourceCount: sources.length,
    discoveredCount,
    evaluatedCount,
    qualifiedCount,
    ingestedCount,
    duplicateCount,
    failedCount,
    rejectedCount,
    updatedCount: 0,
    skippedCount,
    newSourcesCount,
    pdfGeneratedCount,
    errorSummary: jobErrorSummary,
  };
}

export async function createAndRunCrawlJob(
  trigger: CrawlTrigger = "MANUAL",
  targetedQuery?: string,
): Promise<CrawlJob> {
  const sql = await getSql();
  const id = newId("job");
  const startedAt = new Date().toISOString();

  const initialJob: CrawlJob = {
    id,
    status: "running",
    triggerType: trigger,
    startedAt,
    completedAt: null,
    sourceCount: 0,
    discoveredCount: 0,
    evaluatedCount: 0,
    qualifiedCount: 0,
    ingestedCount: 0,
    duplicateCount: 0,
    failedCount: 0,
    rejectedCount: 0,
    updatedCount: 0,
    skippedCount: 0,
    newSourcesCount: 0,
    pdfGeneratedCount: 0,
    errorSummary: "",
    currentStage: "discovered",
  };

  if (isMongoConfigured()) {
    try {
      await mongoInsertCrawlJob(initialJob);
    } catch (err) {
      console.warn("[mongodb] createAndRunCrawlJob initial insert:", err);
    }
  }

  try {
    await sql`
      insert into crawl_jobs (id, status, trigger_type, started_at)
      values (${id}, 'running', ${trigger}, now())
    `;
  } catch {
    /* ignore sql fallback error */
  }

  // Start asynchronous crawl in background so the UI immediately shows "Running" status
  void executeCrawlJob(id, trigger, targetedQuery).catch((err) => {
    console.error(`[crawler] job ${id} error:`, err);
  });

  return initialJob;
}

export async function cancelJob(jobId: string): Promise<boolean> {
  const job = activeJobs.get(jobId);
  if (job) {
    job.cancel = true;
    if (isMongoConfigured()) {
      await mongoUpdateCrawlJob(jobId, { status: "cancelled", completedAt: new Date().toISOString() });
    }
    return true;
  }
  if (isMongoConfigured()) {
    await mongoUpdateCrawlJob(jobId, { status: "cancelled", completedAt: new Date().toISOString() });
  }
  const sql = await getSql();
  await sql`update crawl_jobs set status = 'cancelled', completed_at = now() where id = ${jobId} and status = 'running'`;
  return true;
}
