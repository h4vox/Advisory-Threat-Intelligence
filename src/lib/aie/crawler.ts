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
  extractHtmlMetadata,
  MAX_BYTES,
  scoreQuality,
  sha256Hex,
  toIsoString,
} from "./extract";
import { parseRssOrAtomXml } from "./feeds";
import { buildPristineDocumentHtml, extractTextFromPdfBuffer } from "./pdf";
import { safeFetchResource, validateSafePublicUrl } from "./security";
import { discoverAgentSources, evaluateResourceWithAgent, type AgentEvaluationResult } from "./agy-agent";
import { runUnifiedSourceDiscovery, runUnifiedResourceEvaluation, runUnifiedDomainResourceDiscovery } from "./ai-manager";
import { isCandidateResourceUrl, matchesCrawlPattern, qualifyContent } from "./qualification";
import type {
  CrawlConfig,
  CrawlJob,
  CrawlJobItem,
  CrawlPipelineStage,
  CrawlTrigger,
  DiscoveredResource,
  SourceRecord,
} from "./types";
import { getSql, type Sql } from "@/lib/db";
import { logger } from "./logger";
import { getThreatIntelCollection, isMongoConfigured } from "../mongodb/client.server";
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
  mongoListDiscoveredSources,
  mongoCreateDiscoveredSource,
  mongoSeedSources,
  mongoUpdateCrawlConfig,
  mongoUpdateCrawlJob,
  mongoUpdateSourceLastIngest,
  mongoUpsertDiscoveredResource,
  ensureMongoIndexes,
  invalidateCrawlerStateCache,
  registerJobActiveChecker,
  registerScheduleChecker,
} from "../mongodb/repository.server";
import { SOURCE_SEED } from "./catalog";

function newId(prefix: string) {
  return `${prefix}_${crypto.randomUUID().replace(/-/g, "").slice(0, 16)}`;
}

// Active job cancellation tokens
const activeJobs = new Map<string, { cancel: boolean; pause: boolean }>();

// Register memory state tracker with repository watchdog
registerJobActiveChecker((jobId: string) => activeJobs.has(jobId));

export function isJobActiveInMemory(jobId: string): boolean {
  return activeJobs.has(jobId);
}

interface FrontierItem {
  url: string;
  canonicalUrl: string;
  depth: number;
  priorityScore: number;
  parentUrl: string | null;
  parentSource: string | null;
  discoveryPath: string[];
  discoveryMethod: "seed_source" | "rss_feed" | "outlink_citation" | "pdf_reference" | "repo_reference" | "search_expansion" | "agent_discovery";
  sourceId?: string;
  sourceSlug?: string;
  publisher?: string;
  author?: string;
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
  const rows = await sql<CrawlConfig>`select * from crawl_config limit 1`;
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
    concurrency: 4,
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
  const isMongo = isMongoConfigured();
  const config = isMongo ? await mongoGetCrawlConfig() : await getOrCreateCrawlConfig();

  const jobControl = { cancel: false, pause: false };
  activeJobs.set(jobId, jobControl);

  const breadth = config.discoveryBreadth || "balanced";
  let maxDepth = config.maxDepth || 3;
  if (breadth === "focused") maxDepth = 1;
  else if (breadth === "wide") maxDepth = Math.max(maxDepth, 4);

  const configuredMax = config.maxResourcesPerJob || config.maxResourcesPerRun || 60;
  const maxTotalResources = targetedQuery
    ? Math.min(Math.max(configuredMax, 15), 100)
    : breadth === "wide"
      ? Math.min(Math.max(configuredMax, 30), 300)
      : Math.min(Math.max(configuredMax, 20), 150);
  const maxPerDomain = breadth === "wide" ? Math.max(config.maxResourcesPerDomain || 8, 8) : config.maxResourcesPerDomain || 6;
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

  if (isMongo) {
    try {
      await mongoInsertCrawlJob(initialJob);
    } catch (err) {
      console.warn("[mongodb] insert crawl job:", err);
    }
  } else {
    try {
      const sql = await getSql();
      await sql`
        update crawl_jobs
        set status = 'running', started_at = now()
        where id = ${jobId}
      `;
    } catch {
      /* ignore sql fallback error */
    }
  }

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
  let sql: Sql | null = null;

  try {
    try {
      sql = await getSql();
    } catch {
      /* ignore sql init fallback */
    }
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
            crawlPattern: s.crawlPattern || seed?.crawlPattern,
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

    // Buffer for items discovered during initial source discovery before queue initialization
    const preHarvestedItems: FrontierItem[] = [];

    // Autonomous AI Agent Source Discovery (Adversary Emulation Intelligence Skill)
    if (isMongoConfigured() && config.agentDiscoveryEnabled !== false) {
      try {
        logger.agent(
          "DISCOVERY",
          "Launching autonomous CTI source discovery (Adversary Emulation Intelligence Skill)...",
          { model: config.agentModel || "gemini-3.8-flash-low", timeout: `${config.agentTimeoutSeconds || 45}s` }
        );
        console.log(`[crawler] [AI AGENT] Running autonomous CTI source discovery (Adversary Emulation Intelligence Skill)...`);

        // Build known domain list to prevent duplicate discovery
        const knownDomains: string[] = [];
        for (const s of sources) {
          try {
            const h = new URL(s.homepageUrl).hostname.replace(/^www\./, "").toLowerCase();
            if (h) knownDomains.push(h);
          } catch {}
        }
        try {
          const existingDiscovered = await mongoListDiscoveredSources();
          for (const ds of existingDiscovered) {
            if (ds.domain) knownDomains.push(ds.domain.toLowerCase());
          }
        } catch {}

        const agentResult = await runUnifiedSourceDiscovery({
          limit: 4,
          existingDomains: Array.from(new Set(knownDomains)),
          model: config.agentModel || "AGY: gemini-3.8-flash-low",
          timeoutSeconds: config.agentTimeoutSeconds || 45,
        });

        if (agentResult.sources && agentResult.sources.length > 0) {
          logger.agent(
            "DISCOVERED",
            `Discovered ${agentResult.sources.length} new high-value CTI research endpoints!`,
            agentResult.sources.map((s) => s.domain).join(", ")
          );
          console.log(`[crawler] [AI AGENT] Discovered ${agentResult.sources.length} new high-value CTI sources!`);
          for (const s of agentResult.sources) {
            try {
              const created = await mongoCreateDiscoveredSource({
                domain: s.domain,
                name: s.source_name,
                homepageUrl: s.base_url || `https://${s.domain}`,
                crawlPattern: s.crawl_pattern,
                parentSource: "AGY Autonomous Discovery",
                trustScore: 80,
                origin: "agent_discovery",
                notes: s.why_crawl,
                whyCrawl: s.why_crawl,
                status: "discovered",
                enabled: true,
              });
              if (created) {
                newSourcesCount++;
                logger.agent("REGISTER", `Registered new source endpoint: ${s.source_name}`, s.base_url || s.domain);
                console.log(`[crawler] [AI AGENT] Registered new source endpoint: ${s.source_name} (${s.base_url || s.domain})`);

                // Coordinated Domain Harvesting: Extract all technical report permalinks for this newly discovered domain in one pass!
                try {
                  const domainHarvest = await runUnifiedDomainResourceDiscovery({
                    domain: s.domain,
                    baseUrl: s.base_url || `https://${s.domain}`,
                    model: config.agentModel,
                    timeoutSeconds: Math.min(config.agentTimeoutSeconds || 45, 30),
                  });
                  if (domainHarvest.resources && domainHarvest.resources.length > 0) {
                    logger.agent("HARVEST", `Extracted ${domainHarvest.resources.length} coordinated resources from newly discovered domain ${s.domain}`);
                    for (const dr of domainHarvest.resources) {
                      try {
                        const canonical = canonicalizeUrl(dr.url);
                        preHarvestedItems.push({
                          url: dr.url,
                          canonicalUrl: canonical,
                          depth: 0,
                          priorityScore: dr.isHighValue ? 0.98 : 0.90,
                          parentUrl: s.base_url || `https://${s.domain}`,
                          parentSource: s.source_name,
                          discoveryPath: [s.base_url || `https://${s.domain}`, dr.url],
                          discoveryMethod: "agent_discovery",
                          sourceId: created.id || s.domain,
                          sourceSlug: s.domain.replace(/[^a-z0-9]/gi, "-").toLowerCase(),
                          publisher: s.source_name,
                          domain: s.domain,
                          title: dr.title,
                        });
                      } catch {
                        /* skip */
                      }
                    }
                  }
                } catch (harvestErr) {
                  console.warn(`[crawler][agent] Domain harvest error for ${s.domain}:`, (harvestErr as Error).message);
                }
              }
            } catch (err) {
              logger.warn("AI AGENT", `Error saving discovered source ${s.domain}: ${(err as Error).message}`);
            }
          }
        } else if (agentResult.error) {
          logger.agent("NOTE", `Discovery note: ${agentResult.error} — proceeding with core crawler sources.`);
          console.log(`[crawler] [AI AGENT] Discovery note: ${agentResult.error} — proceeding with core crawler sources.`);
        } else {
          logger.agent(
            "COMPLETED",
            `Source discovery run finished — candidate domains (${agentResult.candidateDomains?.join(", ") || "none"}) already present in registry. Proceeding with crawl.`
          );
        }
      } catch (agentErr) {
        logger.agent("FAILSAFE", `Autonomous discovery skipped (offline / timed out) — proceeding with core crawler: ${(agentErr as Error).message}`);
        console.warn(`[crawler] [AI AGENT] Autonomous discovery skipped (offline / timed out) — proceeding with core crawler:`, (agentErr as Error).message);
      }
    }

    // Merge enabled Discovered Sources if enabled in crawl config
    if (isMongoConfigured() && config.agentCrawlSourcesEnabled !== false) {
      try {
        const discoveredSourcesList = await mongoListDiscoveredSources();
        for (const ds of discoveredSourcesList) {
          if (ds.enabled !== false && ds.status !== "rejected" && ds.status !== "ignored") {
            const domain = ds.domain;
            const slug = domain.replace(/[^a-z0-9]/gi, "-").toLowerCase();
            const rootUrl = ds.crawlPattern ? ds.crawlPattern.replace(/\/\*$/, "") : ds.homepageUrl || `https://${domain}`;
            sources.push({
              id: ds.id,
              name: ds.name || domain,
              slug,
              category: "discovered_source",
              homepageUrl: rootUrl.startsWith("http") ? rootUrl : `https://${rootUrl}`,
              crawlPattern: ds.crawlPattern,
              feedUrl: undefined,
              researchArchives: ds.crawlPattern ? [ds.crawlPattern.replace(/\/\*$/, "")] : undefined,
              enabled: true,
              priority: ds.trustScore ? Math.round(ds.trustScore / 10) : 6,
              trustLevel: ds.trustScore >= 70 ? "reputable" : "community",
              notes: ds.notes || ds.whyCrawl || "",
              lastIngestAt: null,
              isCurated: false,
              isDiscovered: true,
              origin: ds.origin === "agent_discovery" ? "agent_discovery" : "crawler_outlink",
            });
          }
        }
      } catch (err) {
        console.warn("[crawler] Error merging discovered sources into crawl job:", err);
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
      if (sql) await sql`update crawl_jobs set source_count = ${sources.length} where id = ${jobId}`;
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
          if (r.canonicalUrl && (r.wordCount === undefined || r.wordCount >= 500)) {
            storedCanonicalUrls.add(r.canonicalUrl);
          }
          if (r.textHash && (r.wordCount === undefined || r.wordCount >= 500)) {
            storedHashes.add(r.textHash);
          }
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
      if (sql) {
        const sqlExisting = await sql<{ canonical_url: string; text_hash: string }>`
          select canonical_url, text_hash from reports
        `;
        for (const r of sqlExisting) {
          if (r.canonical_url) storedCanonicalUrls.add(r.canonical_url);
          if (r.text_hash) storedHashes.add(r.text_hash);
        }
      }
    } catch {
      /* ignore sql fallback */
    }

    // 3. Initialize the Priority Frontier Queue & Scoped Endpoint Pattern Map
    const frontierQueue: FrontierItem[] = [];
    const enqueuedUrls = new Set<string>();
    const domainVisitCounts = new Map<string, number>();

    // Index all active crawl patterns by sourceId and domain
    const sourcePatternMap = new Map<string, string>();
    for (const s of sources) {
      if (s.crawlPattern) {
        sourcePatternMap.set(s.id, s.crawlPattern);
        try {
          const host = new URL(s.homepageUrl).hostname.toLowerCase().replace(/^www\./, "");
          sourcePatternMap.set(host, s.crawlPattern);
        } catch {}
      }
    }

    const enqueue = (item: FrontierItem) => {
      if (enqueuedUrls.has(item.canonicalUrl)) return;
      if (!validateSafePublicUrl(item.canonicalUrl).safe) return;

      // Strict Scoped Research Endpoint Guard:
      // If the resource belongs to a source with a defined crawlPattern, enforce strict path scoping.
      // This eliminates false data, marketing homepages, corporate sales, careers, and pricing pages.
      const itemDomain = item.domain.toLowerCase().replace(/^www\./, "");
      const pattern = (item.sourceId ? sourcePatternMap.get(item.sourceId) : undefined) || sourcePatternMap.get(itemDomain);
      if (pattern && !matchesCrawlPattern(item.canonicalUrl, pattern)) {
        return;
      }

      enqueuedUrls.add(item.canonicalUrl);
      frontierQueue.push(item);
      discoveredCount++;
    };

    // Enqueue any items extracted during early autonomous source discovery
    for (const phi of preHarvestedItems) {
      enqueue(phi);
    }

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

              // Coordinated Domain Harvesting: Extract all technical report permalinks for this seed source domain
              if (config.agentDiscoveryEnabled !== false && html) {
                try {
                  const sHost = new URL(source.homepageUrl).hostname.replace(/^www\./, "").toLowerCase();
                  const domainHarvest = await runUnifiedDomainResourceDiscovery({
                    domain: sHost,
                    baseUrl: source.homepageUrl,
                    htmlSnippet: html.slice(0, 4500),
                    model: config.agentModel,
                    timeoutSeconds: Math.min(config.agentTimeoutSeconds || 45, 25),
                  });
                  if (domainHarvest.resources && domainHarvest.resources.length > 0) {
                    for (const dr of domainHarvest.resources) {
                      try {
                        const canonical = canonicalizeUrl(dr.url);
                        enqueue({
                          url: dr.url,
                          canonicalUrl: canonical,
                          depth: 0,
                          priorityScore: dr.isHighValue ? 0.96 : 0.88,
                          parentUrl: source.homepageUrl,
                          parentSource: source.name,
                          discoveryPath: [source.homepageUrl, dr.url],
                          discoveryMethod: "agent_discovery",
                          sourceId: source.id,
                          sourceSlug: source.slug,
                          publisher: source.name,
                          domain: new URL(canonical).hostname.replace(/^www\./, ""),
                          title: dr.title,
                        });
                      } catch {
                        /* skip */
                      }
                    }
                  }
                } catch {
                  /* ignore agent harvest error */
                }
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

    const jobStartTime = Date.now();
    const maxRunTimeMinutes = config.maxRunTimeMinutes && config.maxRunTimeMinutes > 0 ? config.maxRunTimeMinutes : 5;
    const MAX_JOB_EXECUTION_TIME_MS = maxRunTimeMinutes * 60 * 1000;

    // 4. ADAPTIVE CONCURRENT WORKER POOL & HOST-AWARE DISPATCHER
    // Distributes extraction across multiple target domains concurrently while respecting polite per-host spacing
    const maxConcurrency = Math.min(Math.max(config.concurrency || 4, 1), 8);
    const activeWorkerTasks = new Set<Promise<void>>();
    const activeDomains = new Set<string>();
    const domainLastAccessTimes = new Map<string, number>();
    const currentlyProcessingUrls = new Set<string>();
    let lastReportedProgressTime = 0;

    async function reportLiveProgress(force = false) {
      const now = Date.now();
      if (!force && now - lastReportedProgressTime < 1000) return;
      lastReportedProgressTime = now;

      const elapsedSec = Math.max((now - jobStartTime) / 1000, 1);
      const throughputDocsPerSec = Number((evaluatedCount / elapsedSec).toFixed(2));
      const activeUrlList = Array.from(currentlyProcessingUrls);

      if (isMongoConfigured()) {
        try {
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
            currentUrl: activeUrlList[0] || (activeDomains.size > 0 ? `Spidertree across ${activeDomains.size} hosts` : "Exploring frontier..."),
            currentStage: "evaluated",
            activeWorkers: activeWorkerTasks.size,
            activeDomains: Array.from(activeDomains),
            throughputDocsPerSec,
          });
        } catch {
          /* non-critical telemetry update error */
        }
      }
    }

    function pickNextItem(): FrontierItem | null {
      if (frontierQueue.length === 0) return null;
      frontierQueue.sort((a, b) => b.priorityScore - a.priorityScore);

      for (let i = 0; i < frontierQueue.length; i++) {
        const item = frontierQueue[i];
        const currentDomainCount = domainVisitCounts.get(item.domain) || 0;
        if (currentDomainCount >= maxPerDomain && item.depth > 0 && item.discoveryMethod === "seed_source") {
          frontierQueue.splice(i, 1);
          i--;
          continue;
        }
        if (!activeDomains.has(item.domain)) {
          frontierQueue.splice(i, 1);
          return item;
        }
      }

      // If all items belong to busy domains, pop only if no workers are active
      if (activeWorkerTasks.size === 0 && frontierQueue.length > 0) {
        return frontierQueue.shift()!;
      }
      return null;
    }

    async function processFrontierItem(current: FrontierItem): Promise<void> {
      currentlyProcessingUrls.add(current.url);
      activeDomains.add(current.domain);

      try {
        const currentDomainCount = domainVisitCounts.get(current.domain) || 0;
        if (currentDomainCount >= maxPerDomain && current.depth > 0 && current.discoveryMethod === "seed_source") {
          return;
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
          if (sql) {
            try {
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
            } catch {
              /* ignore sql fallback error */
            }
          }

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

          return;
        }

        // 4.2 Content Acquisition & Evaluation Increment
        evaluatedCount++;
        domainVisitCounts.set(current.domain, currentDomainCount + 1);
        void reportLiveProgress();

        let textContent = current.preloadedText || "";
        let docTitle = current.title || "Threat Intelligence Report";
        let contentType = "text/html";
        let rawBytes: Uint8Array | string = current.preloadedText || "";
        let fetchedHtmlBody = "";

        const currentWordCount = textContent.split(/\s+/).filter(Boolean).length;
        const needsFullArticleFetch = currentWordCount < 300;

        if (needsFullArticleFetch) {
          try {
            // Polite per-domain rate limit delay (only pauses requests to the SAME domain, allowing other domains to run concurrently!)
            const lastDomainHit = domainLastAccessTimes.get(current.domain) || 0;
            const timeSinceDomainHit = Date.now() - lastDomainHit;
            const politeDelay = Math.min(config.rateLimitMs ?? 150, 300);
            if (timeSinceDomainHit < politeDelay) {
              await new Promise((r) => setTimeout(r, politeDelay - timeSinceDomainHit));
            }
            domainLastAccessTimes.set(current.domain, Date.now());

            const fetched = await safeFetchResource(current.canonicalUrl, {
              timeoutMs: 4500,
              userAgent:
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36 (compatible; AIE-Threat-Crawler/3.0)",
              acceptHeader: "text/html,application/xhtml+xml,application/pdf,text/plain;q=0.9,*/*;q=0.8",
            });

            rawBytes = fetched.bytes;
            contentType = fetched.contentType;

            if (contentType.includes("pdf")) {
              try {
                const pdfResult = await extractTextFromPdfBuffer(Buffer.from(fetched.bytes));
                if (pdfResult.text && pdfResult.text.length > 50) {
                  textContent = pdfResult.text;
                  if (pdfResult.title && pdfResult.title !== "Untitled report") {
                    docTitle = pdfResult.title;
                  }
                  if (pdfResult.author) {
                    current.author = pdfResult.author;
                  }
                  console.log(`[crawler] PDF extracted: ${textContent.length} chars from ${current.canonicalUrl}`);
                } else {
                  textContent = `PDF Document Evidence: ${current.title || current.canonicalUrl}. Raw cryptographic evidence and technical content preserved.`;
                }
              } catch (pdfErr) {
                console.warn("[crawler] PDF extraction failed, using placeholder:", pdfErr);
                textContent = `PDF Document Evidence: ${current.title || current.canonicalUrl}. Raw cryptographic evidence and technical content preserved.`;
              }
            } else {
              const body = fetched.body;
              fetchedHtmlBody = body;
              const extracted = htmlToText(body);
              if (extracted.text && extracted.text.length > textContent.length) {
                textContent = extracted.text;
              }
              if (extracted.title && extracted.title !== "Untitled report") {
                docTitle = extracted.title;
              }

              const htmlMeta = extractHtmlMetadata(body);
              if (htmlMeta.author && (!current.author || current.author === current.domain)) {
                current.author = htmlMeta.author;
              }
              if (htmlMeta.publisher && (!current.publisher || current.publisher === current.domain)) {
                current.publisher = htmlMeta.publisher;
              }
              if (current.domain === "cloud.google.com" || current.sourceId === "src_mandiant") {
                current.publisher = "Google Threat Intelligence Group";
                current.author = htmlMeta.author || "Google Threat Intelligence Group";
              }
            }
          } catch (fetchErr) {
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
              return;
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
          return;
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
            return;
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
              return;
            }
          }
        }

        // Check maxPdfDownloads limit
        const isPdf = contentType.includes("pdf") || /\.pdf$/i.test(current.canonicalUrl);
        if (isPdf && pdfGeneratedCount >= (config.maxPdfDownloads || 10)) {
          skippedCount++;
          return;
        }

        // 4.3 Recursive Citation & Graph Outlink Exploration
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

        // 4.4 Heuristic Qualification Baseline & 5-Dimensional AI Agent Validation
        const isFeedEntry = current.discoveryMethod === "rss_feed";
        const qual = qualifyContent(textContent, docTitle, current.canonicalUrl, config, isFeedEntry);

        let agentResult: AgentEvaluationResult | null = null;

        const shouldRunAgent =
          (config.agentTaggingEnabled || config.agentApprovalEnabled) &&
          !qual.isIndexOrGeneric &&
          textContent.trim().length > 60;

        if (shouldRunAgent) {
          try {
            agentResult = await runUnifiedResourceEvaluation({
              text: textContent,
              title: docTitle,
              url: current.canonicalUrl,
              domain: current.domain,
              timeoutSeconds: config.agentTimeoutSeconds || 45,
              model: config.agentModel || "AGY: gemini-3.8-flash-low",
            });

            if (agentResult.success && !agentResult.fallback) {
              logger.agent(
                "EVALUATE:5D_DONE",
                `"${docTitle.slice(0, 50)}" → score=${agentResult.passScore}, approved=${agentResult.recommendApproval}, class=${agentResult.classification}`,
                {
                  breakdown: agentResult.scoreBreakdown,
                  actors: agentResult.threatActors?.length || 0,
                  malware: agentResult.malwareFamilies?.length || 0,
                  tech: agentResult.mitreTechniques?.length || 0,
                }
              );
              console.log(
                `[crawler][agent] 5D Evaluated "${docTitle.slice(0, 60)}" → score=${agentResult.passScore}, approved=${agentResult.recommendApproval}, class=${agentResult.classification}`,
              );

              if (agentResult.passScore >= 50 || agentResult.recommendApproval) {
                qual.qualified = true;
                qual.classification = agentResult.classification;
                qual.resourceKind = agentResult.resourceKind;
                qual.score = Math.max(qual.score, agentResult.passScore / 100);
                if (agentResult.scoreBreakdown) {
                  qual.simulationScore = Math.max(
                    qual.simulationScore,
                    agentResult.scoreBreakdown.emulationUtility / 20,
                  );
                }
              } else {
                qual.qualified = false;
                qual.rejectionReason = agentResult.rationale || `Rejected by AI Agent: 5D score (${agentResult.passScore}/100) below threshold`;
              }
            } else if (agentResult.error) {
              logger.agent("FALLBACK", `Agent fallback for "${docTitle.slice(0, 40)}": ${agentResult.error} — adhering to heuristic verdict (${qual.qualified})`);
            }
          } catch (agentErr) {
            logger.agent("FAILSAFE", `evaluateResourceWithAgent non-blocking fallback: ${(agentErr as Error).message}`);
            agentResult = null;
          }
        }

        if (!qual.qualified) {
          rejectedCount++;
          const itemId = newId("itm");
          const rejectMsg = qual.rejectionReason || "Below qualification threshold";
          logger.qualification(current.canonicalUrl, "REJECT", qual.score, rejectMsg);

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
            agentScore: agentResult?.passScore,
            agentApproved: agentResult?.recommendApproval,
            agentRationale: agentResult?.rationale,
            agentTags: agentResult?.mitreTechniques,
            agentClassification: agentResult?.classification,
            agentResourceKind: agentResult?.resourceKind,
            scoreBreakdown: agentResult?.scoreBreakdown,
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
              agentScore: agentResult?.passScore,
              agentApproved: agentResult?.recommendApproval,
              agentRationale: agentResult?.rationale,
              agentTags: agentResult?.mitreTechniques,
              agentClassification: agentResult?.classification,
              agentResourceKind: agentResult?.resourceKind,
              scoreBreakdown: agentResult?.scoreBreakdown,
            });
          }

          if (sql) {
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
          }
          return;
        }

        qualifiedCount++;
        logger.qualification(
          current.canonicalUrl,
          "PASS",
          qual.score,
          `Classification: ${qual.classification}, Resource: ${qual.resourceKind}`,
        );

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
          const isPdfResource = contentType.includes("pdf") || current.canonicalUrl.toLowerCase().endsWith(".pdf");
          pristineHtml = buildPristineDocumentHtml(isPdfResource ? textContent : (fetchedHtmlBody || textContent), {
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
        const shouldAutoIngest =
          Boolean(config.autoIngest) ||
          Boolean(config.agentAutoIngestEnabled && agentResult?.recommendApproval && (agentResult.passScore ?? 0) >= 65);

        if (shouldAutoIngest) {
          ingestedCount++;
          storedCanonicalUrls.add(current.canonicalUrl);
          storedHashes.add(textHash);
          logger.ingest(
            "ACQUIRED",
            docTitle,
            `Classification: ${qual.resourceKind}, Score: ${score.toFixed(2)}, Words: ${wordCount}, IOCs: ${iocs.length}, TTPs: ${intelAnalysis?.attackChain?.length ?? 0}`,
          );

          if (isMongoConfigured()) {
            try {
              const isGoogle = current.domain === "cloud.google.com" || current.sourceId === "src_mandiant";
              const effectivePublisher = current.publisher || (isGoogle ? "Google Threat Intelligence Group" : current.domain);
              const effectiveAuthor = current.author || effectivePublisher;
              const effectiveSourceName = isGoogle ? "Google Threat Intelligence" : current.publisher || current.domain;
              const effectiveSourceId = current.sourceId || (isGoogle ? "src_mandiant" : "src_expanded");

              const isAiVerified = Boolean(agentResult?.recommendApproval && (agentResult.passScore ?? 0) >= 50);
              const aiScore = agentResult?.passScore ? agentResult.passScore : Math.round(score * 100);
              const aiReason = agentResult?.rationale || "Verified by CTI Heuristic Qualification Gate";

              if (agentResult) {
                if (agentResult.threatActors?.length) {
                  intelAnalysis = intelAnalysis || {
                    method: "llm" as const,
                    classification: qual.classification || "General Threat Intel",
                    threatActors: [],
                    malware: [],
                    vulnerabilities: [],
                    ttps: [],
                    ioas: [],
                    attackChain: [],
                    detections: [],
                    hunting: [],
                    emulation: [],
                  };
                  const mergedActors = new Set([...(intelAnalysis.threatActors || []), ...agentResult.threatActors]);
                  intelAnalysis.threatActors = Array.from(mergedActors);
                }
                if (agentResult.mitreTechniques?.length) {
                  extractedEntities = extractedEntities || {
                    threatActors: [],
                    malwareFamilies: [],
                    cves: [],
                    tactics: [],
                    techniques: [],
                    procedures: [],
                    detectionRules: [],
                    mitigations: [],
                    campaign: null,
                  };
                  const existingIds = new Set((extractedEntities.techniques || []).map((t) => t.id));
                  for (const techId of agentResult.mitreTechniques) {
                    if (!existingIds.has(techId)) {
                      extractedEntities.techniques.push({
                        id: techId,
                        name: techId,
                        tactic: "Execution",
                      });
                      existingIds.add(techId);
                    }
                  }
                }
              }

              await mongoInsertReport({
                id: reportId,
                sourceId: effectiveSourceId,
                sourceName: effectiveSourceName,
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
                publisher: effectivePublisher,
                author: effectiveAuthor,
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
                aiVerified: isAiVerified,
                aiQualityScore: aiScore,
                aiAuditReason: aiReason,
                scoreBreakdown: agentResult?.scoreBreakdown,
              });

              storedSimhashes.push({
                id: reportId,
                simhash: computeSimHash64(`${docTitle} ${textContent.slice(0, 3000)}`),
                title: docTitle,
              });

              if (current.sourceId) {
                await mongoUpdateSourceLastIngest(current.sourceId);
              }

              await mongoUpsertDiscoveredResource({
                id: newId("dsc"),
                canonicalUrl: current.canonicalUrl,
                url: current.url,
                sourceId: current.sourceId || null,
                title: docTitle,
                publisher: effectivePublisher,
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
                discoveryPath: current.discoveryPath,
                reportId,
                agentScore: agentResult?.passScore,
                agentApproved: agentResult?.recommendApproval,
                agentRationale: agentResult?.rationale,
                agentTags: agentResult?.mitreTechniques,
                agentClassification: agentResult?.classification,
                agentResourceKind: agentResult?.resourceKind,
                scoreBreakdown: agentResult?.scoreBreakdown,
              });
            } catch (mongoErr) {
              console.warn("[mongodb] report persistence error:", mongoErr);
            }
          }

          if (sql) {
            try {
              const isGoogle = current.domain === "cloud.google.com" || current.sourceId === "src_mandiant";
              const effectivePublisher = current.publisher || (isGoogle ? "Google Threat Intelligence Group" : current.domain);
              const effectiveAuthor = current.author || effectivePublisher;
              const effectiveSourceId = current.sourceId || (isGoogle ? "src_mandiant" : "src_dfir");

              await sql`
                insert into reports (
                  id, source_id, title, url, canonical_url, published_at, content_type,
                  status, raw_hash, text_hash, quality_score, quality_reasons, word_count,
                  extracted_text, iocs_json, ingest_origin, publisher, author,
                  classification, discovery_method, discovery_query, parent_source,
                  source_domain, version, analysis_json, raw_html
                ) values (
                  ${reportId}, ${effectiveSourceId}, ${docTitle}, ${current.url}, ${current.canonicalUrl},
                  ${new Date().toISOString().slice(0, 10)}, ${contentType}, 'acquired',
                  ${rawHash}, ${textHash}, ${score}, ${JSON.stringify(reasons)}, ${wordCount},
                  ${textContent}, ${JSON.stringify(iocs)}, ${current.depth > 0 ? 'citation_expansion' : 'crawl'},
                  ${effectivePublisher}, ${effectiveAuthor},
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
            ...(agentResult && agentResult.success && !agentResult.fallback
              ? {
                  agentScore: agentResult.passScore,
                  agentApproved: agentResult.recommendApproval,
                  agentRationale: agentResult.rationale,
                  agentClassification: agentResult.classification,
                  agentResourceKind: agentResult.resourceKind,
                  scoreBreakdown: agentResult.scoreBreakdown,
                  agentTags: [
                    ...(agentResult.threatActors || []).map((a) => `actor:${a}`),
                    ...(agentResult.malwareFamilies || []).map((m) => `malware:${m}`),
                    ...(agentResult.cves || []).map((c) => `cve:${c}`),
                    ...(agentResult.mitreTechniques || []).map((t) => `technique:${t}`),
                  ],
                }
              : {}),
          };

          if (isMongoConfigured()) {
            await mongoInsertCrawlJobItem(jobItem);
          }
          if (sql) {
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
          }
        } else {
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
            ...(agentResult && agentResult.success && !agentResult.fallback
              ? {
                  agentScore: agentResult.passScore,
                  agentApproved: agentResult.recommendApproval,
                  agentRationale: agentResult.rationale,
                  agentClassification: agentResult.classification,
                  agentResourceKind: agentResult.resourceKind,
                  agentTags: [
                    ...(agentResult.threatActors || []).map((a) => `actor:${a}`),
                    ...(agentResult.malwareFamilies || []).map((m) => `malware:${m}`),
                    ...(agentResult.cves || []).map((c) => `cve:${c}`),
                    ...(agentResult.mitreTechniques || []).map((t) => `technique:${t}`),
                  ],
                }
              : {}),
          };

          if (isMongoConfigured()) {
            try {
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
                ...(agentResult && agentResult.success && !agentResult.fallback
                  ? {
                      agentScore: agentResult.passScore,
                      agentApproved: agentResult.recommendApproval,
                      agentRationale: agentResult.rationale,
                      agentClassification: agentResult.classification,
                      agentResourceKind: agentResult.resourceKind,
                      scoreBreakdown: agentResult.scoreBreakdown,
                      agentTags: [
                        ...(agentResult.threatActors || []).map((a) => `actor:${a}`),
                        ...(agentResult.malwareFamilies || []).map((m) => `malware:${m}`),
                        ...(agentResult.cves || []).map((c) => `cve:${c}`),
                        ...(agentResult.mitreTechniques || []).map((t) => `technique:${t}`),
                      ],
                    }
                  : {}),
              });
            } catch (mongoErr) {
              console.warn("[mongodb] report persistence error:", mongoErr);
            }
          }

          if (sql) {
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
      } finally {
        currentlyProcessingUrls.delete(current.url);
        activeDomains.delete(current.domain);
        await reportLiveProgress();
      }
    }

    // Adaptive multi-worker concurrent dispatcher loop
    while ((frontierQueue.length > 0 || activeWorkerTasks.size > 0) && evaluatedCount < configuredMax) {
      if (Date.now() - jobStartTime > MAX_JOB_EXECUTION_TIME_MS) {
        console.warn(`[crawler] max execution time (${maxRunTimeMinutes} min) reached; terminating.`);
        break;
      }

      while (activeWorkerTasks.size < maxConcurrency && frontierQueue.length > 0 && evaluatedCount + activeWorkerTasks.size < configuredMax) {
        const nextItem = pickNextItem();
        if (!nextItem) break;

        const task = (async () => {
          try {
            await processFrontierItem(nextItem);
          } catch (err) {
            console.error(`[crawler] Error processing URL ${nextItem.url}:`, err);
          }
        })();

        activeWorkerTasks.add(task);
        task.finally(() => {
          activeWorkerTasks.delete(task);
        });
      }

      if (activeWorkerTasks.size === 0 && frontierQueue.length === 0) {
        break;
      }

      await Promise.race([
        ...Array.from(activeWorkerTasks),
        new Promise((resolve) => setTimeout(resolve, 50)),
      ]);

      await reportLiveProgress();
    }

    // Await any remaining active concurrent tasks
    if (activeWorkerTasks.size > 0) {
      await Promise.allSettled(Array.from(activeWorkerTasks));
    }
    await reportLiveProgress(true);

    // 5. Finalize Job
    const latestConfig = isMongoConfigured() ? await mongoGetCrawlConfig() : await getOrCreateCrawlConfig();
    const effectiveFreq = Math.max(5, latestConfig.frequencyMinutes || config.frequencyMinutes || 60);
    const nextRun = new Date(Date.now() + effectiveFreq * 60 * 1000).toISOString();
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
    } else {
      try {
        const sql = await getSql();
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
    if (sql) {
      try {
        await sql`
          update crawl_jobs
          set status = 'failed', completed_at = now(), error_summary = ${errMsg}
          where id = ${jobId}
        `;
      } catch {
        /* ignore */
      }
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
  } else {
    try {
      const sql = await getSql();
      await sql`
        insert into crawl_jobs (id, status, trigger_type, started_at)
        values (${id}, 'running', ${trigger}, now())
      `;
    } catch {
      /* ignore sql fallback error */
    }
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
  }
  activeJobs.delete(jobId);
  if (isMongoConfigured()) {
    await mongoUpdateCrawlJob(jobId, {
      status: "cancelled",
      completedAt: new Date().toISOString(),
      errorSummary: "Crawl job cancelled by operator",
      currentStage: "indexed",
    });
  }
  invalidateCrawlerStateCache();
  try {
    const sql = await getSql();
    await sql`update crawl_jobs set status = 'cancelled', completed_at = now() where id = ${jobId} and status = 'running'`;
  } catch {
    /* ignore sql fallback */
  }
  return true;
}

// ---------------------------------------------------------------------------
// Autonomous Background Scheduler & Concurrency Lock
// ---------------------------------------------------------------------------

export interface ScheduleCheckResult {
  triggered: boolean;
  reason: string;
  jobId?: string;
  nextRunAt?: string | null;
  lastRunAt?: string | null;
}

let isCheckingSchedule = false;

export async function checkAndTriggerScheduledCrawl(): Promise<ScheduleCheckResult> {
  // 1. In-memory guards: skip if check in progress or crawler job active
  if (isCheckingSchedule) {
    return { triggered: false, reason: "Schedule check already in progress" };
  }

  if (activeJobs.size > 0) {
    return { triggered: false, reason: "A crawl job is currently executing in server memory" };
  }

  isCheckingSchedule = true;
  try {
    if (!isMongoConfigured()) {
      return { triggered: false, reason: "MongoDB is not configured" };
    }

    const config = await mongoGetCrawlConfig();

    if (!config.enabled) {
      return {
        triggered: false,
        reason: "Master scheduler is disabled in configuration",
        nextRunAt: config.nextRunAt,
        lastRunAt: config.lastRunAt,
      };
    }

    if (config.paused) {
      return {
        triggered: false,
        reason: "Autonomous scheduler is paused in configuration",
        nextRunAt: config.nextRunAt,
        lastRunAt: config.lastRunAt,
      };
    }

    // 2. Atlas document lock & active job check
    const col = await getThreatIntelCollection();
    const runningJobs = await col
      .find({ docType: "crawl_job", status: "running" })
      .sort({ startedAt: -1 })
      .limit(5)
      .toArray();

    const maxRunMs = (config.maxRunTimeMinutes || 5) * 60 * 1000;
    const now = Date.now();

    let genuinelyActiveJobFound = false;
    for (const rj of runningJobs) {
      const startedMs = rj.startedAt ? new Date(rj.startedAt).getTime() : 0;
      const elapsedMs = now - startedMs;
      // Job is active if within runtime limit and (in active memory map OR started under 30s ago)
      if (elapsedMs < maxRunMs + 30_000 && (activeJobs.has(rj.id) || elapsedMs < 30_000)) {
        genuinelyActiveJobFound = true;
        break;
      }
    }

    if (genuinelyActiveJobFound) {
      return {
        triggered: false,
        reason: "A crawl job is currently actively executing in database",
        nextRunAt: config.nextRunAt,
        lastRunAt: config.lastRunAt,
      };
    }

    // 3. Cadence and due condition evaluation
    const freqMinutes = Math.max(5, config.frequencyMinutes || 60);
    const freqMs = freqMinutes * 60 * 1000;
    const nextRunMs = config.nextRunAt ? new Date(config.nextRunAt).getTime() : 0;
    const lastRunMs = config.lastRunAt ? new Date(config.lastRunAt).getTime() : 0;

    const isDueByNextRun = nextRunMs > 0 && now >= nextRunMs;
    const isDueByFrequency = !config.nextRunAt && (!config.lastRunAt || now - lastRunMs >= freqMs);
    const isOverdue = lastRunMs > 0 && now - lastRunMs >= freqMs && (nextRunMs === 0 || nextRunMs <= now);

    const isDue = isDueByNextRun || isDueByFrequency || isOverdue;

    if (!isDue) {
      const targetTime = nextRunMs > 0 ? nextRunMs : (lastRunMs > 0 ? lastRunMs + freqMs : now);
      const remainingMs = Math.max(0, targetTime - now);
      const remainingMins = Math.ceil(remainingMs / 60_000);
      return {
        triggered: false,
        reason: `Next autonomous scan scheduled in ${remainingMins} min`,
        nextRunAt: config.nextRunAt,
        lastRunAt: config.lastRunAt,
      };
    }

    // 4. ATOMIC MUTEX ACQUISITION: Advance nextRunAt in Atlas before launching job
    const nextScheduledTime = new Date(now + freqMs).toISOString();

    const lockFilter: any = {
      docType: "crawl_config",
      id: config.id,
      enabled: true,
      paused: { $ne: true },
    };

    if (nextRunMs > 0) {
      lockFilter.$or = [
        { nextRunAt: { $lte: new Date(now + 10_000).toISOString() } },
        { nextRunAt: null },
        { nextRunAt: { $exists: false } },
      ];
    }

    const lockResult = await col.updateOne(lockFilter, {
      $set: {
        nextRunAt: nextScheduledTime,
        updatedAt: new Date().toISOString(),
      },
    });

    if (lockResult.matchedCount === 0) {
      return {
        triggered: false,
        reason: "Autonomous lock acquired by concurrent worker",
        nextRunAt: config.nextRunAt,
        lastRunAt: config.lastRunAt,
      };
    }

    // Lock successfully acquired! Invalidate caches so UI and subscribers see updated timestamp
    invalidateCrawlerStateCache();
    logger.info(
      "scheduler",
      `[AUTONOMOUS SCAN TRIGGERED] Cadence: ${freqMinutes}m, Next run set to: ${nextScheduledTime}`,
    );

    // 5. Dispatch the scheduled crawl job with triggerType: "SCHEDULED"
    const newJob = await createAndRunCrawlJob("SCHEDULED");
    return {
      triggered: true,
      jobId: newJob.id,
      reason: `Autonomous scheduled crawl dispatched successfully (${newJob.id})`,
      nextRunAt: nextScheduledTime,
      lastRunAt: config.lastRunAt,
    };
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    console.error("[scheduler] Error during checkAndTriggerScheduledCrawl:", err);
    return { triggered: false, reason: `Scheduler error: ${msg}` };
  } finally {
    isCheckingSchedule = false;
  }
}

// ---------------------------------------------------------------------------
// Background Scheduler Daemon Initializer
// ---------------------------------------------------------------------------

let schedulerDaemonTimer: NodeJS.Timeout | null = null;

export function startCrawlerSchedulerDaemon() {
  if (schedulerDaemonTimer) return;

  // Initial schedule check after a brief server startup grace delay (5s)
  setTimeout(() => {
    void checkAndTriggerScheduledCrawl().catch((err) => {
      console.warn("[scheduler-daemon] Initial tick error:", err);
    });
  }, 5_000);

  // Periodic ticker every 20 seconds
  schedulerDaemonTimer = setInterval(() => {
    void checkAndTriggerScheduledCrawl().catch((err) => {
      console.warn("[scheduler-daemon] Periodic tick error:", err);
    });
  }, 20_000);

  if (typeof schedulerDaemonTimer.unref === "function") {
    schedulerDaemonTimer.unref();
  }
  console.log("[scheduler] Autonomous crawler scheduler daemon initialized (20s interval)");
}

// Auto-register hooks and launch daemon on module load
registerScheduleChecker(checkAndTriggerScheduledCrawl);
startCrawlerSchedulerDaemon();
