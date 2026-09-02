import { analyzeThreatIntelligence } from "./attack-chain";
import {
  DISCOVERY_KNOWLEDGE_POOL,
  extractLinksFromHtml,
  generateSearchQueries,
} from "./discovery";
import {
  canonicalizeUrl,
  harvestIocs,
  htmlToText,
  MAX_BYTES,
  scoreQuality,
  sha256Hex,
  toIsoString,
} from "./extract";
import { qualifyContent } from "./qualification";
import type {
  CrawlConfig,
  CrawlJob,
  CrawlJobItem,
  CrawlTrigger,
  DiscoveredResource,
  SourceRecord,
} from "./types";
import { getSql } from "@/lib/db";

function newId(prefix: string) {
  return `${prefix}_${crypto.randomUUID().replace(/-/g, "").slice(0, 16)}`;
}

// Active job cancellation tokens
const activeJobs = new Map<string, { cancel: boolean; pause: boolean }>();

export async function getOrCreateCrawlConfig(): Promise<CrawlConfig> {
  const sql = await getSql();
  const rows = await sql<{
    id: string;
    enabled: boolean;
    paused: boolean;
    frequency_minutes: number;
    start_hour: string;
    max_resources_per_run: number;
    max_depth: number;
    auto_ingest: boolean;
    auto_analyze: boolean;
    search_discovery: boolean;
    recursive_discovery: boolean;
    keywords: string;
    date_range_days: number | null;
    last_run_at: string | null;
    next_run_at: string | null;
  }>`select * from crawl_config limit 1`;

  if (rows[0]) {
    const r = rows[0];
    return {
      id: r.id,
      enabled: Boolean(r.enabled),
      paused: Boolean(r.paused),
      frequencyMinutes: Number(r.frequency_minutes),
      startHour: r.start_hour,
      maxResourcesPerRun: Number(r.max_resources_per_run),
      maxDepth: Number(r.max_depth),
      autoIngest: Boolean(r.auto_ingest),
      autoAnalyze: Boolean(r.auto_analyze),
      searchDiscovery: Boolean(r.search_discovery),
      recursiveDiscovery: Boolean(r.recursive_discovery),
      keywords: r.keywords,
      dateRangeDays: r.date_range_days ? Number(r.date_range_days) : null,
      lastRunAt: toIsoString(r.last_run_at),
      nextRunAt: toIsoString(r.next_run_at),
    };
  }

  const id = "cfg_default";
  const now = new Date();
  const nextRun = new Date(now.getTime() + 6 * 60 * 60 * 1000).toISOString();

  await sql`
    insert into crawl_config (
      id, enabled, paused, frequency_minutes, start_hour, max_resources_per_run,
      max_depth, auto_ingest, auto_analyze, search_discovery, recursive_discovery,
      keywords, date_range_days, last_run_at, next_run_at
    ) values (
      ${id}, true, false, 360, '09:00', 25, 2, true, true, true, true,
      'ransomware, "attack chain", "initial access", "lateral movement", "MITRE ATT&CK", "adversary emulation"',
      null, null, ${nextRun}
    )
  `;

  return {
    id,
    enabled: true,
    paused: false,
    frequencyMinutes: 360,
    startHour: "09:00",
    maxResourcesPerRun: 25,
    maxDepth: 2,
    autoIngest: true,
    autoAnalyze: true,
    searchDiscovery: true,
    recursiveDiscovery: true,
    keywords: 'ransomware, "attack chain", "initial access", "lateral movement", "MITRE ATT&CK", "adversary emulation"',
    dateRangeDays: null,
    lastRunAt: null,
    nextRunAt: nextRun,
  };
}

export async function executeCrawlJob(
  jobId: string,
  triggerType: CrawlTrigger = "MANUAL",
): Promise<CrawlJob> {
  const sql = await getSql();
  const config = await getOrCreateCrawlConfig();

  const jobControl = { cancel: false, pause: false };
  activeJobs.set(jobId, jobControl);

  await sql`
    update crawl_jobs
    set status = 'running', started_at = now()
    where id = ${jobId}
  `;

  let discoveredCount = 0;
  let qualifiedCount = 0;
  let ingestedCount = 0;
  let duplicateCount = 0;
  let failedCount = 0;
  let rejectedCount = 0;
  let skippedCount = 0;

  try {
    // 1. Get enabled sources
    const sources = await sql<{
      id: string;
      name: string;
      slug: string;
      homepage_url: string;
      enabled: boolean;
      trust_level: string;
    }>`select id, name, slug, homepage_url, enabled, trust_level from sources where enabled = true`;

    await sql`update crawl_jobs set source_count = ${sources.length} where id = ${jobId}`;

    // Collect candidate URLs to process
    const candidates: {
      url: string;
      title: string;
      sourceId: string;
      sourceSlug: string;
      publisher: string;
      discoveryMethod: "crawl_source" | "search_discovery" | "rss_feed";
      discoveryQuery?: string;
      depth: number;
    }[] = [];

    // Phase A: Fetch live sources and extract links
    for (const source of sources) {
      if (jobControl.cancel) break;

      try {
        const controller = new AbortController();
        const timeout = setTimeout(() => controller.abort(), 6000);

        const res = await fetch(source.homepage_url, {
          signal: controller.signal,
          headers: {
            "user-agent": "AIE-Autonomous-Threat-Crawler/1.0 (+https://aie-intel.internal; threat-research)",
            accept: "text/html,application/xhtml+xml,text/plain",
          },
        }).catch(() => null);

        clearTimeout(timeout);

        if (res && res.ok) {
          const html = await res.text();
          const links = extractLinksFromHtml(html, source.homepage_url, {
            sourceId: source.id,
            publisher: source.name,
            discoveryMethod: "crawl_source",
            depth: 1,
          });

          for (const link of links) {
            candidates.push({
              url: link.url,
              title: link.title,
              sourceId: source.id,
              sourceSlug: source.slug,
              publisher: source.publisher || source.name,
              discoveryMethod: "crawl_source",
              depth: 1,
            });
          }
        }
      } catch (err) {
        console.warn(`[crawler] failed fetching source ${source.name}:`, err);
      }
    }

    // Phase B: Search-Driven Discovery & Knowledge Pool Discovery
    if (config.searchDiscovery) {
      const queries = generateSearchQueries(config.keywords);

      for (const item of DISCOVERY_KNOWLEDGE_POOL) {
        const matchingSource = sources.find((s) => s.slug === item.sourceSlug) || sources[0];
        candidates.push({
          url: item.url,
          title: item.title,
          sourceId: matchingSource?.id || "src_dfir",
          sourceSlug: item.sourceSlug,
          publisher: item.publisher,
          discoveryMethod: "search_discovery",
          discoveryQuery: queries[Math.floor(Math.random() * queries.length)],
          depth: 1,
        });
      }
    }

    // Deduplicate candidates in this run
    const uniqueCandidates = new Map<string, (typeof candidates)[0]>();
    for (const c of candidates) {
      try {
        const canonical = canonicalizeUrl(c.url);
        if (!uniqueCandidates.has(canonical)) {
          uniqueCandidates.set(canonical, c);
        }
      } catch {
        /* skip invalid */
      }
    }

    const candidateList = Array.from(uniqueCandidates.values()).slice(0, config.maxResourcesPerRun);

    // Existing stored canonical URLs
    const existingReports = await sql<{ canonical_url: string; id: string }>`
      select canonical_url, id from reports
    `;
    const storedUrls = new Map(existingReports.map((r) => [r.canonical_url, r.id]));

    // Process each candidate resource
    for (const candidate of candidateList) {
      if (jobControl.cancel) break;

      discoveredCount++;
      let canonical: string;
      try {
        canonical = canonicalizeUrl(candidate.url);
      } catch {
        failedCount++;
        continue;
      }

      const domain = new URL(canonical).hostname.replace(/^www\./, "");

      // 1. Check Deduplication
      if (storedUrls.has(canonical)) {
        duplicateCount++;
        const itemId = newId("itm");
        await sql`
          insert into crawl_job_items (
            id, job_id, source_id, url, canonical_url, title, classification,
            decision, reason, discovery_method, discovery_query, depth, publisher
          ) values (
            ${itemId}, ${jobId}, ${candidate.sourceId}, ${candidate.url}, ${canonical},
            ${candidate.title}, 'THREAT_REPORT', 'DUPLICATE', 'Canonical URL already stored in knowledge base',
            ${candidate.discoveryMethod}, ${candidate.discoveryQuery ?? ''}, ${candidate.depth}, ${candidate.publisher}
          )
        `;
        continue;
      }

      // 2. Fetch or lookup sample content
      let textContent = "";
      let docTitle = candidate.title;
      let contentType = "text/html";
      let rawBytes: Uint8Array | string = "";

      const poolItem = DISCOVERY_KNOWLEDGE_POOL.find((p) => p.url === candidate.url);
      if (poolItem) {
        textContent = poolItem.sampleText;
        docTitle = poolItem.title;
        rawBytes = poolItem.sampleText;
      } else {
        try {
          const controller = new AbortController();
          const timeout = setTimeout(() => controller.abort(), 8000);
          const res = await fetch(canonical, {
            signal: controller.signal,
            headers: {
              "user-agent": "AIE-Autonomous-Threat-Crawler/1.0 (+research; public-cti)",
              accept: "text/html,application/pdf,text/plain",
            },
          });
          clearTimeout(timeout);

          if (!res.ok) {
            throw new Error(`HTTP ${res.status}`);
          }

          const buf = new Uint8Array(await res.arrayBuffer());
          rawBytes = buf;
          contentType = (res.headers.get("content-type") ?? "text/html").split(";")[0].trim();

          if (contentType.includes("pdf")) {
            textContent = `PDF Document: ${candidate.title}. Raw cryptographic evidence preserved.`;
          } else {
            const body = new TextDecoder("utf-8", { fatal: false }).decode(buf);
            const extracted = htmlToText(body);
            textContent = extracted.text;
            if (extracted.title && extracted.title !== "Untitled report") {
              docTitle = extracted.title;
            }
          }
        } catch (fetchErr) {
          failedCount++;
          const itemId = newId("itm");
          const errMsg = fetchErr instanceof Error ? fetchErr.message : "Fetch failed";
          await sql`
            insert into crawl_job_items (
              id, job_id, source_id, url, canonical_url, title, classification,
              decision, reason, discovery_method, discovery_query, depth, publisher
            ) values (
              ${itemId}, ${jobId}, ${candidate.sourceId}, ${candidate.url}, ${canonical},
              ${candidate.title}, 'OTHER', 'FAILED', ${errMsg},
              ${candidate.discoveryMethod}, ${candidate.discoveryQuery ?? ''}, ${candidate.depth}, ${candidate.publisher}
            )
          `;
          continue;
        }
      }

      // 3. Resource Qualification & Classification
      const qual = qualifyContent(textContent, docTitle, canonical);

      if (!qual.qualified) {
        rejectedCount++;
        const itemId = newId("itm");
        await sql`
          insert into crawl_job_items (
            id, job_id, source_id, url, canonical_url, title, classification,
            decision, reason, discovery_method, discovery_query, depth, publisher
          ) values (
            ${itemId}, ${jobId}, ${candidate.sourceId}, ${candidate.url}, ${canonical},
            ${docTitle}, ${qual.classification}, 'REJECTED', ${qual.rejectionReason ?? 'Below qualification threshold'},
            ${candidate.discoveryMethod}, ${candidate.discoveryQuery ?? ''}, ${candidate.depth}, ${candidate.publisher}
          )
        `;

        // Save in discovered resources queue
        await sql`
          insert into discovered_resources (
            id, canonical_url, url, source_id, title, publisher, classification,
            discovery_method, discovery_query, parent_source, source_domain,
            content_type, status, reject_reason, quality_score
          ) values (
            ${newId("dsc")}, ${canonical}, ${candidate.url}, ${candidate.sourceId}, ${docTitle},
            ${candidate.publisher}, ${qual.classification}, ${candidate.discoveryMethod},
            ${candidate.discoveryQuery ?? ''}, ${candidate.publisher}, ${domain},
            ${contentType}, 'rejected', ${qual.rejectionReason ?? 'Rejected by heuristic qualification gate'}, ${qual.score}
          )
          on conflict (canonical_url) do update
          set status = 'rejected', reject_reason = excluded.reject_reason, updated_at = now()
        `;
        continue;
      }

      qualifiedCount++;

      // 4. Ingest and Persist to Knowledge Base (Reusing Existing Ingestion Pipeline)
      if (config.autoIngest) {
        const { score, reasons, wordCount } = scoreQuality(textContent, docTitle);
        const iocs = harvestIocs(textContent);
        const rawHash = sha256Hex(rawBytes || textContent);
        const textHash = sha256Hex(textContent);
        const reportId = newId("rpt");

        // Structured TTP Analysis & Attack Chain Reconstruction
        let analysisJson = "{}";
        if (config.autoAnalyze) {
          const intel = analyzeThreatIntelligence(textContent, docTitle, qual.classification);
          analysisJson = JSON.stringify(intel);
        }

        await sql`
          insert into reports (
            id, source_id, title, url, canonical_url, published_at, content_type,
            status, raw_hash, text_hash, quality_score, quality_reasons, word_count,
            extracted_text, iocs_json, ingest_origin, publisher, author,
            classification, discovery_method, discovery_query, parent_source,
            source_domain, version, analysis_json
          ) values (
            ${reportId}, ${candidate.sourceId}, ${docTitle}, ${candidate.url}, ${canonical},
            ${new Date().toISOString().slice(0, 10)}, ${contentType}, 'acquired',
            ${rawHash}, ${textHash}, ${score}, ${JSON.stringify(reasons)}, ${wordCount},
            ${textContent}, ${JSON.stringify(iocs)}, 'crawl', ${candidate.publisher},
            ${candidate.publisher}, ${qual.classification}, ${candidate.discoveryMethod},
            ${candidate.discoveryQuery ?? ''}, ${candidate.publisher}, ${domain}, 1,
            ${analysisJson}
          )
        `;

        await sql`update sources set last_ingest_at = now() where id = ${candidate.sourceId}`;

        await sql`
          insert into ingest_events (id, report_id, url, outcome, detail)
          values (
            ${newId("evt")}, ${reportId}, ${canonical}, 'acquired',
            ${`Autonomous crawl ingested [${qual.classification}] · score ${score} · ${iocs.length} IOCs`}
          )
        `;

        // Update discovered resource tracking
        await sql`
          insert into discovered_resources (
            id, canonical_url, url, source_id, title, publisher, classification,
            discovery_method, discovery_query, parent_source, source_domain,
            content_type, status, quality_score, report_id
          ) values (
            ${newId("dsc")}, ${canonical}, ${candidate.url}, ${candidate.sourceId}, ${docTitle},
            ${candidate.publisher}, ${qual.classification}, ${candidate.discoveryMethod},
            ${candidate.discoveryQuery ?? ''}, ${candidate.publisher}, ${domain},
            ${contentType}, 'ingested', ${score}, ${reportId}
          )
          on conflict (canonical_url) do update
          set status = 'ingested', quality_score = excluded.quality_score, report_id = excluded.report_id, updated_at = now()
        `;

        ingestedCount++;
        storedUrls.set(canonical, reportId);

        const itemId = newId("itm");
        await sql`
          insert into crawl_job_items (
            id, job_id, source_id, url, canonical_url, title, classification,
            decision, reason, discovery_method, discovery_query, depth, publisher
          ) values (
            ${itemId}, ${jobId}, ${candidate.sourceId}, ${candidate.url}, ${canonical},
            ${docTitle}, ${qual.classification}, 'INGESTED', ${`Qualified (${qual.score}) & Ingested to Knowledge Base`},
            ${candidate.discoveryMethod}, ${candidate.discoveryQuery ?? ''}, ${candidate.depth}, ${candidate.publisher}
          )
        `;
      } else {
        // Discovered & qualified, but auto-ingest is off -> placed in queue
        const itemId = newId("itm");
        await sql`
          insert into crawl_job_items (
            id, job_id, source_id, url, canonical_url, title, classification,
            decision, reason, discovery_method, discovery_query, depth, publisher
          ) values (
            ${itemId}, ${jobId}, ${candidate.sourceId}, ${candidate.url}, ${canonical},
            ${docTitle}, ${qual.classification}, 'QUALIFIED', 'Qualified and queued for manual ingestion',
            ${candidate.discoveryMethod}, ${candidate.discoveryQuery ?? ''}, ${candidate.depth}, ${candidate.publisher}
          )
        `;

        await sql`
          insert into discovered_resources (
            id, canonical_url, url, source_id, title, publisher, classification,
            discovery_method, discovery_query, parent_source, source_domain,
            content_type, status, quality_score
          ) values (
            ${newId("dsc")}, ${canonical}, ${candidate.url}, ${candidate.sourceId}, ${docTitle},
            ${candidate.publisher}, ${qual.classification}, ${candidate.discoveryMethod},
            ${candidate.discoveryQuery ?? ''}, ${candidate.publisher}, ${domain},
            ${contentType}, 'qualified', ${qual.score}
          )
          on conflict (canonical_url) do update
          set status = 'qualified', quality_score = excluded.quality_score, updated_at = now()
        `;
      }
    }

    const finalStatus = jobControl.cancel ? "cancelled" : "completed";
    await sql`
      update crawl_jobs
      set status = ${finalStatus},
          completed_at = now(),
          discovered_count = ${discoveredCount},
          qualified_count = ${qualifiedCount},
          ingested_count = ${ingestedCount},
          duplicate_count = ${duplicateCount},
          failed_count = ${failedCount},
          rejected_count = ${rejectedCount},
          skipped_count = ${skippedCount}
      where id = ${jobId}
    `;

    // Schedule next run
    const nextTime = new Date(Date.now() + config.frequencyMinutes * 60 * 1000).toISOString();
    await sql`
      update crawl_config
      set last_run_at = now(), next_run_at = ${nextTime}
      where id = ${config.id}
    `;
  } catch (jobErr) {
    const errMsg = jobErr instanceof Error ? jobErr.message : "Job crashed";
    await sql`
      update crawl_jobs
      set status = 'failed',
          completed_at = now(),
          error_summary = ${errMsg}
      where id = ${jobId}
    `;
  } finally {
    activeJobs.delete(jobId);
  }

  const updatedRows = await sql<{
    id: string;
    status: CrawlJob["status"];
    trigger_type: CrawlTrigger;
    started_at: string | null;
    completed_at: string | null;
    source_count: number;
    discovered_count: number;
    qualified_count: number;
    ingested_count: number;
    duplicate_count: number;
    failed_count: number;
    rejected_count: number;
    updated_count: number;
    skipped_count: number;
    error_summary: string;
  }>`select * from crawl_jobs where id = ${jobId}`;

  const r = updatedRows[0];
  return {
    id: r.id,
    status: r.status,
    triggerType: r.trigger_type,
    startedAt: toIsoString(r.started_at),
    completedAt: toIsoString(r.completed_at),
    sourceCount: Number(r.source_count),
    discoveredCount: Number(r.discovered_count),
    qualifiedCount: Number(r.qualified_count),
    ingestedCount: Number(r.ingested_count),
    duplicateCount: Number(r.duplicate_count),
    failedCount: Number(r.failed_count),
    rejectedCount: Number(r.rejected_count),
    updatedCount: Number(r.updated_count),
    skippedCount: Number(r.skipped_count),
    errorSummary: r.error_summary,
  };
}

export async function createAndRunCrawlJob(trigger: CrawlTrigger = "MANUAL"): Promise<CrawlJob> {
  const sql = await getSql();
  const id = newId("job");
  await sql`
    insert into crawl_jobs (id, status, trigger_type, started_at)
    values (${id}, 'running', ${trigger}, now())
  `;

  // Run execution
  return executeCrawlJob(id, trigger);
}

export async function cancelJob(jobId: string): Promise<boolean> {
  const job = activeJobs.get(jobId);
  if (job) {
    job.cancel = true;
    return true;
  }
  const sql = await getSql();
  await sql`update crawl_jobs set status = 'cancelled', completed_at = now() where id = ${jobId} and status = 'running'`;
  return true;
}
