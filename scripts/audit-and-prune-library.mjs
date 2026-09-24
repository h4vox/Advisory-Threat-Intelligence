#!/usr/bin/env node

/**
 * Adversary Intelligence Engine (AIE) - Library Quality Audit & Pruning Utility
 *
 * Scans all reports in MongoDB threat-intel-DB, audits them against strict
 * Adversary Emulation & CTI tradecraft qualification standards, and safely
 * prunes low-signal artifacts (homepages, category roots, podcasts, marketing,
 * zero-procedure news blurbs, and legal policies).
 *
 * Usage:
 *   node scripts/audit-and-prune-library.mjs [--dry-run | --prune] [--verbose]
 */

import { MongoClient } from "mongodb";
import dns from "node:dns";
import { writeFileSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = dirname(fileURLToPath(import.meta.url));
const ROOT_DIR = join(__dirname, "..");

try {
  if (typeof dns.setDefaultResultOrder === "function") {
    dns.setDefaultResultOrder("ipv4first");
  }
  dns.setServers(["8.8.8.8", "1.1.1.1", "8.8.4.4"]);
} catch {}

const DEFAULT_MONGO_URI =
  process.env.MONGODB_URI ||
  "mongodb://threatintel_app:UsvyDIqA5d5YztAf@ac-0e7499a-shard-00-00.gr9ihel.mongodb.net:27017,ac-0e7499a-shard-00-01.gr9ihel.mongodb.net:27017,ac-0e7499a-shard-00-02.gr9ihel.mongodb.net:27017/threat-intel-DB?ssl=true&replicaSet=atlas-ekdr6v-shard-0&authSource=admin&appName=Cluster0";

const DB_NAME = process.env.MONGODB_DATABASE || "threat-intel-DB";
const COLLECTION_NAME = process.env.MONGODB_COLLECTION || "threat-intel";

// Non-CTI hosts (government immigration/administrative portals or pure news aggregators)
const JUNK_HOSTS = new Set([
  "uscis.gov",
  "ice.gov",
  "e-verify.gov",
  "edit.dhs.gov",
]);

// Known index / landing / marketing path patterns that are not technical reports
const JUNK_URL_SUBSTRINGS = [
  "/all-news-updates",
  "/podcasts",
  "/webinars",
  "/white-papers",
  "/tips-advice",
  "/business-security",
  "/eset-research",
  "/disclosure-policy",
  "/privacy-policy",
  "/privacy",
  "/terms-of-service",
  "/terms",
  "/careers",
  "/pricing",
  "/contact",
  "/about",
  "/sitemap",
  "/sitemap1.aspx",
  "/latest-publications",
  "/resources",
  "/projects",
  "/reputation_center",
  "/secure-endpoint-naming",
  "/software-development-companies",
  "/family",
  "/upload-my-documents",
  "/9-11",
  "/en-us/security",
  "/en-us/security/blog",
  "/security/blog",
  "/security-labs/blog",
  "/nice",
];

// Title indicators of pure non-report / aggregator / marketing pages
const JUNK_TITLE_PATTERNS = [
  /^podcasts?$/i,
  /^white papers?$/i,
  /^tips & advice$/i,
  /^business security$/i,
  /^eset research$/i,
  /^disclosure policy$/i,
  /^latest publications$/i,
  /^microsoft security blog$/i,
  /^blogs?$/i,
  /^news$/i,
  /^projects?$/i,
  /^privacy policy$/i,
  /^terms (?:of service|and conditions)$/i,
  /^about (?:us|checkpoint|sentinelone|google|mandiant)$/i,
  /labscon\d+\s+replay\s*\|\s*keynote/i,
  /#videointerview:/i,
  /^cloud security solutions \| microsoft security$/i,
  /^qualys cybersecurity resources/i,
  /^nice$/i,
];

export function evaluateReportQuality(report) {
  const url = report.url || "";
  let urlReason = null;
  let host = "";
  let path = "";

  try {
    const u = new URL(url);
    host = u.hostname.replace(/^www\./, "").toLowerCase();
    path = u.pathname.replace(/\/+$/, "") || "/";
  } catch {
    return {
      action: "PRUNE",
      reason: "Malformed URL",
      wordCount: 0,
      iocCount: 0,
      attackChainStages: 0,
      mitreTechniques: 0,
    };
  }

  const title = (report.title || "").trim();
  const wordCount =
    Number(report.wordCount) ||
    (report.extractedText ? report.extractedText.split(/\s+/).filter(Boolean).length : 0);
  const iocCount = Array.isArray(report.iocs) ? report.iocs.length : 0;
  const attackChainStages = report.analysis?.attackChain?.length || 0;
  const mitreTechniques = report.analysis?.techniques?.length || 0;
  const hasCve = Boolean(
    report.analysis?.cves?.length ||
      (title && /\bcve-\d{4}-\d{4,}\b/i.test(title)) ||
      (report.summary && /\bcve-\d{4}-\d{4,}\b/i.test(report.summary)),
  );
  const score = Number(report.qualityScore) || 0;

  // 1. Non-CTI host filter
  if (JUNK_HOSTS.has(host) || (host.endsWith(".dhs.gov") && !host.includes("cisa"))) {
    urlReason = `Non-CTI administrative host: ${host}`;
  }
  // 2. Pure homepages / sitemaps
  else if (path === "" || path === "/" || path === "/en" || path === "/en-us" || path === "/en_us" || /sitemap/i.test(path)) {
    urlReason = `Homepage / Root index: ${path || "/"}`;
  }
  // 3. Known index/junk URL paths (exact or ending match)
  else if (JUNK_URL_SUBSTRINGS.some((s) => path.endsWith(s) || path === s)) {
    urlReason = `Index / Resource aggregator path: ${path}`;
  }
  // 4. Multimedia, Podcasts, Keynote replays
  else if (
    /\/podcasts?(?:\/.*)?$/i.test(path) ||
    /talos_takes/i.test(path) ||
    /labscon\d+\s+replay\s*\|\s*keynote/i.test(title) ||
    /#videointerview/i.test(title)
  ) {
    urlReason = "Multimedia / Podcast / Keynote video replay";
  }

  if (urlReason) {
    return {
      action: "PRUNE",
      reason: urlReason,
      wordCount,
      iocCount,
      attackChainStages,
      mitreTechniques,
    };
  }

  // 5. Title matching junk patterns
  for (const pat of JUNK_TITLE_PATTERNS) {
    if (pat.test(title)) {
      return {
        action: "PRUNE",
        reason: `Junk title pattern: ${pat}`,
        wordCount,
        iocCount,
        attackChainStages,
        mitreTechniques,
      };
    }
  }

  // 6. Generic news portals (infosecurity-magazine) with ZERO technical artifacts
  if (
    host.includes("infosecurity-magazine.com") &&
    iocCount === 0 &&
    attackChainStages === 0 &&
    mitreTechniques === 0 &&
    !hasCve
  ) {
    return {
      action: "PRUNE",
      reason: "Journalistic news blurb without TTPs, IOCs, or attack chains",
      wordCount,
      iocCount,
      attackChainStages,
      mitreTechniques,
    };
  }

  // 7. Pure zero-signal short stubs
  if (wordCount < 200 && iocCount === 0 && attackChainStages === 0 && mitreTechniques === 0 && !hasCve) {
    return {
      action: "PRUNE",
      reason: `Stub overview (${wordCount} words) with zero technical indicators, chain stages, or MITRE techniques`,
      wordCount,
      iocCount,
      attackChainStages,
      mitreTechniques,
    };
  }

  // 8. Low-signal short overview with 0 technical anchors (<350 words, 0 IOCs, 0 chain, 0 techniques)
  if (wordCount < 350 && iocCount === 0 && attackChainStages === 0 && mitreTechniques === 0 && !hasCve && score < 0.45) {
    return {
      action: "PRUNE",
      reason: `Short non-technical news overview (${wordCount} words) with zero technical artifacts`,
      wordCount,
      iocCount,
      attackChainStages,
      mitreTechniques,
    };
  }

  // 9. Reports with score 0 and zero technical findings
  if (score <= 0.10 && iocCount === 0 && attackChainStages === 0 && mitreTechniques === 0 && !hasCve) {
    return {
      action: "PRUNE",
      reason: `Zero/near-zero quality score (${score}) with zero technical evidence`,
      wordCount,
      iocCount,
      attackChainStages,
      mitreTechniques,
    };
  }

  // High-value CTI detection
  const reasonsToKeep = [];
  if (attackChainStages > 0) reasonsToKeep.push(`${attackChainStages} attack chain stages`);
  if (iocCount > 0) reasonsToKeep.push(`${iocCount} verified IOCs`);
  if (mitreTechniques > 0) reasonsToKeep.push(`${mitreTechniques} MITRE techniques`);
  if (hasCve) reasonsToKeep.push("Verified CVE reference");
  if (wordCount >= 800) reasonsToKeep.push(`Detailed technical writeup (${wordCount} words)`);
  if (score >= 0.60) reasonsToKeep.push(`High tradecraft quality score (${score})`);

  return {
    action: "KEEP",
    reason: reasonsToKeep.join("; ") || "Qualified CTI report",
    wordCount,
    iocCount,
    attackChainStages,
    mitreTechniques,
    score,
  };
}

async function runAudit() {
  const args = process.argv.slice(2);
  const doPrune = args.includes("--prune");

  console.log(`Connecting to MongoDB (${DB_NAME})...`);
  const client = new MongoClient(DEFAULT_MONGO_URI, { serverSelectionTimeoutMS: 10000 });
  await client.connect();
  const db = client.db(DB_NAME);
  const col = db.collection(COLLECTION_NAME);

  console.log("Querying all reports with docType: 'report'...");
  const cursor = col.find(
    { docType: "report" },
    {
      projection: {
        id: 1,
        title: 1,
        url: 1,
        canonicalUrl: 1,
        publisher: 1,
        sourceName: 1,
        qualityScore: 1,
        wordCount: 1,
        iocs: 1,
        analysis: 1,
        summary: 1,
        ingestedAt: 1,
      },
    },
  );

  const reports = await cursor.toArray();
  console.log(`Auditing ${reports.length} reports in the library...\n`);

  const toKeep = [];
  const toPrune = [];

  for (const r of reports) {
    const evalResult = evaluateReportQuality(r);
    const itemSummary = {
      id: r.id,
      title: r.title,
      url: r.url,
      publisher: r.publisher || r.sourceName || "Unknown",
      ingestedAt: r.ingestedAt,
      ...evalResult,
    };

    if (evalResult.action === "KEEP") {
      toKeep.push(itemSummary);
    } else {
      toPrune.push(itemSummary);
    }
  }

  console.log("================================================================================");
  console.log("             ADVERSARY THREAT INTELLIGENCE LIBRARY AUDIT REPORT                 ");
  console.log("================================================================================");
  console.log(`Total Reports Scanned:                   ${reports.length}`);
  console.log(`Retained (High-Value Adversary Intel):   ${toKeep.length} (${Math.round((toKeep.length / reports.length) * 100)}%)`);
  console.log(`Pruned (Junk / Index / Low-Signal):       ${toPrune.length} (${Math.round((toPrune.length / reports.length) * 100)}%)`);
  console.log("--------------------------------------------------------------------------------\n");

  console.log("--- BREAKDOWN OF REASONS FOR PRUNING ---");
  const reasonBuckets = {};
  for (const p of toPrune) {
    const category = p.reason.startsWith("Index / Resource aggregator")
      ? "Aggregator / Index Path"
      : p.reason.startsWith("Homepage")
        ? "Homepage / Root Index"
        : p.reason.startsWith("Non-CTI administrative")
          ? "Non-CTI Administrative Host"
          : p.reason.startsWith("Multimedia")
            ? "Multimedia / Podcast / Keynote"
            : p.reason.startsWith("Junk title")
              ? "Aggregator / Junk Title"
              : p.reason.startsWith("Journalistic news")
                ? "Journalistic News Blurb (0 artifacts)"
                : p.reason.includes("Stub overview")
                  ? "Stub (<200 words, 0 artifacts)"
                  : p.reason.includes("Short non-technical")
                    ? "Short News / Zero Technical Artifacts"
                    : p.reason.includes("Zero/near-zero")
                      ? "Zero Quality Score"
                      : "Other";
    reasonBuckets[category] = (reasonBuckets[category] || 0) + 1;
  }
  for (const [cat, count] of Object.entries(reasonBuckets)) {
    console.log(`  • ${cat.padEnd(42)}: ${count}`);
  }

  console.log("\n--- EXAMPLES OF PRUNED ENTRIES (TOP 15) ---");
  for (const p of toPrune.slice(0, 15)) {
    console.log(`[PRUNED] "${p.title?.slice(0, 55)}"`);
    console.log(`         URL:    ${p.url}`);
    console.log(`         Reason: ${p.reason}`);
    console.log(`         Stats:  ${p.wordCount} words, ${p.iocCount} IOCs, ${p.attackChainStages} chain stages\n`);
  }

  console.log("--- EXAMPLES OF RETAINED HIGH-SIGNAL CTI (TOP 10) ---");
  for (const k of toKeep.slice(0, 10)) {
    console.log(`[RETAINED] "${k.title?.slice(0, 55)}"`);
    console.log(`           Publisher: ${k.publisher} | Score: ${k.score}`);
    console.log(`           URL:       ${k.url}`);
    console.log(`           Evidence:  ${k.reason}\n`);
  }

  // Save audit log to disk for operators and methodology tracking
  const auditLogFile = join(ROOT_DIR, "docs/library-audit-log.json");
  writeFileSync(
    auditLogFile,
    JSON.stringify(
      {
        auditedAt: new Date().toISOString(),
        totalScanned: reports.length,
        retainedCount: toKeep.length,
        prunedCount: toPrune.length,
        pruneReasonBuckets: reasonBuckets,
        prunedSample: toPrune.slice(0, 50),
        retainedSample: toKeep.slice(0, 50),
      },
      null,
      2,
    ),
    "utf8",
  );
  console.log(`Detailed audit log saved to: ${auditLogFile}`);

  if (doPrune) {
    console.log(`\nExecuting PRUNE operation for ${toPrune.length} rejected documents...`);
    const pruneIds = toPrune.map((p) => p.id).filter(Boolean);
    if (pruneIds.length > 0) {
      const deleteResult = await col.deleteMany({
        docType: "report",
        id: { $in: pruneIds },
      });
      console.log(`Successfully deleted ${deleteResult.deletedCount} documents from MongoDB!`);
    } else {
      console.log("No documents matched prune criteria.");
    }
  } else {
    console.log(`\n[DRY RUN COMPLETE] To delete these ${toPrune.length} records, run:`);
    console.log("  node scripts/audit-and-prune-library.mjs --prune");
  }

  await client.close();
  console.log("Done.");
}

runAudit().catch((err) => {
  console.error("Audit failed:", err);
  process.exit(1);
});
