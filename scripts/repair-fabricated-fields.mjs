#!/usr/bin/env node
/**
 * One-off repair for report fields that earlier versions fabricated:
 *
 *  1. "AI verified" set without any model call: aiAuditReason starting with
 *     "Verified by Automated AI Quality Gate", with aiQualityScore floored at 75.
 *     -> aiVerified=false, aiQualityScore unset, honest reason.
 *  2. Crawled reports whose publishedAt is the day they were ingested (the
 *     crawler used to store today's date). -> publishedAt=null (unknown).
 *     Only applied with --fix-dates, since a report may genuinely have been
 *     published on the day it was crawled.
 *
 * Dry run by default; pass --apply to write.
 *   MONGODB_URI=... node scripts/repair-fabricated-fields.mjs [--fix-dates] [--apply]
 */
import { MongoClient } from "mongodb";

const args = new Set(process.argv.slice(2));
const APPLY = args.has("--apply");
const FIX_DATES = args.has("--fix-dates");
const uri = process.env.MONGODB_URI;
if (!uri) {
  console.error("MONGODB_URI is not set (see .env.example).");
  process.exit(1);
}
const dbName = process.env.MONGODB_DATABASE || "threat-intel-DB";
const colName = process.env.MONGODB_COLLECTION || "threat-intel";

const client = new MongoClient(uri);
try {
  await client.connect();
  const col = client.db(dbName).collection(colName);

  const fakeVerified = {
    docType: "report",
    aiAuditReason: { $regex: "^Verified by Automated AI Quality Gate" },
  };
  const verifiedCount = await col.countDocuments(fakeVerified);
  console.log(`[1] reports marked AI-verified without a model call: ${verifiedCount}`);
  if (APPLY && verifiedCount > 0) {
    const res = await col.updateMany(fakeVerified, {
      $set: { aiVerified: false, aiAuditReason: "Not yet evaluated by an AI model." },
      $unset: { aiQualityScore: "" },
    });
    console.log(`    updated ${res.modifiedCount}`);
  }

  // Crawl-origin reports whose publishedAt equals the ingestion day.
  const crawlDates = await col
    .find(
      { docType: "report", ingestOrigin: { $in: ["crawl", "citation_expansion"] }, publishedAt: { $type: "string" } },
      { projection: { id: 1, publishedAt: 1, ingestedAt: 1, title: 1 } },
    )
    .toArray();
  const sameDay = crawlDates.filter(
    (d) => typeof d.ingestedAt === "string" && d.publishedAt === d.ingestedAt.slice(0, 10),
  );
  console.log(`[2] crawled reports with publishedAt == ingestion day: ${sameDay.length}`);
  for (const d of sameDay.slice(0, 10)) console.log(`    ${d.id}  ${d.publishedAt}  ${String(d.title).slice(0, 70)}`);
  if (APPLY && FIX_DATES && sameDay.length > 0) {
    const res = await col.updateMany(
      { docType: "report", id: { $in: sameDay.map((d) => d.id) } },
      { $set: { publishedAt: null } },
    );
    console.log(`    cleared ${res.modifiedCount} (re-crawl to recover real dates)`);
  } else if (sameDay.length > 0 && !FIX_DATES) {
    console.log("    (pass --fix-dates with --apply to clear them)");
  }

  if (!APPLY) console.log("\nDry run: nothing written. Re-run with --apply to write.");
} finally {
  await client.close();
}
