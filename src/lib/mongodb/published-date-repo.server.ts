/**
 * Re-dates stored reports with the publication-date resolver (../aie/published-date): reports
 * stored before it existed, or under an older version of it. The original page (kept gzipped on
 * the report) is read when there is one, otherwise the extracted text and URL. A date recorded at
 * ingestion is kept unless the source's own structured data states another one, and a report is
 * never left without a date it had. Derived data only: the report text is never changed.
 */
import type { AnyBulkWriteOperation, Document } from "mongodb";
import { gunzipSync } from "node:zlib";
import { getThreatIntelCollection, isMongoConfigured } from "./client.server";
import { invalidateReportsCache } from "./repository.server";
import { PUBLISHED_DATE_VERSION, resolvePublicationDate, type PublishedDate } from "../aie/published-date";

const NEEDS_DATE = {
  docType: "report",
  discoveryMethod: { $ne: "structured_sync" },
  "publishedDate.version": { $ne: PUBLISHED_DATE_VERSION },
};

function originalHtml(doc: Document): string | null {
  if (typeof doc.originalContent !== "string" || !/html/i.test(String(doc.originalContentType ?? ""))) return null;
  try {
    return gunzipSync(Buffer.from(doc.originalContent, "base64")).toString("utf8");
  } catch {
    return null;
  }
}

/** Dates one stored report. Exported for the post-ingest path and tests of the policy. */
export function redate(doc: Document): PublishedDate {
  const recorded = typeof doc.publishedAt === "string" && doc.publishedAt ? doc.publishedAt : null;
  const isPdf = /pdf/i.test(String(doc.contentType ?? "")) || /\.pdf($|\?)/i.test(String(doc.canonicalUrl ?? ""));
  const r = resolvePublicationDate({
    html: isPdf ? null : originalHtml(doc),
    text: String(doc.extractedText ?? "").slice(0, 8000),
    url: String(doc.canonicalUrl || doc.url || ""),
    // The stored date stands in for the feed date: only structured page data outranks it.
    feedDate: recorded,
  });
  if (r.source === "feed") return { ...r, source: "recorded", confidence: "medium", evidence: "date recorded when the report was ingested" };
  if (!r.publishedAt && recorded) {
    return { publishedAt: recorded, sourceUpdatedAt: null, source: "recorded", confidence: "low", evidence: "date recorded when the report was ingested", version: PUBLISHED_DATE_VERSION };
  }
  return r;
}

export async function mongoRedateReportsBatch(limit = 25): Promise<{ dated: number; changed: number; remaining: number }> {
  if (!isMongoConfigured()) return { dated: 0, changed: 0, remaining: 0 };
  const col = await getThreatIntelCollection();
  const docs = await col
    .find(NEEDS_DATE, {
      projection: { _id: 0, id: 1, url: 1, canonicalUrl: 1, contentType: 1, publishedAt: 1, extractedText: 1, originalContent: 1, originalContentType: 1 },
    })
    .limit(Math.max(1, Math.min(100, limit)))
    .toArray();
  let changed = 0;
  const ops: AnyBulkWriteOperation<Document>[] = docs.map((d) => {
    const publishedDate = redate(d);
    const set: Document = { publishedDate };
    if (publishedDate.publishedAt && publishedDate.publishedAt !== d.publishedAt) {
      set.publishedAt = publishedDate.publishedAt;
      changed++;
    }
    return { updateOne: { filter: { docType: "report", id: d.id }, update: { $set: set } } };
  });
  if (ops.length) {
    await col.bulkWrite(ops, { ordered: false });
    invalidateReportsCache();
  }
  const remaining = await col.countDocuments(NEEDS_DATE);
  return { dated: ops.length, changed, remaining };
}
