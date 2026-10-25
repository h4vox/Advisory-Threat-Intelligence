/**
 * Research labels and telemetry references on stored reports: library coverage per research
 * category (for the coverage view and discovery priority) and the backfill that labels reports
 * stored before labelling existed, or under an older labeller version. Derived data only: the
 * report text is never changed.
 */
import type { AnyBulkWriteOperation, Document } from "mongodb";
import { getThreatIntelCollection, isMongoConfigured } from "./client.server";
import { invalidateReportsCache } from "./repository.server";
import { RESEARCH_CATEGORY_IDS, RESEARCH_LABELS_VERSION, classifyResearch, type ResearchCategoryId } from "../aie/research-taxonomy";
import { TELEMETRY_REFS_VERSION, extractTelemetryRefs } from "../aie/telemetry-refs";

export type ResearchCoverage = {
  counts: Record<ResearchCategoryId, number>;
  /** Visible reports with at least one label. */
  labelled: number;
  /** Visible reports. */
  total: number;
  /** Visible reports not yet labelled under the current version. */
  pending: number;
};

// Structured reference records (ATT&CK objects, atomic tests, emulation library) are not research
// reports: they are neither labelled nor counted, so they cannot skew coverage or discovery.
const VISIBLE = { docType: "report", status: { $ne: "rejected" }, discoveryMethod: { $ne: "structured_sync" } };
const NEEDS_LABELS = {
  docType: "report",
  discoveryMethod: { $ne: "structured_sync" },
  $or: [{ "research.version": { $ne: RESEARCH_LABELS_VERSION } }, { "telemetry.version": { $ne: TELEMETRY_REFS_VERSION } }],
};

function emptyCounts(): Record<ResearchCategoryId, number> {
  return Object.fromEntries(RESEARCH_CATEGORY_IDS.map((id) => [id, 0])) as Record<ResearchCategoryId, number>;
}

export async function mongoResearchCoverage(): Promise<ResearchCoverage> {
  const counts = emptyCounts();
  if (!isMongoConfigured()) return { counts, labelled: 0, total: 0, pending: 0 };
  const col = await getThreatIntelCollection();
  const [rows, total, labelled, pending] = await Promise.all([
    col
      .aggregate<{ _id: string; n: number }>([{ $match: VISIBLE }, { $unwind: "$research.labels" }, { $group: { _id: "$research.labels.id", n: { $sum: 1 } } }])
      .toArray(),
    col.countDocuments(VISIBLE),
    col.countDocuments({ ...VISIBLE, "research.labels.0": { $exists: true } }),
    col.countDocuments({ ...VISIBLE, "research.version": { $ne: RESEARCH_LABELS_VERSION } }),
  ]);
  for (const r of rows) if (r._id in counts) counts[r._id as ResearchCategoryId] = r.n;
  return { counts, labelled, total, pending };
}

/**
 * Labels up to `limit` reports that have no labels (or older ones), hidden reports included so a
 * restored report is labelled too. Returns how many were labelled and how many remain.
 */
export async function mongoLabelResearchBatch(limit = 100): Promise<{ labelled: number; remaining: number }> {
  if (!isMongoConfigured()) return { labelled: 0, remaining: 0 };
  const col = await getThreatIntelCollection();
  const docs = await col
    .find(NEEDS_LABELS, { projection: { _id: 0, id: 1, title: 1, extractedText: 1 } })
    .limit(Math.max(1, Math.min(500, limit)))
    .toArray();
  const ops: AnyBulkWriteOperation<Document>[] = docs.map((d) => {
    const text = String(d.extractedText ?? "");
    const research = classifyResearch({ title: String(d.title ?? ""), text });
    const telemetry = extractTelemetryRefs(text);
    return { updateOne: { filter: { docType: "report", id: d.id }, update: { $set: { research, telemetry } } } };
  });
  if (ops.length) {
    await col.bulkWrite(ops, { ordered: false });
    invalidateReportsCache();
  }
  const remaining = await col.countDocuments(NEEDS_LABELS);
  return { labelled: ops.length, remaining };
}
