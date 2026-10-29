/**
 * Library gate persistence: runs the rules in ../aie/library-gate over stored reports and records
 * the verdicts, and hides / restores reports on an analyst's request. Nothing is ever deleted.
 *
 * MongoDB: verdicts live on the report document (`gate.*`); a hidden report gets
 * `status: "rejected"`, `rejectedBy` ("rules" | "analyst"), the status it had before
 * (`previousStatus`) and a readable `aiAuditReason` that the Library already shows. Every view that
 * excludes rejected reports (search, coverage, dashboard, emulation) then leaves it out too.
 * Restore puts the previous status back and sets `gate.override: "keep"` so the rules never hide it
 * again. Only reports not yet checked under the current rules version are evaluated.
 *
 * Local fallback (no MONGODB_URI): the same through `reports.status` plus a `library_gate` table.
 */
import type { AnyBulkWriteOperation, Document } from "mongodb";
import { getSql, type Sql } from "@/lib/db";
import { getThreatIntelCollection, isMongoConfigured } from "./client.server";
import { invalidateDashboardCache, invalidateReportsCache } from "./repository.server";
import { invalidateLocalSearchCache } from "../aie/search/corpus.server";
import { LIBRARY_GATE_VERSION, evaluateLibraryReport, gateReasonLine, type GateInput, type GateVerdict } from "../aie/library-gate";
import { summarizeEmulation } from "../aie/emulation-value";

export type GatePassResult = {
  storage: "mongodb" | "local";
  version: number;
  checked: number;
  newlyHidden: Array<{ id: string; title: string; reason: string }>;
  totalHidden: number;
};

export type VisibilityResult = { changed: number };

const g = globalThis as typeof globalThis & {
  __libraryGatePass__?: Promise<GatePassResult>;
  __libraryGateTable__?: Promise<Sql>;
};

function afterChange(): void {
  invalidateReportsCache();
  invalidateDashboardCache();
  invalidateLocalSearchCache();
}

function gateFields(v: GateVerdict, at: string): Record<string, unknown> {
  // Dotted paths, so an analyst's `gate.override` survives re-checks.
  return {
    "gate.version": LIBRARY_GATE_VERSION,
    "gate.verdict": v.verdict,
    "gate.rule": v.rule,
    "gate.reasons": v.reasons,
    "gate.protectedBy": v.protectedBy,
    "gate.relevance": v.relevance,
    "gate.checkedAt": at,
    // Emulation value travels with each check, so every stored report gets a grade. Dotted paths,
    // so the AI's verdict (`emulation.ai`) survives re-checks.
    ...(v.emulation ? Object.fromEntries(Object.entries(summarizeEmulation(v.emulation)).map(([k, x]) => [`emulation.${k}`, x])) : {}),
  };
}

/** How much of each stored report's text the gate reads. */
const GATE_TEXT_CHARS = 150_000;

const TIERS = new Set([1, 2, 3, 4]);
const tierOf = (v: unknown): GateInput["sourceTier"] => (TIERS.has(Number(v)) ? (Number(v) as 1 | 2 | 3 | 4) : null);

// ---------------------------------------------------------------------------
// MongoDB
// ---------------------------------------------------------------------------

const size = (path: string) => ({ $cond: [{ $isArray: path }, { $size: path }, 0] });
const text = (path: string) => ({ $cond: [{ $eq: [{ $type: path }, "string"] }, path, ""] });

async function mongoPass(): Promise<GatePassResult> {
  const col = await getThreatIntelCollection();
  const cursor = col.aggregate(
    [
      { $match: { docType: "report", status: { $ne: "duplicate" }, "gate.version": { $ne: LIBRARY_GATE_VERSION } } },
      {
        $project: {
          _id: 0,
          id: 1,
          title: 1,
          url: 1,
          status: 1,
          wordCount: 1,
          qualityScore: 1,
          sourceTier: 1,
          discoveryMethod: 1,
          summary: {
            $substrCP: [{ $cond: [{ $gt: [{ $strLenCP: text("$summary") }, 0] }, text("$summary"), text("$extractedText")] }, 0, 800],
          },
          // The content rule reads the text; the cap keeps a giant appendix from slowing the pass.
          body: { $substrCP: [text("$extractedText"), 0, GATE_TEXT_CHARS] },
          structured: { $cond: [{ $ifNull: ["$structured", false] }, true, false] },
          keep: { $eq: ["$gate.override", "keep"] },
          iocCount: size("$iocs"),
          techniques: size("$extractedEntities.techniques"),
          cves: size("$extractedEntities.cves"),
          attackChain: size("$analysis.attackChain"),
          attackRefs: size("$extractedEntities.attackRefs"),
          actors: size("$analysis.threatActors"),
          malware: size("$analysis.malware"),
        },
      },
    ],
    { allowDiskUse: true },
  );

  const at = new Date().toISOString();
  let checked = 0;
  const newlyHidden: GatePassResult["newlyHidden"] = [];
  let ops: AnyBulkWriteOperation<Document>[] = [];
  const flush = async () => {
    if (ops.length === 0) return;
    await col.bulkWrite(ops, { ordered: false });
    ops = [];
  };

  for await (const d of cursor) {
    checked += 1;
    const v = evaluateLibraryReport({
      title: String(d.title ?? ""),
      url: String(d.url ?? ""),
      summary: String(d.summary ?? ""),
      text: String(d.body ?? ""),
      wordCount: Number(d.wordCount ?? 0) || 0,
      iocCount: d.iocCount,
      techniques: d.techniques,
      cves: d.cves,
      attackChainSteps: d.attackChain,
      entities: d.attackRefs || d.actors + d.malware,
      qualityScore: Number(d.qualityScore ?? 0) || 0,
      sourceTier: tierOf(d.sourceTier),
      structured: Boolean(d.structured) || d.discoveryMethod === "structured_sync",
      keep: Boolean(d.keep),
    });
    const filter = { docType: "report", id: d.id };
    if (v.verdict === "reject" && d.status !== "rejected") {
      const reason = gateReasonLine(v);
      ops.push({
        updateOne: {
          filter,
          update: { $set: { ...gateFields(v, at), status: "rejected", previousStatus: d.status ?? "acquired", rejectedBy: "rules", aiAuditReason: reason, updatedAt: at } },
        },
      });
      newlyHidden.push({ id: d.id, title: String(d.title || d.url || d.id), reason });
    } else {
      // Already hidden (by the AI audit or an analyst) or kept: record the verdict only.
      ops.push({ updateOne: { filter, update: { $set: gateFields(v, at) } } });
    }
    if (ops.length >= 500) await flush();
  }
  await flush();
  if (newlyHidden.length) afterChange();
  const totalHidden = await col.countDocuments({ docType: "report", status: "rejected" });
  return { storage: "mongodb", version: LIBRARY_GATE_VERSION, checked, newlyHidden, totalHidden };
}

async function mongoSetVisibility(ids: string[], action: "hide" | "restore", by: string): Promise<VisibilityResult> {
  const col = await getThreatIntelCollection();
  const at = new Date().toISOString();
  const res =
    action === "restore"
      ? await col.updateMany({ docType: "report", id: { $in: ids }, status: "rejected" }, [
          { $set: { status: { $ifNull: ["$previousStatus", "acquired"] }, "gate.override": "keep", restoredBy: by, restoredAt: at, updatedAt: at } },
          { $unset: ["previousStatus", "rejectedBy", "aiAuditReason"] },
        ])
      : await col.updateMany({ docType: "report", id: { $in: ids }, status: { $nin: ["rejected", "duplicate"] } }, [
          { $set: { previousStatus: "$status", status: "rejected", rejectedBy: "analyst", aiAuditReason: `Hidden by ${by}`, "gate.override": "hide", updatedAt: at } },
        ]);
  if (res.modifiedCount) afterChange();
  return { changed: res.modifiedCount };
}

// ---------------------------------------------------------------------------
// Local SQL
// ---------------------------------------------------------------------------

async function localSql(): Promise<Sql> {
  g.__libraryGateTable__ ??= (async () => {
    const sql = await getSql();
    await sql`create table if not exists library_gate (
      report_id text primary key,
      version integer not null default 0,
      verdict text not null default 'keep',
      rule text,
      reasons text not null default '[]',
      previous_status text,
      override text,
      hidden_by text,
      checked_at timestamptz not null default now()
    )`;
    return sql;
  })().catch((err) => {
    g.__libraryGateTable__ = undefined;
    throw err;
  });
  return g.__libraryGateTable__;
}

type LocalRow = {
  id: string;
  title: string | null;
  url: string | null;
  status: string | null;
  word_count: number | null;
  quality_score: number | string | null;
  extracted_text: string | null;
  iocs_json: string | null;
  analysis_json: string | null;
  discovery_method: string | null;
  override: string | null;
};

function parseJson<T>(raw: string | null, fallback: T): T {
  if (!raw) return fallback;
  try {
    return JSON.parse(raw) as T;
  } catch {
    return fallback;
  }
}

async function localPass(): Promise<GatePassResult> {
  const sql = await localSql();
  const rows = await sql<LocalRow>`
    select r.id, r.title, r.url, r.status, r.word_count, r.quality_score, left(coalesce(r.extracted_text, ''), ${GATE_TEXT_CHARS}) as extracted_text,
      r.iocs_json, r.analysis_json, r.discovery_method, lg.override
    from reports r left join library_gate lg on lg.report_id = r.id
    where coalesce(r.status, '') <> 'duplicate' and (lg.version is null or lg.version <> ${LIBRARY_GATE_VERSION})
  `;
  const newlyHidden: GatePassResult["newlyHidden"] = [];
  for (const r of rows) {
    const analysis = parseJson<{ attackChain?: unknown[]; techniques?: unknown[]; threatActors?: unknown[]; malware?: unknown[] } | null>(r.analysis_json, null);
    const body = r.extracted_text ?? "";
    const len = (v: unknown) => (Array.isArray(v) ? v.length : 0);
    const v = evaluateLibraryReport({
      title: r.title ?? "",
      url: r.url ?? "",
      summary: body.slice(0, 800),
      text: body,
      wordCount: Number(r.word_count ?? 0) || 0,
      iocCount: len(parseJson<unknown[]>(r.iocs_json, [])),
      techniques: Math.max(len(analysis?.techniques), new Set(body.match(/\bT1\d{3}(?:\.\d{3})?\b/g) ?? []).size),
      cves: new Set(body.match(/\bCVE-\d{4}-\d{4,7}\b/gi) ?? []).size,
      attackChainSteps: len(analysis?.attackChain),
      entities: len(analysis?.threatActors) + len(analysis?.malware),
      qualityScore: Number(r.quality_score ?? 0) || 0,
      structured: r.discovery_method === "structured_sync",
      keep: r.override === "keep",
    });
    const hide = v.verdict === "reject" && r.status !== "rejected";
    await sql`
      insert into library_gate (report_id, version, verdict, rule, reasons, previous_status, checked_at)
      values (${r.id}, ${LIBRARY_GATE_VERSION}, ${v.verdict}, ${v.rule}, ${JSON.stringify(v.reasons)}, ${hide ? r.status ?? "acquired" : null}, now())
      on conflict (report_id) do update set version = excluded.version, verdict = excluded.verdict, rule = excluded.rule, reasons = excluded.reasons,
        previous_status = coalesce(excluded.previous_status, library_gate.previous_status), checked_at = now()
    `;
    if (hide) {
      await sql`update reports set status = 'rejected' where id = ${r.id}`;
      newlyHidden.push({ id: r.id, title: r.title || r.url || r.id, reason: gateReasonLine(v) });
    }
  }
  if (newlyHidden.length) afterChange();
  const total = await sql<{ n: number }>`select count(*)::int as n from reports where status = 'rejected'`;
  return { storage: "local", version: LIBRARY_GATE_VERSION, checked: rows.length, newlyHidden, totalHidden: Number(total[0]?.n ?? 0) };
}

async function localSetVisibility(ids: string[], action: "hide" | "restore", by: string): Promise<VisibilityResult> {
  const sql = await localSql();
  let changed = 0;
  for (const id of ids) {
    const rows = await sql<{ status: string | null; previous_status: string | null }>`
      select r.status, lg.previous_status from reports r left join library_gate lg on lg.report_id = r.id where r.id = ${id}
    `;
    const row = rows[0];
    if (!row) continue;
    if (action === "restore" && row.status === "rejected") {
      await sql`update reports set status = ${row.previous_status || "acquired"} where id = ${id}`;
      await sql`
        insert into library_gate (report_id, version, verdict, reasons, override, hidden_by) values (${id}, 0, 'keep', '[]', 'keep', null)
        on conflict (report_id) do update set override = 'keep', verdict = 'keep', previous_status = null, hidden_by = null
      `;
      changed += 1;
    } else if (action === "hide" && row.status !== "rejected" && row.status !== "duplicate") {
      await sql`update reports set status = 'rejected' where id = ${id}`;
      await sql`
        insert into library_gate (report_id, version, verdict, reasons, previous_status, override, hidden_by)
        values (${id}, 0, 'reject', ${JSON.stringify([`Hidden by ${by}`])}, ${row.status ?? "acquired"}, 'hide', ${by})
        on conflict (report_id) do update set override = 'hide', verdict = 'reject', reasons = excluded.reasons,
          previous_status = excluded.previous_status, hidden_by = excluded.hidden_by
      `;
      changed += 1;
    }
  }
  if (changed) afterChange();
  return { changed };
}

/** Readable reasons for hidden local reports (MongoDB keeps them on the document as `aiAuditReason`). */
export async function localHiddenReasons(): Promise<Map<string, string>> {
  const out = new Map<string, string>();
  if (isMongoConfigured()) return out;
  const sql = await localSql();
  const rows = await sql<{ report_id: string; rule: string | null; reasons: string; override: string | null; hidden_by: string | null }>`
    select report_id, rule, reasons, override, hidden_by from library_gate where verdict = 'reject'
  `;
  for (const r of rows) {
    const reasons = parseJson<string[]>(r.reasons, []);
    out.set(r.report_id, r.override === "hide" ? `Hidden by ${r.hidden_by ?? "an analyst"}` : gateReasonLine({ rule: r.rule, reasons }));
  }
  return out;
}

// ---------------------------------------------------------------------------
// Entry points
// ---------------------------------------------------------------------------

/** Checks every report not yet checked under the current rules; one pass at a time per server. */
export function runLibraryGatePass(): Promise<GatePassResult> {
  g.__libraryGatePass__ ??= (isMongoConfigured() ? mongoPass() : localPass()).finally(() => {
    g.__libraryGatePass__ = undefined;
  });
  return g.__libraryGatePass__;
}

export function setReportVisibility(ids: string[], action: "hide" | "restore", by: string): Promise<VisibilityResult> {
  const unique = [...new Set(ids)].slice(0, 500);
  return isMongoConfigured() ? mongoSetVisibility(unique, action, by) : localSetVisibility(unique, action, by);
}
