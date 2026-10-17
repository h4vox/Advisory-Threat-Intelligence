#!/usr/bin/env node
// Retrieval evaluation: labelled threat-intel queries over the eval corpus (5 public vendor reports,
// loaded exactly as scripts/eval/run-eval.mjs loads them) plus the 4 seed reports and the bundled
// ATT&CK knowledge. Compares the previous behaviour with the hybrid ranker (src/lib/aie/search).
//
//   npm run eval:retrieval                    # corpus from scripts/eval/.cache/ (run `npm run eval` once to fetch)
//   npm run eval:retrieval -- --raw <dir>     # read the HTML from <dir> (offline)
//   npm run eval:retrieval -- --verbose       # per-query rankings
//
// Baselines (previous behaviour):
//   substring  local library search: lower-cased query substring of title / source / url / excerpt / classification
//   bm25       chat grounding passage selection (selectPassages) over every report, reports ordered by best passage
// New: hybrid  query understanding (aliases, technique names, field syntax) + BM25F + entity / id boosts + priors
//
// Metrics: recall@5 and MRR, computed (a) on reports only and (b) on the unified list (reports + ATT&CK
// knowledge cards). Negative checks: forbidden ids must not appear in the top 5; "no reports" queries must
// return no report. Exits non-zero when the hybrid ranker misses a threshold.
import { existsSync, readFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const REPO = path.resolve(HERE, "../..");
const CACHE_DIR = path.join(HERE, ".cache");

const { htmlToText, extractHtmlMetadata, harvestIocs, excerptOf, sha256Hex } = await import(path.join(REPO, "src/lib/aie/extract.ts"));
const { qualifyContent } = await import(path.join(REPO, "src/lib/aie/qualification.ts"));
const { analyzeThreatIntelligence } = await import(path.join(REPO, "src/lib/aie/attack-chain.ts"));
const { SEED_REPORTS } = await import(path.join(REPO, "src/lib/aie/seed-reports.ts"));
const { registryEntry } = await import(path.join(REPO, "src/lib/aie/catalog.ts"));
const { selectPassages } = await import(path.join(REPO, "src/lib/aie/retrieval.ts"));
const { understandQuery } = await import(path.join(REPO, "src/lib/aie/search/query.ts"));
const { prepareReport } = await import(path.join(REPO, "src/lib/aie/search/report-docs.ts"));
const { runSearch } = await import(path.join(REPO, "src/lib/aie/search/engine.ts"));

const args = process.argv.slice(2);
const argValue = (name) => {
  const i = args.indexOf(name);
  return i >= 0 ? args[i + 1] : undefined;
};
const rawDir = argValue("--raw");
const verbose = args.includes("--verbose");
const manifest = JSON.parse(readFileSync(path.join(HERE, "manifest.json"), "utf8"));
const queries = JSON.parse(readFileSync(path.join(HERE, "retrieval-queries.json"), "utf8"));

// ---------------------------------------------------------------------------
// Corpus
// ---------------------------------------------------------------------------

function loadHtml(entry) {
  const dir = rawDir ?? CACHE_DIR;
  const p = path.join(dir, entry.file);
  if (!existsSync(p)) throw new Error(`missing ${p} (run \`npm run eval\` to fetch, or pass --raw <dir>)`);
  return readFileSync(p, "utf8");
}

function sourceIdFor(url) {
  const host = new URL(url).hostname;
  if (/microsoft\.com$/.test(host)) return "src_msft";
  if (/cloud\.google\.com$|mandiant\.com$/.test(host)) return "src_mandiant";
  if (/thedfirreport\.com$/.test(host)) return "src_dfir";
  return undefined;
}

function buildReport({ id, url, title, text, publishedAt, sourceId }, i) {
  const qual = qualifyContent(text, title, url);
  const analysis = analyzeThreatIntelligence(text, title, qual.classification);
  const src = registryEntry(sourceId);
  return {
    id,
    title,
    extractedText: text,
    excerpt: excerptOf(text),
    url,
    canonicalUrl: url,
    publisher: src?.name ?? new URL(url).hostname,
    sourceName: src?.name,
    sourceId,
    publishedAt: publishedAt ?? null,
    qualityScore: 0.8,
    analysis,
    iocs: harvestIocs(text, { sourceDomain: new URL(url).hostname.replace(/^www\./, "") }),
    classification: qual.classification,
    textHash: sha256Hex(text),
    // ingest order for the substring baseline (newest first, as the local library lists)
    _order: i,
  };
}

const reports = [];
for (const entry of manifest.reports) {
  const html = loadHtml(entry);
  const { title, text } = htmlToText(html);
  const meta = extractHtmlMetadata(html);
  reports.push(buildReport({ id: entry.id, url: entry.url, title, text, publishedAt: meta.publishedAt?.slice(0, 10), sourceId: sourceIdFor(entry.url) }, reports.length));
}
for (const r of SEED_REPORTS) {
  reports.push(buildReport({ id: r.id, url: r.url, title: r.title, text: r.text, publishedAt: r.publishedAt, sourceId: r.sourceId }, reports.length));
}

// ---------------------------------------------------------------------------
// Rankers
// ---------------------------------------------------------------------------

function substringBaseline(q) {
  const ql = q.trim().toLowerCase();
  if (!ql) return [];
  return reports
    .filter((r) => `${r.title} ${r.sourceName ?? ""} ${r.url} ${r.excerpt} ${r.classification}`.toLowerCase().includes(ql))
    .map((r) => r.id);
}

function bm25Baseline(q) {
  const passages = selectPassages(
    reports.map((r) => ({ id: r.id, title: r.title, text: r.extractedText })),
    q,
    { k: 60, perDoc: 1 },
  );
  return [...new Set(passages.map((p) => p.docId))];
}

const prepared = reports.map(prepareReport);
const NOW = Date.parse("2026-10-16T00:00:00Z");
function hybrid(q) {
  const iq = understandQuery(q);
  const reportsOnly = runSearch(prepared, iq, { group: "reports", limit: 50, now: NOW }).results.map((r) => r.id);
  const all = runSearch(prepared, iq, { group: "all", limit: 50, now: NOW });
  return { reports: reportsOnly, unified: all.results.map((r) => r.id), interpreted: iq.summary, total: all.total };
}

// ---------------------------------------------------------------------------
// Metrics
// ---------------------------------------------------------------------------

const reportIds = new Set(reports.map((r) => r.id));
function recallAt(ranked, relevant, k = 5) {
  if (relevant.length === 0) return null;
  const top = new Set(ranked.slice(0, k));
  return relevant.filter((r) => top.has(r)).length / relevant.length;
}
function rr(ranked, relevant) {
  if (relevant.length === 0) return null;
  const i = ranked.findIndex((x) => relevant.includes(x));
  return i === -1 ? 0 : 1 / (i + 1);
}
const mean = (xs) => {
  const v = xs.filter((x) => x !== null);
  return v.length ? v.reduce((a, b) => a + b, 0) / v.length : null;
};

const rows = [];
const negatives = [];
for (const q of queries.queries) {
  const relevant = q.relevant ?? [];
  const relReports = relevant.filter((id) => reportIds.has(id));
  const h = hybrid(q.q);
  const s = substringBaseline(q.q);
  const b = bm25Baseline(q.q);
  const row = {
    q: q.q,
    kind: q.kind,
    interpreted: h.interpreted,
    reports: {
      substring: { r5: recallAt(s, relReports), rr: rr(s, relReports) },
      bm25: { r5: recallAt(b, relReports), rr: rr(b, relReports) },
      hybrid: { r5: recallAt(h.reports, relReports), rr: rr(h.reports, relReports) },
    },
    unified: {
      substring: { r5: recallAt(s, relevant), rr: rr(s, relevant) },
      bm25: { r5: recallAt(b, relevant), rr: rr(b, relevant) },
      hybrid: { r5: recallAt(h.unified, relevant), rr: rr(h.unified, relevant) },
    },
    ranked: { substring: s.slice(0, 5), bm25: b.slice(0, 5), hybridReports: h.reports.slice(0, 5), hybridUnified: h.unified.slice(0, 5) },
  };
  rows.push(row);
  const forbidden = q.forbidden ?? [];
  if (forbidden.length || q.noReports || q.noResults) {
    const check = (list, unifiedTotal) => {
      const hits = forbidden.filter((f) => list.slice(0, 5).includes(f));
      const okReports = !q.noReports || list.length === 0;
      const okResults = !q.noResults || unifiedTotal === 0;
      return { pass: hits.length === 0 && okReports && okResults, hits, reportCount: list.length };
    };
    negatives.push({
      q: q.q,
      hybrid: check(h.reports, h.total),
      substring: check(s, s.length),
      bm25: check(b, b.length),
    });
  }
}

// ---------------------------------------------------------------------------
// Report
// ---------------------------------------------------------------------------

const fmt = (v) => (v === null ? "  —  " : v.toFixed(3));
const summary = {};
for (const scope of ["reports", "unified"]) {
  summary[scope] = {};
  for (const sys of ["substring", "bm25", "hybrid"]) {
    summary[scope][sys] = {
      recallAt5: mean(rows.map((r) => r[scope][sys].r5)),
      mrr: mean(rows.map((r) => r[scope][sys].rr)),
      n: rows.filter((r) => r[scope][sys].r5 !== null).length,
    };
  }
}
const negPass = (sys) => negatives.filter((n) => n[sys].pass).length;

console.log(`Retrieval eval: ${reports.length} reports (${manifest.reports.length} vendor + ${SEED_REPORTS.length} seed), ${queries.queries.length} labelled queries, ATT&CK knowledge bundled\n`);
if (verbose) {
  for (const r of rows) {
    console.log(`• ${r.q}   [${r.kind}]  → ${r.interpreted || "(keywords)"}`);
    console.log(`    hybrid  R@5 rep ${fmt(r.reports.hybrid.r5)} uni ${fmt(r.unified.hybrid.r5)} | ${r.ranked.hybridUnified.join(", ")}`);
    console.log(`    bm25    R@5 rep ${fmt(r.reports.bm25.r5)}           | ${r.ranked.bm25.join(", ")}`);
    console.log(`    substr  R@5 rep ${fmt(r.reports.substring.r5)}           | ${r.ranked.substring.join(", ")}`);
  }
  console.log("");
}
console.log("                         reports only (n=%d)        unified: reports + ATT&CK (n=%d)", summary.reports.hybrid.n, summary.unified.hybrid.n);
console.log("system                   recall@5     MRR           recall@5     MRR");
for (const [sys, label] of [
  ["substring", "baseline: substring"],
  ["bm25", "baseline: BM25 passages"],
  ["hybrid", "hybrid ranker (new)"],
]) {
  console.log(
    `${label.padEnd(24)} ${fmt(summary.reports[sys].recallAt5).padEnd(12)} ${fmt(summary.reports[sys].mrr).padEnd(13)} ${fmt(summary.unified[sys].recallAt5).padEnd(12)} ${fmt(summary.unified[sys].mrr)}`,
  );
}
console.log(`\nnegative / exclusion checks (${negatives.length}): substring ${negPass("substring")}/${negatives.length} · bm25 ${negPass("bm25")}/${negatives.length} · hybrid ${negPass("hybrid")}/${negatives.length}`);
for (const n of negatives) if (!n.hybrid.pass) console.log(`  FAIL hybrid: ${n.q} → forbidden ${n.hybrid.hits.join(", ") || "-"}, ${n.hybrid.reportCount} reports`);

const T = queries.thresholds;
const checks = [
  ["reports recall@5", summary.reports.hybrid.recallAt5, T.reportsRecallAt5],
  ["reports MRR", summary.reports.hybrid.mrr, T.reportsMrr],
  ["unified recall@5", summary.unified.hybrid.recallAt5, T.unifiedRecallAt5],
  ["unified MRR", summary.unified.hybrid.mrr, T.unifiedMrr],
  ["negatives passed", negPass("hybrid") / Math.max(1, negatives.length), 1],
  ["margin over the BM25 baseline (reports recall@5, hybrid minus bm25)", summary.reports.hybrid.recallAt5 - summary.reports.bm25.recallAt5, 0],
];
let failed = 0;
console.log("\nthresholds");
for (const [name, value, min] of checks) {
  const pass = value !== null && value >= min - 1e-9;
  if (!pass) failed++;
  console.log(`  ${pass ? "PASS" : "FAIL"}  ${name}: ${fmt(value)} (min ${min})`);
}
const missed = rows.filter((r) => (r.unified.hybrid.r5 ?? 1) < 1);
if (missed.length) {
  console.log("\nqueries below full recall@5 (hybrid, unified):");
  for (const r of missed) console.log(`  ${r.q}: ${fmt(r.unified.hybrid.r5)} → ${r.ranked.hybridUnified.join(", ")}`);
}
console.log(failed ? `\n${failed} threshold(s) failed` : "\nall thresholds passed");
process.exit(failed ? 1 : 0);
