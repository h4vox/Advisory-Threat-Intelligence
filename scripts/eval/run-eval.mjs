#!/usr/bin/env node
// Evaluation harness: runs the app's real heuristic ingest pipeline over a fixed set of
// public threat-intel reports and checks concrete expectations.
//
//   npm run eval                      # fetch into scripts/eval/.cache/ (git-ignored), reuse cache
//   npm run eval -- --refresh         # re-download even when cached
//   npm run eval -- --raw <dir>       # read <file> from <dir> instead of fetching (offline)
//
// Pipeline (mirrors server.ts URL ingest -> persistReport, minus DB writes):
//   htmlToText -> extractHtmlMetadata -> qualifyContent -> harvestIocs(sourceDomain)
//   -> analyzeThreatIntelligence (heuristic; LLM/sandbox modules are stubbed by hooks.mjs)
//
// Must be run with: node --experimental-strip-types --import ./scripts/eval/register.mjs
// Exits non-zero when any check fails or a report cannot be loaded.
import { createHash } from "node:crypto";
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const REPO = path.resolve(HERE, "../..");
const CACHE_DIR = path.join(HERE, ".cache");

const { htmlToText, extractHtmlMetadata, harvestIocs, isNonPublicIpv4, decodeEntities } = await import(
  path.join(REPO, "src/lib/aie/extract.ts")
);
const { qualifyContent } = await import(path.join(REPO, "src/lib/aie/qualification.ts"));
const { analyzeThreatIntelligence } = await import(path.join(REPO, "src/lib/aie/attack-chain.ts"));

// ---------------------------------------------------------------------------
// Args & loading
// ---------------------------------------------------------------------------

const args = process.argv.slice(2);
const argValue = (name) => {
  const i = args.indexOf(name);
  return i >= 0 ? args[i + 1] : undefined;
};
const rawDir = argValue("--raw");
const refresh = args.includes("--refresh");

const manifest = JSON.parse(readFileSync(path.join(HERE, "manifest.json"), "utf8"));
const sha256 = (s) => createHash("sha256").update(s).digest("hex");

async function loadHtml(entry) {
  if (rawDir) {
    const p = path.join(rawDir, entry.file);
    if (!existsSync(p)) throw new Error(`missing ${p}`);
    return { html: readFileSync(p, "utf8"), origin: "raw" };
  }
  const cached = path.join(CACHE_DIR, entry.file);
  if (!refresh && existsSync(cached)) return { html: readFileSync(cached, "utf8"), origin: "cache" };
  const res = await fetch(entry.url, {
    headers: {
      "user-agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124 Safari/537.36",
      accept: "text/html,application/xhtml+xml",
    },
    signal: AbortSignal.timeout(30_000),
  });
  if (!res.ok) throw new Error(`HTTP ${res.status} fetching ${entry.url}`);
  const html = await res.text();
  mkdirSync(CACHE_DIR, { recursive: true });
  writeFileSync(cached, html);
  return { html, origin: "fetched" };
}

// ---------------------------------------------------------------------------
// Pipeline
// ---------------------------------------------------------------------------

function runPipeline(entry, html) {
  const { title, text } = htmlToText(html);
  const meta = extractHtmlMetadata(html);
  const domain = new URL(entry.url).hostname.replace(/^www\./, "");
  const qual = qualifyContent(text, title, entry.url);
  const iocs = harvestIocs(text, { sourceDomain: domain });
  const analysis = analyzeThreatIntelligence(text, title, qual.classification);
  return { title, text, meta, qual, iocs, analysis };
}

/** Share of the page's prose blocks (p, li, h1-h6, td, pre with >= 8 words) that survive in the extracted text. */
function proseRetention(html, text) {
  const strip = (h) =>
    decodeEntities(h.replace(/<script[\s\S]*?<\/script>|<style[\s\S]*?<\/style>/gi, " ").replace(/<[^>]+>/g, " "))
      .replace(/\s+/g, " ")
      .trim();
  const norm = (s) => s.replace(/\s+/g, " ").toLowerCase();
  const blocks = [...html.matchAll(/<(p|li|h[1-6]|td|pre)\b[^>]*>([\s\S]*?)<\/\1>/gi)]
    .map((m) => strip(m[2]))
    .filter((s) => s.split(" ").length >= 8);
  const haystack = norm(text);
  const total = blocks.reduce((a, b) => a + b.length, 0);
  const kept = blocks.filter((b) => haystack.includes(norm(b).slice(0, 80))).reduce((a, b) => a + b.length, 0);
  return total ? kept / total : 0;
}

/** Every Evidence object produced for the report (analysis evidence + IOC evidence). */
function allEvidence(analysis, iocs) {
  const ev = analysis.evidence;
  const out = [];
  if (ev) {
    for (const t of ev.techniques) out.push(...t.evidence);
    for (const a of ev.actors) out.push(...a.evidence);
    for (const m of ev.malware) out.push(...m.evidence);
    for (const t of ev.targeting) out.push(...t.evidence);
    for (const r of ev.relationships) out.push(...r.evidence);
    for (const s of ev.chain.steps) out.push(...s.evidence);
    for (const x of ev.excluded) out.push(x.evidence);
  }
  for (const i of iocs) if (i.evidence) out.push(i.evidence);
  return out;
}

// ---------------------------------------------------------------------------
// Checks
// ---------------------------------------------------------------------------

const ADVERSARY = new Set(["observed", "inferred"]);

function genericChecks(r) {
  const checks = [];
  const steps = r.analysis.evidence?.chain.steps ?? [];
  const basis = r.analysis.evidence?.chain.orderBasis;
  if (steps.length >= 2) {
    checks.push({ name: "chain orderBasis", expected: "reported", actual: basis, pass: basis === "reported" });
  } else {
    checks.push({ name: "chain orderBasis (<2 steps)", expected: "unknown", actual: basis, pass: basis === "unknown" });
  }
  const positions = steps.map((s) => s.position);
  const ordered =
    positions.every((p, i) => i === 0 || p > positions[i - 1]) &&
    steps.every((s, i) => s.order === i + 1 && s.evidence.every((e) => e.start >= s.position));
  checks.push({
    name: "chain steps follow source position",
    expected: "ascending",
    actual: positions.length ? positions.join(",") : "(no steps)",
    pass: ordered,
  });
  const evidence = allEvidence(r.analysis, r.iocs);
  const bad = evidence.filter((e) => r.text.slice(e.start, e.end) !== e.quote);
  checks.push({
    name: "evidence quotes == text.slice(start,end)",
    expected: "all",
    actual: `${evidence.length - bad.length}/${evidence.length}`,
    pass: bad.length === 0 && evidence.length > 0,
  });
  const privateIps = r.iocs.filter((i) => i.kind === "ipv4" && isNonPublicIpv4(i.value)).map((i) => i.value);
  checks.push({
    name: "no private/non-public IPs",
    expected: "0",
    actual: privateIps.length ? privateIps.join(",") : "0",
    pass: privateIps.length === 0,
  });
  return checks;
}

const SCENARIOS = {
  msft_volt_typhoon: (r) => [retention(r)],
  msft_octo_tempest: (r) => [retention(r)],
  gti_brickstorm: (r) => {
    const apt29 = r.analysis.evidence?.actors.find((a) => a.value.toLowerCase() === "apt29");
    const apt29Adversary = r.analysis.threatActors.some((a) => a.toLowerCase() === "apt29") || (apt29 && ADVERSARY.has(apt29.label));
    return [
      {
        name: "APT29 not attributed as observed",
        expected: "not observed",
        actual: apt29 ? apt29.label : "absent",
        pass: !apt29Adversary,
      },
      {
        name: "actor UNC5221",
        expected: "in threatActors",
        actual: r.analysis.threatActors.join(", ") || "(none)",
        pass: r.analysis.threatActors.includes("UNC5221"),
      },
    ];
  },
  gti_unc3944_hardening: (r) => {
    const observed = (r.analysis.evidence?.techniques ?? []).filter((t) => t.label === "observed");
    return [
      {
        name: "observed techniques (hardening guide)",
        expected: "0",
        actual: `${observed.length} (ttps=${r.analysis.ttps.length})`,
        pass: observed.length === 0,
      },
    ];
  },
  gti_breeze_comet: (r) => {
    const defanged = r.iocs.filter((i) => i.defanged);
    return [{ name: "defanged IOCs captured", expected: ">=20", actual: String(defanged.length), pass: defanged.length >= 20 }];
  },
};

function retention(r) {
  const ratio = proseRetention(r.html, r.text);
  return { name: "prose text retained", expected: ">80%", actual: `${(ratio * 100).toFixed(1)}%`, pass: ratio > 0.8 };
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

const rows = [];
const warnings = [];
let loadFailures = 0;

for (const entry of manifest.reports) {
  let loaded;
  try {
    loaded = await loadHtml(entry);
  } catch (err) {
    loadFailures++;
    rows.push({ report: entry.id, name: "load report", expected: "html", actual: String(err.message ?? err), pass: false });
    continue;
  }
  const hash = sha256(loaded.html);
  if (hash !== entry.sha256) {
    warnings.push(`${entry.id}: sha256 ${hash.slice(0, 12)}… differs from manifest ${entry.sha256.slice(0, 12)}… (page changed since baseline)`);
  }
  const r = { ...runPipeline(entry, loaded.html), html: loaded.html };
  const checks = [...(SCENARIOS[entry.id]?.(r) ?? []), ...genericChecks(r)];
  for (const c of checks) rows.push({ report: entry.id, ...c });
}

const cols = [
  ["report", "Report"],
  ["name", "Check"],
  ["expected", "Expected"],
  ["actual", "Actual"],
  ["result", "Result"],
];
const table = rows.map((r) => ({ ...r, result: r.pass ? "PASS" : "FAIL" }));
const widths = cols.map(([k, h]) => Math.min(60, Math.max(h.length, ...table.map((r) => String(r[k]).length))));
const fmt = (vals) => vals.map((v, i) => String(v).slice(0, widths[i]).padEnd(widths[i])).join(" | ");
console.log(fmt(cols.map(([, h]) => h)));
console.log(widths.map((w) => "-".repeat(w)).join("-|-"));
for (const r of table) console.log(fmt(cols.map(([k]) => r[k])));

for (const w of warnings) console.warn(`WARN ${w}`);
const failed = rows.filter((r) => !r.pass).length;
console.log(`\n${rows.length - failed}/${rows.length} checks passed${loadFailures ? `, ${loadFailures} report(s) failed to load` : ""}.`);
process.exit(failed > 0 ? 1 : 0);
