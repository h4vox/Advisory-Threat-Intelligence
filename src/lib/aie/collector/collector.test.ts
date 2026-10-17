import { test } from "node:test";
import assert from "node:assert/strict";
import { canonicalizeUrl, harvestIocs, htmlToText, sectionsOf } from "../extract.ts";
import {
  computeFingerprints,
  hammingDistance64,
  normalizeForFingerprint,
  simhash64,
  titlePublisherHash,
} from "./fingerprint.ts";
import { DedupIndex, isSyndicatorDomain, mergeMirrors, preferCanonical, type DedupIndexEntry } from "./dedup.ts";
import { conditionalHeaders, decideFetchOutcome, needsRevalidation, MAX_PREVIOUS_HASHES } from "./fetch-state.ts";
import {
  discoverFeedLinks,
  filterSitemapEntries,
  findNextPageUrl,
  nextPageFromPattern,
  paginationUrls,
  parseRobotsTxt,
  parseSitemapXml,
  planBackfill,
  rankChildSitemaps,
  robotsAllows,
  robotsCrawlDelayMs,
  titleFromSlug,
} from "./discovery-depth.ts";
import { scoreRelevance, RELEVANCE_SKIP_THRESHOLD } from "./relevance.ts";
import { RELEVANCE_FIXTURES } from "./relevance-fixtures.ts";
import { acceptanceRatio, applyRunOutcome, backoffMs, computeDue, healthStatus, SCHEDULE_INTERVAL_MS } from "./health.ts";
import { appendPdfText, enrichAttackEntities, findFullReportPdfLinks, withAttackRefs } from "./enrich.ts";

// ---------------------------------------------------------------------------
// URL canonicalisation
// ---------------------------------------------------------------------------

test("canonicalizeUrl: tracking params, fragments and trailing slashes", () => {
  const a = "https://www.example.com/blog/akira-esxi/?utm_source=x&utm_campaign=y&fbclid=1&gclid=2&ref=feed#iocs";
  assert.equal(canonicalizeUrl(a), "https://www.example.com/blog/akira-esxi");
  assert.equal(canonicalizeUrl("https://example.com/a/?msclkid=9&mkt_tok=abc&id=4"), "https://example.com/a?id=4");
  assert.equal(canonicalizeUrl("https://example.com//research//report/"), "https://example.com/research/report");
});

test("canonicalizeUrl: AMP, print and mobile renditions collapse to the article", () => {
  const want = "https://www.example.com/2025/03/akira-esxi";
  for (const v of [
    "https://www.example.com/2025/03/akira-esxi/amp/",
    "https://www.example.com/amp/2025/03/akira-esxi",
    "https://www.example.com/2025/03/akira-esxi?amp",
    "https://www.example.com/2025/03/akira-esxi?amp=1&utm_medium=social",
    "https://www.example.com/2025/03/akira-esxi/print",
    "https://www.example.com/2025/03/akira-esxi?output=print",
    "https://www.example.com/2025/03/akira-esxi?print=1",
    "https://www-example-com.cdn.ampproject.org/c/s/www.example.com/2025/03/akira-esxi/amp/",
  ]) {
    assert.equal(canonicalizeUrl(v), want, v);
  }
  assert.equal(canonicalizeUrl("https://m.example.com/news/report-x"), "https://example.com/news/report-x");
  assert.equal(canonicalizeUrl("https://mobile.example.com/news/report-x/"), "https://example.com/news/report-x");
  assert.equal(canonicalizeUrl("https://amp.example.com/news/report-x"), "https://example.com/news/report-x");
  assert.equal(canonicalizeUrl("https://example.com/posts/story.amp.html"), "https://example.com/posts/story.html");
  assert.equal(canonicalizeUrl("https://example.com/reports/index.html"), "https://example.com/reports");
  // A bare "m.com"-style host and meaningful params are untouched.
  assert.equal(canonicalizeUrl("https://m.com/x"), "https://m.com/x");
  assert.equal(canonicalizeUrl("https://example.com/search?page=2&view=list"), "https://example.com/search?page=2&view=list");
});

// ---------------------------------------------------------------------------
// Fingerprints and SimHash
// ---------------------------------------------------------------------------

const ARTICLE = Array.from({ length: 120 }, (_, i) => {
  const s = [
    `Stage ${i}: the operators used rclone to exfiltrate archives from file server FS${i} to a VPS at 45.77.${i}.10.`,
    `They created scheduled task Updater${i} for persistence and ran AdFind against domain controller DC${i % 7}.`,
    `Defender tamper protection was disabled with Set-MpPreference before Akira encrypted ESXi datastore ${i}.`,
  ];
  return s[i % 3];
}).join(" ");

test("fingerprints: normalised hash ignores case, punctuation and volatile lines", () => {
  const a = computeFingerprints({ text: `Published 2 hours ago\n${ARTICLE}`, title: "Akira hits ESXi", publisher: "Vendor" });
  const b = computeFingerprints({ text: `Published 3 hours ago\n\n${ARTICLE.toUpperCase().replace(/\. /g, ".\n")}`, title: "x", publisher: "y" });
  assert.notEqual(a.contentSha256, b.contentSha256);
  assert.equal(a.normalizedTextHash, b.normalizedTextHash);
  assert.match(a.simhash, /^[0-9a-f]{16}$/);
  assert.ok(normalizeForFingerprint("C2 at 185.220.101[.]44, then!").includes("185.220.101.44"));
});

test("titlePublisherHash: branding suffixes collapse; short titles give null", () => {
  const h1 = titlePublisherHash("Akira Ransomware Targets ESXi Hypervisors | Acme Threat Research", "Acme Labs");
  const h2 = titlePublisherHash("Akira ransomware targets ESXi hypervisors", "Acme");
  assert.ok(h1);
  assert.equal(h1, h2);
  assert.equal(titlePublisherHash("Blog", "Acme"), null);
  assert.equal(titlePublisherHash("Untitled report", "Acme"), null);
});

test("simhash64: syndicated copy within 3 bits, different reports far apart", () => {
  const original = simhash64(normalizeForFingerprint(ARTICLE));
  const repost = simhash64(
    normalizeForFingerprint(
      `This article originally appeared on Security News Wire. Researchers published the following analysis this week.\n${ARTICLE}\nRelated stories: ten things to know this week. Subscribe to our newsletter.`,
    ),
  );
  assert.ok(hammingDistance64(original, repost) <= 3, `syndicated distance ${hammingDistance64(original, repost)}`);
  const other = simhash64(
    normalizeForFingerprint(
      Array.from({ length: 120 }, (_, i) => `Phishing lure ${i} delivered a OneNote attachment that dropped QakBot via mshta and contacted Cobalt Strike team server ${i}.`).join(" "),
    ),
  );
  assert.ok(hammingDistance64(original, other) > 10, `distinct distance ${hammingDistance64(original, other)}`);
  assert.equal(hammingDistance64("ffffffffffffffff", "0000000000000000"), 64);
  assert.equal(hammingDistance64("bad", "0000000000000000"), 64);
});

// ---------------------------------------------------------------------------
// Dedup matching and canonical choice
// ---------------------------------------------------------------------------

function entry(id: string, url: string, text: string, extra: Partial<DedupIndexEntry> = {}): DedupIndexEntry {
  return {
    id,
    canonicalUrl: url,
    title: extra.title ?? "Akira ransomware targets ESXi hypervisors",
    publisher: extra.publisher ?? "Acme",
    sourceDomain: extra.sourceDomain ?? new URL(url).hostname,
    sourceTier: extra.sourceTier ?? 3,
    fingerprints: computeFingerprints({ text, title: extra.title ?? "Akira ransomware targets ESXi hypervisors", publisher: extra.publisher ?? "Acme" }),
    ...extra,
  };
}

test("DedupIndex: exact, normalised, title+publisher and SimHash matches", () => {
  const idx = new DedupIndex([entry("rpt_1", "https://acme.com/research/akira", ARTICLE, { publishedAt: "2025-03-10" })]);
  const cand = (url: string, text: string, title = "A different headline entirely here", publisher = "Other", publishedAt: string | null = null) => ({
    canonicalUrl: url,
    title,
    publisher,
    sourceDomain: new URL(url).hostname,
    publishedAt,
    fingerprints: computeFingerprints({ text, title, publisher }),
  });
  assert.equal(idx.findContentDuplicate(cand("https://mirror.net/a", ARTICLE))?.kind, "content_sha256");
  assert.equal(idx.findContentDuplicate(cand("https://mirror.net/b", ARTICLE.toLowerCase()))?.kind, "normalized_text");
  // Same title + publisher, published a day apart (e.g. the same post under /blog and /research).
  assert.equal(
    idx.findContentDuplicate(cand("https://acme.com/blog/akira", "Totally different body text about something else.", "Akira Ransomware Targets ESXi Hypervisors | Acme", "Acme", "2025-03-11"))?.kind,
    "title_publisher",
  );
  // A recurring series reuses one title for different issues weeks apart: not a duplicate.
  assert.equal(
    idx.findContentDuplicate(cand("https://acme.com/blog/akira-2", "Totally different body text about something else.", "Akira Ransomware Targets ESXi Hypervisors | Acme", "Acme", "2025-05-02")),
    null,
  );
  const near = idx.findContentDuplicate(cand("https://news.example/akira", `Exclusive: researchers shared this report.\n${ARTICLE}\nCopyright News Example.`));
  assert.equal(near?.kind, "simhash");
  assert.ok((near?.distance ?? 99) <= 3);
  assert.equal(idx.findContentDuplicate(cand("https://acme.com/research/akira", ARTICLE)), null, "same URL is not a content duplicate of itself");
  assert.equal(idx.findContentDuplicate(cand("https://x.org/y", "short unrelated text")), null);
});

test("preferCanonical: primary publisher and higher tier win over re-posts", () => {
  assert.ok(isSyndicatorDomain("www.bleepingcomputer.com"));
  assert.equal(preferCanonical({ sourceDomain: "thehackernews.com", sourceTier: 4 }, { sourceDomain: "cloud.google.com", sourceTier: 3 }), "candidate");
  assert.equal(preferCanonical({ sourceDomain: "cloud.google.com", sourceTier: 3 }, { sourceDomain: "securityweek.com", sourceTier: 3 }), "existing");
  assert.equal(preferCanonical({ sourceDomain: "blog.vendor.com", sourceTier: 4 }, { sourceDomain: "cisa.gov", sourceTier: 1 }), "candidate");
  assert.equal(
    preferCanonical({ sourceDomain: "a.com", sourceTier: 3, publishedAt: "2025-05-02" }, { sourceDomain: "b.com", sourceTier: 3, publishedAt: "2025-05-01" }),
    "candidate",
  );
  assert.equal(preferCanonical({ sourceDomain: "a.com", sourceTier: 3 }, { sourceDomain: "b.com", sourceTier: 3 }), "existing");
  const m = mergeMirrors(
    [{ url: "https://n.com/1", canonicalUrl: "https://n.com/1", publisher: "N", sourceDomain: "n.com", matchKind: "simhash", seenAt: "t1" }],
    [{ url: "https://n.com/1?utm_source=x", canonicalUrl: "https://n.com/1", publisher: "N", sourceDomain: "n.com", matchKind: "simhash", seenAt: "t2" }],
  );
  assert.equal(m.length, 1);
});

// ---------------------------------------------------------------------------
// Conditional fetch decisions
// ---------------------------------------------------------------------------

test("fetch state: new → not_modified → unchanged → changed keeps versions and hashes", () => {
  const base = { url: "https://acme.com/feed", kind: "feed" as const, sourceId: "src_acme" };
  assert.deepEqual(conditionalHeaders(null), {});
  const first = decideFetchOutcome(null, { status: 200, etag: '"v1"', lastModified: "Mon, 01 Sep 2025 10:00:00 GMT", contentHash: "h1", fetchedAt: "2025-09-01T10:00:00Z" }, base);
  assert.equal(first.outcome, "new");
  assert.equal(first.next.version, 1);
  assert.deepEqual(conditionalHeaders(first.next), { "if-none-match": '"v1"', "if-modified-since": "Mon, 01 Sep 2025 10:00:00 GMT" });

  const nm = decideFetchOutcome(first.next, { status: 304, fetchedAt: "2025-09-02T10:00:00Z" }, base);
  assert.equal(nm.outcome, "not_modified");
  assert.equal(nm.next.etag, '"v1"', "304 without validators keeps the stored ones");
  assert.equal(nm.next.notModifiedCount, 1);

  const same = decideFetchOutcome(nm.next, { status: 200, contentHash: "h1" }, base);
  assert.equal(same.outcome, "unchanged");
  assert.equal(same.next.version, 1);

  const changed = decideFetchOutcome(same.next, { status: 200, etag: '"v2"', contentHash: "h2" }, base);
  assert.equal(changed.outcome, "changed");
  assert.equal(changed.next.version, 2);
  assert.deepEqual(changed.next.previousHashes, ["h1"]);
  assert.equal(changed.previousHash, "h1");

  let s = changed.next;
  for (let i = 3; i < 20; i++) s = decideFetchOutcome(s, { status: 200, contentHash: `h${i}` }, base).next;
  assert.equal(s.previousHashes.length, MAX_PREVIOUS_HASHES);
  assert.equal(s.version, 19);
});

test("needsRevalidation: listing updates and age trigger a conditional re-fetch", () => {
  const now = Date.parse("2025-10-10T00:00:00Z");
  const state = { url: "u", kind: "article" as const, version: 1, previousHashes: [], notModifiedCount: 0, lastFetchedAt: "2025-10-05T00:00:00Z", contentHash: "h" };
  assert.equal(needsRevalidation(null, {}, now, 86400000).revalidate, true);
  assert.equal(needsRevalidation(state, { lastmod: "2025-10-07T00:00:00Z" }, now, 30 * 86400000).revalidate, true);
  assert.equal(needsRevalidation(state, { lastmod: "2025-10-01T00:00:00Z" }, now, 30 * 86400000).revalidate, false);
  assert.equal(needsRevalidation(state, {}, now, 2 * 86400000).revalidate, true);
});

// ---------------------------------------------------------------------------
// Sitemaps, feeds, pagination, robots
// ---------------------------------------------------------------------------

test("parseSitemapXml: urlset with namespaces/CDATA and sitemap index", () => {
  const urlset = `<?xml version="1.0"?><urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9" xmlns:image="x">
    <url><loc>https://acme.com/research/akira-esxi/</loc><lastmod>2025-09-30T12:00:00+00:00</lastmod></url>
    <url><loc><![CDATA[https://acme.com/research/old-post?a=1&amp;b=2]]></loc><lastmod>2023-01-02</lastmod></url>
    <url><loc>https://acme.com/about</loc></url>
    <url><loc>https://acme.com/research/akira-esxi/</loc></url>
  </urlset>`;
  const p = parseSitemapXml(urlset);
  assert.equal(p.type, "urlset");
  assert.equal(p.entries.length, 3);
  assert.equal(p.entries[0].lastmod, "2025-09-30T12:00:00.000Z");
  assert.equal(p.entries[1].loc, "https://acme.com/research/old-post?a=1&b=2");
  const recent = filterSitemapEntries(p.entries, { sinceIso: "2025-01-01T00:00:00Z" });
  assert.deepEqual(recent.map((e) => e.loc), ["https://acme.com/research/akira-esxi/"]);
  assert.equal(filterSitemapEntries(p.entries, { sinceIso: "2025-01-01T00:00:00Z", keepUndated: true }).length, 2);

  const index = `<sitemapindex xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
    <sitemap><loc>https://acme.com/post-sitemap.xml</loc><lastmod>2025-10-01</lastmod></sitemap>
    <sitemap><loc>https://acme.com/tag-sitemap.xml</loc><lastmod>2025-10-01</lastmod></sitemap>
    <sitemap><loc>https://acme.com/post-sitemap2.xml</loc><lastmod>2021-01-01</lastmod></sitemap>
  </sitemapindex>`;
  const pi = parseSitemapXml(index);
  assert.equal(pi.type, "sitemapindex");
  const ranked = rankChildSitemaps(pi.entries, { sinceIso: "2025-01-01T00:00:00Z", limit: 3 });
  assert.equal(ranked[0].loc, "https://acme.com/post-sitemap.xml");
  assert.ok(!ranked.some((e) => e.loc.includes("post-sitemap2")), "child sitemaps older than the window are skipped");
  assert.equal(titleFromSlug("https://acme.com/2025/03/akira-ransomware-esxi/"), "akira ransomware esxi");
});

test("discoverFeedLinks: rel=alternate feeds first, comment feeds skipped, anchor fallback", () => {
  const html = `<head>
    <link rel="alternate" type="application/rss+xml" title="Acme Research" href="/research/feed/">
    <link rel="alternate" type="application/rss+xml" title="Comments" href="/comments/feed/">
    <link rel='alternate' type='application/atom+xml' href='https://acme.com/atom.xml'>
    <link rel="stylesheet" href="/x.css"></head>`;
  const feeds = discoverFeedLinks(html, "https://acme.com/research/");
  assert.deepEqual(feeds.map((f) => f.url), ["https://acme.com/research/feed/", "https://acme.com/atom.xml"]);
  assert.equal(feeds[0].type, "rss");
  const fallback = discoverFeedLinks(`<a href="/blog/feed">RSS</a><a href="/about">About</a>`, "https://acme.com/");
  assert.deepEqual(fallback.map((f) => f.url), ["https://acme.com/blog/feed"]);
});

test("pagination: rel=next, labelled anchors and page patterns", () => {
  assert.equal(findNextPageUrl(`<link rel="next" href="/reports/page/2/">`, "https://acme.com/reports/"), "https://acme.com/reports/page/2/");
  assert.equal(findNextPageUrl(`<a class="nav" href="/blog?page=3">Older posts</a>`, "https://acme.com/blog?page=2"), "https://acme.com/blog?page=3");
  assert.equal(findNextPageUrl(`<p>no links</p>`, "https://acme.com/reports/page/4/"), "https://acme.com/reports/page/5/");
  assert.equal(findNextPageUrl(`<a href="https://evil.example/page/2">Next</a>`, "https://acme.com/blog/"), null);
  assert.equal(nextPageFromPattern("https://acme.com/research?paged=9"), "https://acme.com/research?paged=10");
  assert.deepEqual(paginationUrls("https://acme.com/reports/page/{n}/", 2, 4), [
    "https://acme.com/reports/page/2/",
    "https://acme.com/reports/page/3/",
    "https://acme.com/reports/page/4/",
  ]);
});

test("robots.txt: groups, longest match, crawl-delay and sitemaps", () => {
  const robots = parseRobotsTxt(`# comment
User-agent: BadBot
Disallow: /

User-agent: *
Disallow: /wp-admin/
Disallow: /search
Allow: /wp-admin/admin-ajax.php
Disallow: /*.pdf$
Crawl-delay: 4

Sitemap: https://acme.com/sitemap_index.xml`);
  const ua = "AIE-Autonomous-Threat-Crawler/3.0";
  assert.equal(robotsAllows(robots, ua, "https://acme.com/research/akira"), true);
  assert.equal(robotsAllows(robots, ua, "https://acme.com/wp-admin/options.php"), false);
  assert.equal(robotsAllows(robots, ua, "https://acme.com/wp-admin/admin-ajax.php"), true);
  assert.equal(robotsAllows(robots, ua, "https://acme.com/search?q=x"), false);
  assert.equal(robotsAllows(robots, ua, "https://acme.com/files/report.pdf"), false);
  assert.equal(robotsAllows(robots, ua, "https://acme.com/files/report.pdf?v=2"), true);
  assert.equal(robotsAllows(robots, "BadBot/1.0", "https://acme.com/research/akira"), false);
  assert.equal(robotsCrawlDelayMs(robots, ua), 4000);
  assert.deepEqual(robots.sitemaps, ["https://acme.com/sitemap_index.xml"]);
  assert.equal(robotsAllows(null, ua, "https://acme.com/anything"), true);
});

test("planBackfill: bounded windows", () => {
  const now = Date.parse("2026-10-16T00:00:00Z");
  const six = planBackfill(6, now);
  const two = planBackfill(24, now);
  assert.equal(six.sinceIso.slice(0, 10), "2026-04-16");
  assert.equal(two.sinceIso.slice(0, 10), "2024-10-16");
  assert.ok(two.maxArticles > six.maxArticles && two.maxArticles <= 200);
  assert.ok(six.hostSpacingMs >= 1000);
});

// ---------------------------------------------------------------------------
// Relevance pre-score
// ---------------------------------------------------------------------------

test("scoreRelevance: realistic intel titles are fetched, marketing is skipped with a reason", () => {
  const volt = scoreRelevance({ title: "Volt Typhoon targets US critical infrastructure with living-off-the-land techniques" });
  assert.equal(volt.decision, "fetch");
  assert.ok(volt.strongPositive);
  assert.ok(volt.signals.some((s) => s.label === "ATT&CK actor / campaign" && /G1017/.test(s.evidence ?? "")));

  const cve = scoreRelevance({ title: "Threat Actors Exploit CVE-2023-34362 MOVEit Transfer Vulnerability" });
  assert.ok(cve.signals.some((s) => s.label === "CVE ID"));

  const unc = scoreRelevance({ title: "UNC6040 Uses Vishing to Breach Salesforce Instances" });
  assert.equal(unc.decision, "fetch");

  const webinar = scoreRelevance({ title: "Webinar: Building a Modern SOC with AI-Driven Detection", url: "https://vendor.example/resources/webinars/modern-soc" });
  assert.equal(webinar.decision, "skip");
  assert.match(webinar.reason, /webinar/);
  assert.match(webinar.reason, /Low relevance pre-score/);

  for (const t of ["Acme Security Reports Fourth Quarter and Fiscal Year 2026 Financial Results", "We're Hiring: Senior Detection Engineer (Remote)", "Introducing Falconry XDR 5.0: New Features for Faster Investigations"]) {
    assert.equal(scoreRelevance({ title: t }).decision, "skip", t);
  }
  // No signal at all stays neutral and is fetched (the quality gate decides).
  assert.equal(scoreRelevance({ title: "Read more" }).decision, "fetch");
  assert.equal(scoreRelevance({ title: "" }).score, 0.35);
});

test("scoreRelevance: consumer-awareness explainers are skipped, intrusion reports with the same words are not", () => {
  const explainer = scoreRelevance({ title: "Ransomware as a service: Understanding the cybercrime gig economy and how to protect yourself" });
  assert.equal(explainer.decision, "skip", explainer.reason);
  assert.ok(explainer.signals.some((s) => s.label === "awareness explainer"));
  const intel = scoreRelevance({ title: "Understanding the Storm-2570 intrusion: RMM abuse and ESXi encryption" });
  assert.equal(intel.decision, "fetch", intel.reason);
});

test("scoreRelevance: source acceptance history shifts the score", () => {
  const t = { title: "Notes from the field" };
  const good = scoreRelevance({ ...t, sourceHistory: { accepted: 40, rejected: 2 } });
  const bad = scoreRelevance({ ...t, sourceHistory: { accepted: 1, rejected: 40 } });
  const none = scoreRelevance({ ...t, sourceHistory: { accepted: 1, rejected: 1 } });
  assert.ok(good.score > none.score && none.score > bad.score);
  assert.equal(bad.decision, "skip");
});

test("scoreRelevance: labelled fixture set precision", () => {
  let tp = 0, fp = 0, fn = 0;
  for (const f of RELEVANCE_FIXTURES) {
    const skip = scoreRelevance({ title: f.title, url: f.url }).decision === "skip";
    if (skip && f.label === "junk") tp++;
    else if (skip) fp++;
    else if (f.label === "junk") fn++;
  }
  const precision = tp / Math.max(1, tp + fp);
  const recall = tp / Math.max(1, tp + fn);
  assert.equal(fp, 0, "no real intelligence title is skipped");
  assert.ok(precision >= 0.95 && recall >= 0.85, `precision ${precision} recall ${recall}`);
  assert.equal(RELEVANCE_SKIP_THRESHOLD, 0.3);
});

// ---------------------------------------------------------------------------
// Health, backoff and schedules
// ---------------------------------------------------------------------------

test("source health: counters, backoff after repeated failures, reset on success", () => {
  let h = applyRunOutcome(null, "src_a", { jobId: "j1", at: "2025-10-01T00:00:00Z", reachable: true, counters: { fetched: 10, new: 3, accepted: 3, rejectedQuality: 2, skippedRelevance: 5, qualitySum: 2.1, qualityCount: 3 } });
  assert.equal(healthStatus(h, Date.parse("2025-10-01T01:00:00Z")), "healthy");
  assert.equal(acceptanceRatio(h.totals), 0.3);
  for (let i = 0; i < 3; i++) h = applyRunOutcome(h, "src_a", { jobId: `f${i}`, at: `2025-10-0${2 + i}T00:00:00Z`, reachable: false, counters: { failed: 1 }, error: "HTTP 503" });
  assert.equal(h.consecutiveFailures, 3);
  assert.equal(h.lastError, "HTTP 503");
  assert.equal(h.backoffUntil, "2025-10-04T02:00:00.000Z");
  assert.equal(healthStatus(h, Date.parse("2025-10-04T01:00:00Z")), "backoff");
  assert.equal(backoffMs(4), 4 * 3600_000);
  assert.equal(backoffMs(30), 7 * 24 * 3600_000);
  h = applyRunOutcome(h, "src_a", { jobId: "ok", at: "2025-10-05T00:00:00Z", reachable: true, counters: { fetched: 1 } });
  assert.equal(h.consecutiveFailures, 0);
  assert.equal(h.backoffUntil, null);
  assert.equal(h.totals.fetched, 11);
  assert.equal(h.runs, 5);
});

test("computeDue: schedule hints, never crawled and backoff", () => {
  const now = Date.parse("2025-10-10T12:00:00Z");
  assert.equal(computeDue("daily", null, null, now).dueNow, true);
  assert.equal(computeDue("daily", "2025-10-10T06:00:00Z", null, now).dueNow, false);
  assert.equal(computeDue("daily", "2025-10-10T06:00:00Z", null, now).nextDueAt, "2025-10-11T06:00:00.000Z");
  assert.equal(computeDue("hourly", "2025-10-10T10:55:00Z", null, now).dueNow, true);
  assert.equal(computeDue("weekly", "2025-10-05T12:00:00Z", null, now).dueNow, false);
  const backoff = computeDue("hourly", "2025-10-01T00:00:00Z", "2025-10-11T00:00:00Z", now);
  assert.equal(backoff.dueNow, false);
  assert.match(backoff.reason, /Backing off/);
  assert.equal(SCHEDULE_INTERVAL_MS.weekly, 7 * 86400000);
});

// ---------------------------------------------------------------------------
// Structure-preserving extraction, PDF links, entity enrichment
// ---------------------------------------------------------------------------

const REPORT_HTML = `<html><head><title>Akira ESXi intrusion | Acme Research</title></head><body>
<nav><a href="/">Home</a></nav>
<article class="post-content">
  <h1>Akira ESXi intrusion</h1>
  <p>${"The intrusion began with a VPN login using stolen credentials and moved to ESXi. ".repeat(6)}</p>
  <h2>Initial access</h2>
  <ul><li>Valid accounts on the Cisco VPN</li><li>No MFA on the appliance</li></ul>
  <h2>Execution</h2>
  <ol><li>Enumerated hosts with AdFind</li><li>Ran the encryptor</li></ol>
  <pre><code># step 1: stop VMs
esxcli vm process list
  vim-cmd vmsvc/power.off 12</code></pre>
  <h2>Indicators of compromise</h2>
  <table><thead><tr><th>Indicator</th><th>Type</th><th>Notes</th></tr></thead>
  <tbody><tr><td>185.220.101[.]44</td><td>IPv4</td><td>C2 server</td></tr>
  <tr><td>hxxps://update-cdn[.]com/a.exe</td><td>URL</td><td>Payload</td></tr>
  <tr><td>3b22605244dbace8f0c07c2c599f88c4b831bb07e9998b869a5da2759d27ceec</td><td>SHA256</td><td>Encryptor | ELF</td></tr></tbody></table>
  <p>Download the <a href="/files/akira-esxi-full-report.pdf">full report (PDF)</a> or the <a href="/files/xdr-datasheet.pdf">product datasheet</a>.</p>
</article>
<footer>FOOTER</footer></body></html>`;

test("htmlToText structured: headings, lists, code blocks and IOC tables survive", () => {
  const plain = htmlToText(REPORT_HTML);
  const s = htmlToText(REPORT_HTML, { structured: true });
  assert.equal(s.title, plain.title);
  assert.match(s.text, /^# Akira ESXi intrusion$/m);
  assert.match(s.text, /^## Initial access$/m);
  assert.match(s.text, /^- Valid accounts on the Cisco VPN$/m);
  assert.match(s.text, /^2\. Ran the encryptor$/m);
  assert.ok(s.text.includes("```\n# step 1: stop VMs\nesxcli vm process list\n  vim-cmd vmsvc/power.off 12\n```"), "code block keeps lines and indentation");
  assert.match(s.text, /^\| Indicator \| Type \| Notes \|$/m);
  assert.match(s.text, /^\| --- \| --- \| --- \|$/m);
  assert.match(s.text, /^\| 185\.220\.101\[\.\]44 \| IPv4 \| C2 server \|$/m);
  assert.ok(s.text.includes("Encryptor \\| ELF"), "pipes inside cells are escaped");
  assert.ok(!s.text.includes("FOOTER"));
  // Every plain-text prose block is still present verbatim.
  assert.ok(s.text.includes("The intrusion began with a VPN login using stolen credentials"));
  const sections = s.sections ?? [];
  assert.deepEqual(sections.map((x) => x.heading), ["Akira ESXi intrusion", "Initial access", "Execution", "Indicators of compromise"], "code comments are not headings");
  assert.deepEqual(sectionsOf("## A\ntext\n```\n# not a heading\n```\n## B"), sectionsOf("## A\ntext\n```\n# not a heading\n```\n## B"));
  const iocs = harvestIocs(s.text, { sourceDomain: "acme.com" });
  const values = iocs.map((i) => i.value);
  assert.ok(values.includes("185.220.101.44"), "defanged IP from the IOC table");
  assert.ok(values.some((v) => v.includes("update-cdn.com")), "defanged URL/domain from the IOC table");
  assert.ok(values.includes("3b22605244dbace8f0c07c2c599f88c4b831bb07e9998b869a5da2759d27ceec"));
});

test("findFullReportPdfLinks: full-report PDF found, datasheets ignored", () => {
  const links = findFullReportPdfLinks(REPORT_HTML, "https://acme.com/research/akira-esxi");
  assert.deepEqual(links.map((l) => l.url), ["https://acme.com/files/akira-esxi-full-report.pdf"]);
  assert.equal(findFullReportPdfLinks(`<a href="/brochure.pdf">Download brochure</a>`, "https://acme.com/").length, 0);
  const joined = appendPdfText("Blog body.", { url: "https://acme.com/r.pdf", text: "PDF body", pages: 12 });
  assert.match(joined, /## Full report \(PDF, 12 pages\)/);
});

test("enrichAttackEntities: canonical IDs with matched alias and first offset", () => {
  const text = "In March the actor tracked as Cozy Bear (also NOBELIUM) deployed Cobalt Strike Beacon. Later, Cozy Bear used Mimikatz.";
  const refs = enrichAttackEntities("Midnight Blizzard targets diplomats", text);
  const apt29 = refs.find((r) => r.id === "G0016");
  assert.ok(apt29, JSON.stringify(refs));
  assert.equal(apt29.kind, "group");
  assert.equal(apt29.inTitle, true);
  assert.ok(apt29.firstOffset >= 0 && text.slice(apt29.firstOffset).startsWith(apt29.matched), "offset points at the matched alias");
  const cs = refs.find((r) => r.name === "Cobalt Strike");
  assert.equal(cs?.kind, "software");
  assert.match(cs?.id ?? "", /^S\d{4}$/);
  const merged = withAttackRefs({ threatActors: ["APT29"], malwareFamilies: [], cves: [], tactics: [], techniques: [], procedures: [], detectionRules: [], mitigations: [], campaign: null }, refs);
  assert.deepEqual(merged.threatActors, ["APT29"], "heuristic fields untouched");
  assert.equal(merged.attackRefs?.length, refs.length);
});

test("normalised hash is identical for plain and structured renderings (safe revalidation of older records)", () => {
  const plain = computeFingerprints({ text: htmlToText(REPORT_HTML).text, title: "t", publisher: "p" });
  const structured = computeFingerprints({ text: htmlToText(REPORT_HTML, { structured: true }).text, title: "t", publisher: "p" });
  assert.notEqual(plain.contentSha256, structured.contentSha256);
  assert.equal(plain.normalizedTextHash, structured.normalizedTextHash);
});
