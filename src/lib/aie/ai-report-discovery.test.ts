import { test } from "node:test";
import assert from "node:assert/strict";
import { buildReportDiscoveryPrompt, parseReportSuggestions } from "./ai-report-discovery.ts";

test("the prompt names the topics, the date and the publishers already followed", () => {
  const p = buildReportDiscoveryPrompt({ topics: [{ query: "YARA rules malware family analysis", category: "detection_content" }], since: "2026-07-01", knownDomains: ["thedfirreport.com"], webSearch: true, max: 10 });
  assert.match(p, /Search the web for/);
  assert.match(p, /2026-07-01/);
  assert.match(p, /YARA rules malware family analysis \[category: detection_content\]/);
  assert.match(p, /thedfirreport\.com/);
  assert.match(buildReportDiscoveryPrompt({ topics: [], since: "2026-07-01", knownDomains: [], webSearch: false, max: 5 }), /confident exist/);
});

test("article URLs are kept; homepages, search pages and social posts are dropped", () => {
  const r = parseReportSuggestions(
    {
      reports: [
        { url: "https://www.example-sec.com/blog/2026/10/loader-analysis", title: "Loader", publisher: "Example Sec", published: "2026-10-12", category: "malware", why: "TTPs" },
        { url: "https://www.example-sec.com/blog/2026/10/loader-analysis", title: "dup" },
        { url: "https://www.example-sec.com/", title: "home" },
        { url: "https://example-sec.com/blog", title: "listing" },
        { url: "https://twitter.com/someone/status/1", title: "tweet" },
        { url: "https://www.google.com/search?q=x", title: "search" },
        { url: "https://vertexaisearch.cloud.google.com/grounding-api-redirect/abc", title: "redirect" },
        { url: "ftp://files.example/x.pdf", title: "ftp" },
        { url: "not a url" },
        { url: "https://cert.example.gov/advisories/aa26-123a.pdf", title: "Advisory", published: "soon", category: "made_up" },
      ],
      sources: [
        { domain: "https://www.newlab.example/research", name: "New Lab", why: "malware research" },
        { domain: "thedfirreport.com", name: "known" },
        { domain: "x.com", name: "social" },
        { domain: "not a domain" },
      ],
    },
    { categories: ["malware"], knownDomains: ["thedfirreport.com"] },
  );
  assert.deepEqual(r.reports.map((x) => x.url), ["https://www.example-sec.com/blog/2026/10/loader-analysis", "https://cert.example.gov/advisories/aa26-123a.pdf"]);
  assert.equal(r.reports[0].category, "malware");
  assert.equal(r.reports[0].published, "2026-10-12");
  assert.equal(r.reports[1].published, null);
  assert.equal(r.reports[1].category, undefined);
  assert.equal(r.dropped, 8);
  assert.deepEqual(r.sources.map((s) => s.domain), ["newlab.example"]);
});

test("an answer that is not the expected shape gives nothing", () => {
  assert.deepEqual(parseReportSuggestions("text", {}), { reports: [], sources: [], dropped: 0 });
  assert.deepEqual(parseReportSuggestions({ reports: "x" }, {}), { reports: [], sources: [], dropped: 0 });
});

test("the number of reports is capped", () => {
  const many = { reports: Array.from({ length: 40 }, (_, i) => ({ url: `https://lab.example/r/${i}` })) };
  assert.equal(parseReportSuggestions(many, { max: 10 }).reports.length, 10);
});
