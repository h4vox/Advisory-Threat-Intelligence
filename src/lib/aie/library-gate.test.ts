import { test } from "node:test";
import assert from "node:assert/strict";
import { evaluateLibraryReport, gateReasonLine, type GateInput } from "./library-gate.ts";

const base: GateInput = {
  title: "",
  url: "",
  summary: "",
  wordCount: 1500,
  iocCount: 0,
  techniques: 0,
  cves: 0,
  attackChainSteps: 0,
  entities: 0,
  qualityScore: 0.4,
};
const r = (over: Partial<GateInput>) => evaluateLibraryReport({ ...base, ...over });

test("keeps real threat reports", () => {
  for (const over of [
    { title: "Volt Typhoon targets US critical infrastructure with living-off-the-land techniques", url: "https://www.cisa.gov/news-events/cybersecurity-advisories/aa24-038a" },
    { title: "Inside a BlackCat ransomware intrusion: from initial access to exfiltration", url: "https://thedfirreport.com/2024/01/01/blackcat/" },
    { title: "CVE-2024-3400: exploitation of PAN-OS GlobalProtect", url: "https://unit42.paloaltonetworks.com/cve-2024-3400/" },
    { title: "Quarterly threat trends", url: "https://vendor.example/research/q2-trends", summary: "We tracked phishing campaigns and new loaders used by several threat actors." },
  ]) {
    const v = r(over);
    assert.equal(v.verdict, "keep", `${over.title} → ${v.reasons.join("; ")}`);
  }
});

test("hides off-topic marketing, events, hiring and earnings posts", () => {
  const cases: Array<[Partial<GateInput>, RegExp]> = [
    [{ title: "Join our webinar: securing the modern SOC", url: "https://vendor.example/blog/webinar-modern-soc" }, /webinar/],
    [{ title: "Acme named a Leader in the 2025 Gartner Magic Quadrant", url: "https://vendor.example/blog/acme-leader-gartner" }, /award/],
    [{ title: "We're hiring: join the team as a security engineer", url: "https://vendor.example/blog/we-are-hiring" }, /hiring/],
    [{ title: "Acme announces Q3 2025 financial results", url: "https://vendor.example/blog/q3-results" }, /earnings|announcement/],
    [{ title: "Podcast episode 42: the year in review", url: "https://vendor.example/blog/episode-42" }, /podcast/],
    [{ title: "Introducing Acme XDR 5.0: now available with new features", url: "https://vendor.example/blog/xdr-5" }, /product launch/],
  ];
  for (const [over, re] of cases) {
    const v = r(over);
    assert.equal(v.verdict, "reject", `${over.title} should be hidden`);
    assert.equal(v.rule, "topic");
    assert.match(v.reasons.join(" "), re, over.title);
  }
});

test("hides pages that are not single reports", () => {
  const cases: Array<[Partial<GateInput>, RegExp]> = [
    [{ title: "Acme Security", url: "https://www.acme.example/" }, /homepage/],
    [{ title: "Acme Security", url: "https://www.acme.example/en-us/" }, /homepage/],
    [{ title: "Sitemap", url: "https://www.acme.example/sitemap.xml" }, /Not an article|Sitemap/],
    [{ title: "Threat research blog", url: "https://www.acme.example/blog/" }, /Listing/],
    [{ title: "Ransomware archives", url: "https://www.acme.example/tag/ransomware/" }, /listing/],
    [{ title: "Older posts", url: "https://www.acme.example/category/research/page/3" }, /listing/],
    [{ title: "Privacy Policy", url: "https://www.acme.example/legal/privacy-policy" }, /Not an article|utility/],
    [{ title: "Page not found", url: "https://www.acme.example/blog/some-post" }, /Not an article/],
    [{ title: "Results", url: "https://www.acme.example/?s=lockbit" }, /Search/],
    [{ title: "Alerts & advisories", url: "https://www.cisa.gov/news-events/cybersecurity-advisories?f%5B0%5D=type%3A1" }, /Search or filter/],
    [{ title: "E-Verify", url: "https://www.e-verify.gov/employers" }, /Government service/],
  ];
  for (const [over, re] of cases) {
    const v = r(over);
    assert.equal(v.verdict, "reject", `${over.url} should be hidden`);
    assert.equal(v.rule, "page_type");
    assert.match(v.reasons[0], re, over.url);
  }
});

test("hides stubs only when the word count is known", () => {
  assert.equal(r({ title: "Update", url: "https://vendor.example/blog/update", wordCount: 40 }).rule, "stub");
  assert.equal(r({ title: "Update", url: "https://vendor.example/blog/update", wordCount: 0 }).verdict, "keep");
  assert.equal(r({ title: "Update", url: "https://vendor.example/blog/update", wordCount: 40, iocCount: 1 }).verdict, "keep");
});

test("threat evidence protects an article, but not a structural non-report", () => {
  // On a real article URL, any one piece of threat evidence keeps it.
  const article = { title: "APT29 campaign analysis", url: "https://vendor.example/blog/apt29-campaign-analysis" };
  for (const over of [{ techniques: 3 }, { cves: 1 }, { iocCount: 5 }, { attackChainSteps: 4 }, { entities: 1 }, { qualityScore: 0.82 }, { structured: true }, { keep: true }]) {
    const v = r({ ...article, ...over });
    assert.equal(v.verdict, "keep", JSON.stringify(over));
    assert.ok(v.protectedBy.length > 0);
  }
});

test("a homepage / listing page is a hard reject even when its snippets name threats", () => {
  // A listing page's fragments name actors and techniques, but it is not a report. Only an analyst
  // Restore, a structured record, or a genuinely high quality score overrides the page-type reject.
  const home = { title: "Join our webinar", url: "https://vendor.example/" };
  for (const over of [{ techniques: 3 }, { cves: 2 }, { iocCount: 5 }, { attackChainSteps: 4 }, { entities: 3 }]) {
    assert.equal(r({ ...home, ...over }).verdict, "reject", JSON.stringify(over));
    assert.equal(r({ ...home, ...over }).rule, "page_type");
  }
  assert.equal(r({ ...home, structured: true }).verdict, "keep");
  assert.equal(r({ ...home, keep: true }).verdict, "keep");
  assert.equal(r({ ...home, qualityScore: 0.82 }).verdict, "keep");
});

test("a topic/section landing page is rejected even with a real-looking article title", () => {
  // The WeLiveSecurity case: /en/ransomware is a section listing; its featured-article title and the
  // T1486 + LockBit its snippets contain must not rescue it.
  const v = r({ title: "Ransomware protection: tips to defend against data hijacking", url: "https://www.welivesecurity.com/en/ransomware", techniques: 1, entities: 1, qualityScore: 0.0 });
  assert.equal(v.verdict, "reject");
  assert.equal(v.rule, "page_type");
  assert.match(v.reasons[0], /section|listing/i);
  // A real article with a descriptive slug under the same site is kept.
  assert.equal(r({ title: "SparrowDoor analysis", url: "https://www.welivesecurity.com/en/eset-research/sparrowdoor-backdoor-analysis", techniques: 2 }).verdict, "keep");
});

test("reason line for the library", () => {
  const v = r({ title: "Join our webinar: securing the modern SOC", url: "https://vendor.example/blog/webinar-modern-soc" });
  assert.match(gateReasonLine(v), /^Hidden as unrelated: Off-topic: webinar/);
});
