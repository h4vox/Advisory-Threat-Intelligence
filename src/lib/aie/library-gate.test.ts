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

test("threat evidence, structured sources and analyst keeps always protect", () => {
  const webinarHome = { title: "Join our webinar", url: "https://vendor.example/" };
  for (const over of [
    { techniques: 3 },
    { cves: 1 },
    { iocCount: 5 },
    { attackChainSteps: 4 },
    { entities: 1 },
    { qualityScore: 0.82 },
    { structured: true },
    { keep: true },
  ]) {
    const v = r({ ...webinarHome, ...over });
    assert.equal(v.verdict, "keep", JSON.stringify(over));
    assert.ok(v.protectedBy.length > 0);
  }
  // One stray indicator is not enough to protect a homepage.
  assert.equal(r({ ...webinarHome, iocCount: 1 }).verdict, "reject");
});

test("reason line for the library", () => {
  const v = r({ title: "Join our webinar: securing the modern SOC", url: "https://vendor.example/blog/webinar-modern-soc" });
  assert.match(gateReasonLine(v), /^Hidden as unrelated: Off-topic: webinar/);
});
