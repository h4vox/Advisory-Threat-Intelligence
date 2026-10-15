import { test } from "node:test";
import assert from "node:assert/strict";
import {
  canonicalizeUrl,
  computeReportSimHash,
  harvestIocs,
  htmlToText,
  refang,
} from "./extract.ts";

const para = (n: number, word = "telemetry") =>
  Array.from(
    { length: n },
    (_, i) => `<p>Paragraph ${i} describes ${word} and lateral movement in detail.</p>`,
  ).join("\n");

test("htmlToText: header-card <article> followed by a much larger content block", () => {
  const html = `<html><head><title>Volt Report | Microsoft Security Blog</title></head><body>
    <header><nav><a href="/">Home</a></nav></header>
    <main>
      <article class="card"><h1>Volt Report</h1><p>${"Short header card summary text. ".repeat(20)}</p></article>
      <div class="entry-content">${para(80)}<p>FINAL-SENTENCE-MARKER of the article.</p></div>
      <article data-bi-an="Related Articles"><p>RELATED-POST-MARKER should be stripped.</p></article>
    </main>
    <footer>FOOTER-MARKER</footer>
  </body></html>`;
  const { title, text } = htmlToText(html);
  assert.equal(title, "Volt Report");
  assert.ok(text.includes("FINAL-SENTENCE-MARKER"), "keeps the main content block");
  assert.ok(text.includes("Paragraph 79 describes"), "keeps late paragraphs");
  assert.ok(!text.includes("RELATED-POST-MARKER"), "strips related posts");
  assert.ok(!text.includes("FOOTER-MARKER"), "strips footer");
  assert.ok(text.length > 4000);
});

test("htmlToText: nested <article> does not truncate at the first </article>", () => {
  const html = `<html><body><article class="post">
    ${para(10, "intro")}
    <article class="embedded-quote"><p>Nested quoted article body.</p></article>
    ${para(40, "after-nested")}
    <p>END-OF-OUTER-ARTICLE</p>
  </article></body></html>`;
  const { text } = htmlToText(html);
  assert.ok(text.includes("Nested quoted article body."));
  assert.ok(text.includes("END-OF-OUTER-ARTICLE"), "content after the nested close tag is kept");
  assert.ok(text.includes("Paragraph 39 describes after-nested"));
});

test("htmlToText: <format> is not treated as <form>; entities are decoded", () => {
  const html = `<html><body><main>
    <p>Use the &lt;vCenter object&gt; &amp; &quot;quoted&quot; value &#39;x&#39; &#x2014; done&nbsp;now.</p>
    <format>KEEP-FORMAT-TEXT</format>
    <form><input value="x">FORM-MARKER</form>
    ${para(20)}
  </main></body></html>`;
  const { text } = htmlToText(html);
  assert.ok(
    text.includes(`Use the <vCenter object> & "quoted" value 'x' — done now.`),
    text.slice(0, 200),
  );
  assert.ok(text.includes("KEEP-FORMAT-TEXT"));
  assert.ok(!text.includes("FORM-MARKER"));
  assert.ok(!/&(?:amp|lt|gt|quot|#39);/.test(text));
});

test("refang", () => {
  assert.equal(refang("hxxps://evil[.]com/a[.]php"), "https://evil.com/a.php");
  assert.equal(refang("bad(.)example{.}org"), "bad.example.org");
  assert.equal(refang("evil[dot]net"), "evil.net");
  assert.equal(refang("ops[at]evil[.]com"), "ops@evil.com");
  assert.equal(refang("ops[@]evil[.]com"), "ops@evil.com");
  assert.equal(refang("http[:]//1[.]2[.]3[.]4"), "http://1.2.3.4");
});

test("harvestIocs: defanged url / domain / ip / email keep original + defanged flag", () => {
  const text =
    "The loader beaconed to hxxps://update-check[.]evil-cdn[.]com/api/v2 for command and control.\n" +
    "Stolen archives were exfiltrated to 45[.]77[.]12[.]9 over HTTPS.\n" +
    "Phishing lures were sent from billing[@]invoice-portal[.]top.\n" +
    "A second domain, staging-files[.]xyz, was also observed.";
  const iocs = harvestIocs(text);
  const find = (kind: string, value: string) =>
    iocs.find((h) => h.kind === kind && h.value === value);

  const url = find("url", "https://update-check.evil-cdn.com/api/v2");
  assert.ok(url, JSON.stringify(iocs));
  assert.equal(url.original, "hxxps://update-check[.]evil-cdn[.]com/api/v2");
  assert.equal(url.defanged, true);
  assert.equal(url.role, "C2");

  const dom = find("domain", "update-check.evil-cdn.com");
  assert.ok(dom);
  assert.equal(dom.defanged, true);

  const ip = find("ipv4", "45.77.12.9");
  assert.ok(ip);
  assert.equal(ip.original, "45[.]77[.]12[.]9");
  assert.equal(ip.defanged, true);
  assert.equal(ip.role, "exfiltration");

  const email = find("email", "billing@invoice-portal.top");
  assert.ok(email);
  assert.equal(email.defanged, true);
  assert.equal(email.role, "phishing");
  assert.equal(
    find("domain", "invoice-portal.top"),
    undefined,
    "email host is not double-reported as a domain",
  );

  const staging = find("domain", "staging-files.xyz");
  assert.ok(staging);
  assert.equal(staging.role, undefined, "no role words in that sentence");
});

test("harvestIocs: private / reserved IPs dropped unless defanged; octets validated", () => {
  const text =
    "Sample log: 10.0.0.255 connected to 192.168.1.20 and 127.0.0.1; doc range 203.0.113.7.\n" +
    "Public relay 185.220.101.4 was used. Version 2.0.0.1 shipped. Bad 300.1.2.3 value.\n" +
    "Internal pivot host 10[.]0[.]9[.]9 (defanged by the author).";
  const ips = harvestIocs(text)
    .filter((h) => h.kind === "ipv4")
    .map((h) => h.value);
  assert.deepEqual(ips.sort(), ["10.0.9.9", "185.220.101.4"]);
});

test("harvestIocs: sha1 vs sha256 vs md5 are not double counted", () => {
  const sha256 = "a".repeat(10) + "0123456789abcdef".repeat(3) + "b".repeat(6);
  const sha1 = "0123456789abcdef0123456789abcdef01234567";
  const md5 = "0123456789abcdef0123456789abcdef";
  const sha512 = "0123456789abcdef".repeat(8);
  const text = `SHA256: ${sha256}\nSHA1: ${sha1}\nMD5: ${md5}\nSHA512: ${sha512}\nAgain ${sha256.toUpperCase()}`;
  const iocs = harvestIocs(text);
  assert.equal(sha256.length, 64);
  assert.deepEqual(
    iocs
      .filter((h) => ["sha256", "sha1", "md5"].includes(h.kind))
      .map((h) => `${h.kind}:${h.value}`),
    [`sha256:${sha256}`, `sha1:${sha1}`, `md5:${md5}`],
  );
});

test("harvestIocs: file names, code identifiers, own domain and schema hosts are not domains", () => {
  const text =
    "The actor ran loader.ps1 and dropped payload.zip next to config.json and lsass.exe.\n" +
    "It calls System.IO.File and $e.target.ip in rules. See https://www.w3.org/2001/XMLSchema and schema.org.\n" +
    "Read more on https://www.microsoft.com/security/blog and learn.microsoft.com.\n" +
    "Defanged drop: payload[.]zip was served. Exfil to GoFile.io observed.";
  const domains = harvestIocs(text, {
    sourceDomain: "https://www.microsoft.com/en-us/security/blog/x",
  })
    .filter((h) => h.kind === "domain" || h.kind === "url")
    .map((h) => h.value);
  assert.deepEqual(domains.sort(), ["gofile.io", "payload.zip"]);
});

test("harvestIocs: evidence offsets are exact (text.slice(start,end) === quote)", () => {
  const text =
    "Intro line without indicators.\n\nThe group used CVE-2023-1234 for access. Then T1059.001 ran. " +
    "C2 traffic went to hxxp://c2[.]bad-actor[.]ru:8443/gate.php and 91.92.93.94!\n" +
    "| 91.92.93.94 | C2 server |\nFinal hash 0123456789abcdef0123456789abcdef seen.";
  const iocs = harvestIocs(text);
  assert.ok(iocs.length >= 6, JSON.stringify(iocs.map((h) => h.value)));
  for (const h of iocs) {
    assert.ok(h.evidence, `${h.kind} has evidence`);
    assert.equal(text.slice(h.evidence.start, h.evidence.end), h.evidence.quote);
    assert.ok(h.evidence.quote.length > 0);
    const needle = (h.original ?? h.value).toLowerCase();
    assert.ok(
      h.evidence.quote.toLowerCase().includes(needle.toLowerCase()) ||
        h.kind === "cve" ||
        h.kind === "technique",
      `${h.kind} ${needle} in quote "${h.evidence.quote}"`,
    );
  }
  const cve = iocs.find((h) => h.kind === "cve");
  assert.equal(cve?.evidence?.quote, "The group used CVE-2023-1234 for access.");
  const ip = iocs.find((h) => h.kind === "ipv4" && h.value === "91.92.93.94");
  assert.equal(ip?.role, "C2");
});

test("harvestIocs: dedupe by kind+value and cap", () => {
  const ips = Array.from({ length: 700 }, (_, i) => `45.${Math.floor(i / 250)}.${i % 250}.9`);
  const text = ips.join("\n") + "\n" + ips.join("\n");
  const iocs = harvestIocs(text);
  assert.equal(iocs.length, 500);
  assert.equal(new Set(iocs.map((h) => `${h.kind}:${h.value}`)).size, 500);
  assert.equal(harvestIocs(text, { limit: 20 }).length, 20);
});

test("canonicalizeUrl: strips tracking params, sorts query, drops fragment, lowercases host", () => {
  assert.equal(
    canonicalizeUrl(
      "https://Example.COM:443/blog/post/?utm_source=x&b=2&fbclid=abc&a=1&UTM_Medium=y&gclid=z#section",
    ),
    "https://example.com/blog/post?a=1&b=2",
  );
  assert.equal(canonicalizeUrl("http://example.com:80/"), "http://example.com/");
  assert.equal(canonicalizeUrl("https://example.com/?ref=home"), "https://example.com/");
  assert.equal(canonicalizeUrl("https://example.com/a/b/"), "https://example.com/a/b");
  // normal URLs unchanged
  assert.equal(
    canonicalizeUrl("https://www.microsoft.com/en-us/security/blog/2023/05/24/volt-typhoon/"),
    "https://www.microsoft.com/en-us/security/blog/2023/05/24/volt-typhoon",
  );
  assert.equal(
    canonicalizeUrl("https://example.com/search?q=a%20b&page=2"),
    "https://example.com/search?page=2&q=a%20b",
  );
  assert.equal(canonicalizeUrl("https://example.com:8443/x"), "https://example.com:8443/x");
});

test("computeReportSimHash: same window for near-identical texts, title excluded", () => {
  const body = Array.from(
    { length: 300 },
    (_, i) => `sentence ${i} about intrusion activity and persistence`,
  ).join(". ");
  const a = computeReportSimHash(body);
  const b = computeReportSimHash(`  ${body.replace(/\. /g, ".\n\n")}  `);
  assert.equal(a, b);
  assert.match(a, /^[0-9a-f]{16}$/);
});
