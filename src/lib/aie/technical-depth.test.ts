import { test } from "node:test";
import assert from "node:assert/strict";
import { articleProse, assessTechnicalDepth, detectLanguage } from "./technical-depth.ts";
import { qualifyContent } from "./qualification.ts";
import {
  CAMPAIGN_SUMMARY,
  GOVERNMENT_ADVISORY,
  INDICATOR_APPENDIX,
  NEWS_REWRITE,
  NON_ENGLISH,
  PRODUCT_PAGE,
  STRATEGIC_ASSESSMENT,
} from "./__fixtures__/depth-samples.ts";

test("articleProse drops link-only lines (menus, footers, resource lists) and keeps text", () => {
  const prose = articleProse(PRODUCT_PAGE.text);
  assert.ok(!prose.includes("Threat Intel and Incident Response Services"), "footer link list is not content");
  assert.ok(!prose.includes("Request demo"), "a call-to-action link line is not content");
  assert.ok(prose.includes("Overprivileged users and applications"), "prose stays");
  // A link inside a sentence keeps its label.
  assert.equal(articleProse("Read the [full report](https://x.example/r) for details."), "Read the full report for details.");
});

test("the reported product page is rejected as marketing, despite 'lateral movement', 'ransomware' and ATT&CK", () => {
  const v = assessTechnicalDepth(PRODUCT_PAGE);
  assert.equal(v.pass, false);
  assert.equal(v.kind, "product_marketing");
  assert.match(v.reasons[0], /Product or marketing page/);
  // The crawler's qualifier used to approve it (72%, INTRUSION_REPORT from the footer).
  const q = qualifyContent(PRODUCT_PAGE.text, PRODUCT_PAGE.title, PRODUCT_PAGE.url);
  assert.equal(q.qualified, false);
  assert.match(q.rejectionReason ?? "", /Product or marketing page/);
});

test("strategic assessments and news rewrites are rejected with the reason", () => {
  const strategic = assessTechnicalDepth(STRATEGIC_ASSESSMENT);
  assert.equal(strategic.pass, false);
  assert.equal(strategic.kind, "strategic");

  const news = assessTechnicalDepth(NEWS_REWRITE);
  assert.equal(news.pass, false);
  assert.equal(news.kind, "news");
  assert.match(news.reasons[0], /News coverage without technical detail/);
});

test("a government advisory on an exploited CVE passes; the same facts in a news rewrite do not", () => {
  const advisory = assessTechnicalDepth(GOVERNMENT_ADVISORY);
  assert.equal(advisory.pass, true, advisory.reasons.join("; "));
  assert.ok(advisory.anchors.some((a) => /exploited CVE/.test(a)));
  assert.equal(assessTechnicalDepth(NEWS_REWRITE).pass, false);
});

test("described attacker activity by a named actor passes without indicators", () => {
  const v = assessTechnicalDepth(CAMPAIGN_SUMMARY);
  assert.equal(v.pass, true, v.reasons.join("; "));
  assert.deepEqual(v.stats.actors, ["UNC9999"]);
  assert.ok(v.stats.behaviours.length >= 5, v.stats.behaviours.join(", "));
});

test("indicators and technique IDs are hard evidence; defanged values count, private and version-like numbers do not", () => {
  const v = assessTechnicalDepth(INDICATOR_APPENDIX);
  assert.equal(v.pass, true);
  assert.equal(v.stats.techniques, 2);
  assert.equal(v.stats.indicators, 5, "2 hashes, 2 IPs (one defanged), 1 defanged domain");

  const noise = assessTechnicalDepth({
    title: "Release notes",
    url: "https://vendor.example/blog/release-notes-update",
    text: "Upgrade to version 10.2.3.4 today. The appliance listens on 192.168.1.10 and 10.0.0.5 by default. ".repeat(4),
  });
  assert.equal(noise.stats.indicators, 0);
  assert.equal(noise.pass, false);
});

test("a non-English page without hard evidence waits for translation instead of being judged", () => {
  const v = assessTechnicalDepth(NON_ENGLISH);
  assert.equal(v.pass, false);
  assert.equal(v.kind, "non_english");
  assert.equal(v.language, "pl");
});

test("detectLanguage: English by stopwords, others by script and common words", () => {
  assert.equal(detectLanguage(CAMPAIGN_SUMMARY.text).lang, "en");
  assert.equal(detectLanguage(NON_ENGLISH.text).lang, "pl");
  assert.equal(detectLanguage("Die Angreifer nutzen die Schwachstelle und werden nicht gestoppt, weil die Systeme mit alten Versionen und ohne Updates laufen. Die Betreiber werden aufgefordert, die Updates mit hoher Priorität einzuspielen und die Systeme nicht ungeschützt zu lassen, denn die Lücke wird mit hoher Wahrscheinlichkeit weiter ausgenutzt und die Folgen sind nicht absehbar.").lang, "de");
  assert.equal(detectLanguage("攻撃者は脆弱性を悪用して、システムに不正にアクセスしました。このキャンペーンは、複数の組織を標的にしています。").lang, "ja");
});
