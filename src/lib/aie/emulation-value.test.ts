import { test } from "node:test";
import assert from "node:assert/strict";
import { assessEmulationValue } from "./emulation-value.ts";
import { assessTechnicalDepth } from "./technical-depth.ts";
import { BREACH_NEWS, CLICKFIX_CHAIN, PATCH_NOTICE, PATCH_NOTICE_WITH_BACKGROUND, SIDELOADING_PROCEDURE } from "./__fixtures__/emulation-samples.ts";
import { CAMPAIGN_SUMMARY, GOVERNMENT_ADVISORY, PRODUCT_PAGE } from "./__fixtures__/depth-samples.ts";

test("an infection-chain write-up grades as an attack chain, with its steps quoted in order", () => {
  const v = assessEmulationValue(CLICKFIX_CHAIN);
  assert.equal(v.grade, "chain", JSON.stringify(v.stats));
  assert.ok(v.score >= 60, String(v.score));
  const msi = v.steps.findIndex((s) => /IconEdit2Turb\.msi/.test(s));
  const sideload = v.steps.findIndex((s) => /DeElevator64\.dll/.test(s));
  assert.ok(msi >= 0 && sideload > msi, v.steps.join("\n"));
  assert.ok(v.novelty.length >= 1, "a 'new … delivery platform' is a novelty statement");
});

test("a side-loading walk-through grades as an attack chain", () => {
  const v = assessEmulationValue(SIDELOADING_PROCEDURE);
  assert.equal(v.grade, "chain", JSON.stringify(v.stats));
  assert.ok(v.steps.some((s) => /jli\.dll/.test(s)));
});

test("a patch notice is news, however many version numbers it lists", () => {
  const v = assessEmulationValue(PATCH_NOTICE);
  assert.equal(v.grade, "news", JSON.stringify(v.stats));
  assert.ok(v.score < 25, String(v.score));
  // Version numbers are not IP indicators either.
  const asa = "Cisco fixed the flaw in ASA Software releases 9.18.4.47 and 9.20.2.10; customers on 9.16.4.55 or earlier should upgrade.";
  assert.equal(assessTechnicalDepth({ title: "Cisco ASA patch", url: "https://brandefense.io/security-news/cisco-asa", text: asa }).stats.indicators, 0);
  assert.equal(assessTechnicalDepth({ title: "C2", url: "https://x.example/r", text: "The implant connects to its C2 server at 45.77.12.9 and 103.21.4.18 over HTTPS." }).stats.indicators, 2);
  assert.equal(assessTechnicalDepth({ ...PATCH_NOTICE, url: "https://brandefense.io/security-news/veeam-backup-replication-cve-2026-108142-patch" }).stats.indicators, 0);
});

test("breach news and product pages are news", () => {
  assert.equal(assessEmulationValue(BREACH_NEWS).grade, "news");
  assert.equal(assessEmulationValue(PRODUCT_PAGE).grade, "news");
});

test("a campaign summary with behaviour but no procedures is context; an advisory is not graded a chain", () => {
  const c = assessEmulationValue(CAMPAIGN_SUMMARY);
  assert.equal(c.grade, "context", JSON.stringify(c.stats));
  assert.notEqual(assessEmulationValue(GOVERNMENT_ADVISORY).grade, "chain");
});

test("the library gate hides a vendor patch notice as low emulation value, but not a CERT advisory or an analyst's Restore", async () => {
  const { evaluateLibraryReport } = await import("./library-gate.ts");
  const base = { wordCount: 160, iocCount: 0, techniques: 0, cves: 1, attackChainSteps: 0, entities: 0, qualityScore: 0.5 };
  assert.equal(assessTechnicalDepth({ ...PATCH_NOTICE_WITH_BACKGROUND, url: "https://brandefense.io/x" }).pass, true, "background on earlier attacks passes the depth check");
  assert.equal(assessEmulationValue(PATCH_NOTICE_WITH_BACKGROUND).grade, "news");
  const notice = evaluateLibraryReport({ ...base, ...PATCH_NOTICE_WITH_BACKGROUND, url: "https://brandefense.io/security-news/veeam-backup-replication-cve-2026-108142-patch" });
  assert.equal(notice.verdict, "reject");
  assert.equal(notice.rule, "low_value");
  assert.equal(evaluateLibraryReport({ ...base, ...PATCH_NOTICE_WITH_BACKGROUND, url: "https://www.cisa.gov/news-events/alerts/2026/veeam" }).verdict, "keep");
  assert.equal(evaluateLibraryReport({ ...base, ...PATCH_NOTICE_WITH_BACKGROUND, url: "https://brandefense.io/x", keep: true }).verdict, "keep");
  const chain = evaluateLibraryReport({ ...base, ...CLICKFIX_CHAIN, url: "https://www.forescout.com/blog/romulus" });
  assert.equal(chain.verdict, "keep");
  assert.equal(chain.emulation?.grade, "chain");
});
