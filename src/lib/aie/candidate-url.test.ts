import { test } from "node:test";
import assert from "node:assert/strict";
import { isCandidateResourceUrl } from "./qualification.ts";

test("paginated listings are not resources, even from a feed", () => {
  for (const u of [
    "https://www.microsoft.com/en-us/security/blog/threat-intelligence/ransomware?paged=2",
    "https://unit42.paloaltonetworks.com/new-loader-analysis/?page=3",
    "https://example-research.org/research/archive-of-reports?start=40",
  ]) {
    assert.equal(isCandidateResourceUrl(u, true).isResource, false, u);
  }
});

test("Microsoft Security Blog topic listings are not resources; its dated articles are", () => {
  assert.equal(isCandidateResourceUrl("https://www.microsoft.com/en-us/security/blog/threat-intelligence/ransomware/", true).isResource, false);
  assert.equal(isCandidateResourceUrl("https://www.microsoft.com/en-us/security/blog/content-type/research/", true).isResource, false);
  assert.equal(
    isCandidateResourceUrl("https://www.microsoft.com/en-us/security/blog/2026/09/25/storm-3168-agentic-driven-cloud-attacks-using-compromised-service-principals/", true).isResource,
    true,
  );
  assert.equal(isCandidateResourceUrl("https://thedfirreport.com/2026/05/12/from-icedid-to-ransomware/").isResource, true);
});
