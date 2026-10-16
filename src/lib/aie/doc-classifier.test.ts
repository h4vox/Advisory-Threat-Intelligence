import { test } from "node:test";
import assert from "node:assert/strict";
import { annotateReportProvenance, classifyDocument, confidenceClassFor, tierFor } from "./doc-classifier.ts";

const filler = (s: string, n: number) => Array.from({ length: n }, () => s).join(" ");

test("CISA joint advisory id and CVE density → THREAT_ADVISORY + VULNERABILITY_ADVISORY", () => {
  const text =
    "CISA, FBI and NSA are releasing this joint advisory. Threat actors exploited CVE-2024-3400, CVE-2023-46805 and CVE-2024-21887 " +
    "to gain access. The vulnerabilities were exploited before a patch was available; exploitation continued after patches were released.";
  const r = classifyDocument({
    title: "AA24-060B: Threat Actors Exploit Multiple Vulnerabilities in Ivanti Connect Secure",
    url: "https://www.cisa.gov/news-events/cybersecurity-advisories/aa24-060b",
    text,
    sourceYields: ["THREAT_ADVISORY", "VULNERABILITY_ADVISORY"],
    sourceTier: 1,
  });
  assert.equal(r.docTypes[0], "THREAT_ADVISORY");
  assert.ok(r.docTypes.includes("VULNERABILITY_ADVISORY"), r.docTypes.join(","));
  assert.ok(r.signals.find((s) => s.docType === "THREAT_ADVISORY")?.reason);
});

test("DFIR intrusion timeline → DFIR_REPORT / INCIDENT_REPORT", () => {
  const text =
    filler("On day 1 the threat actor then ran discovery commands, hands-on-keyboard activity followed and lateral movement to the domain controller occurred.", 3) +
    " The time to ransom (TTR) was 4 days. Our incident response and forensic analysis of the intrusion found the initial access broker sold access. " +
    filler("The intrusion compromised the victim network.", 8);
  const r = classifyDocument({
    title: "From Bing Search to Ransomware: Bumblebee and AdaptixC2 Deliver Akira",
    url: "https://thedfirreport.com/2026/06/29/from-bing-search-to-ransomware/",
    text,
    sourceYields: ["DFIR_REPORT", "INCIDENT_REPORT"],
  });
  assert.equal(r.docTypes[0], "DFIR_REPORT");
  assert.ok(r.docTypes.includes("INCIDENT_REPORT"));
});

test("malware family analysis → MALWARE_REPORT", () => {
  const text = filler(
    "The loader decrypts the payload with string decryption, unpacking a backdoor. The sample's C2 configuration and SHA256 were extracted after we reverse engineered the variant.",
    4,
  );
  const r = classifyDocument({ title: "Inside the new LummaC2 stealer variant", url: "https://example-vendor.com/research/lumma", text });
  assert.equal(r.docTypes[0], "MALWARE_REPORT");
});

test("campaign wording → CAMPAIGN_REPORT; generic text falls back to THREAT_REPORT", () => {
  const c = classifyDocument({
    title: "Operation Silent Harbor: a phishing campaign against shipping firms",
    url: "https://x.example/blog/silent-harbor",
    text: filler("The campaign used lures; this cluster of activity overlapped with an earlier campaign.", 3),
  });
  assert.ok(c.docTypes.includes("CAMPAIGN_REPORT"));
  const g = classifyDocument({ title: "Quarterly notes", url: "https://x.example/notes", text: "Some general security notes." });
  assert.deepEqual(g.docTypes, ["THREAT_REPORT"]);
});

test("structured kinds decide outright", () => {
  assert.deepEqual(classifyDocument({ title: "APT29", url: "https://attack.mitre.org/groups/G0016", structuredKind: "attack_group" }).docTypes, ["MITRE_GROUP"]);
  assert.deepEqual(classifyDocument({ title: "x", url: "https://x", structuredKind: "attack_flow" }).docTypes, ["ATTACK_FLOW"]);
  assert.deepEqual(classifyDocument({ title: "x", url: "https://x", structuredKind: "kev" }).docTypes, ["KEV_ENTRY"]);
});

test("detection and hunting research", () => {
  const r = classifyDocument({
    title: "Hunting for DLL side-loading with Sigma and KQL",
    url: "https://redcanary.com/blog/threat-detection/dll-sideloading",
    text: filler("This Sigma detection rule and KQL hunting query support threat hunting; detection opportunities follow.", 3),
  });
  assert.ok(r.docTypes.includes("DETECTION_RESEARCH"), r.docTypes.join(","));
  assert.ok(r.docTypes.includes("THREAT_HUNTING_REPORT"), r.docTypes.join(","));
});

test("confidence classes and tiers", () => {
  assert.equal(confidenceClassFor({ confidenceClass: "RESEARCH_ORG" }), "RESEARCH_ORG");
  assert.equal(confidenceClassFor({ trustLevel: "official", tier: 1 }), "OFFICIAL_PRIMARY");
  assert.equal(confidenceClassFor({ trustLevel: "high" }), "TRUSTED_VENDOR");
  assert.equal(confidenceClassFor({ isDiscovered: true, trustLevel: "community" }), "COMMUNITY");
  assert.equal(confidenceClassFor(undefined), "UNKNOWN");
  assert.equal(tierFor({ isDiscovered: true }), 4);
  assert.equal(tierFor({ tier: 2 }), 2);
  assert.equal(tierFor({ trustLevel: "high" }), 3);
});

test("annotateReportProvenance multiplies class weight by quality and explains it", () => {
  const p = annotateReportProvenance({
    source: { tier: 3, confidenceClass: "TRUSTED_VENDOR", yields: ["MALWARE_REPORT"] },
    title: "New backdoor analysis",
    url: "https://vendor.example/backdoor",
    text: "The backdoor sample decrypts its payload.",
    qualityScore: 80,
    qualityReasons: [{ label: "Long-form", delta: 10 }],
  });
  assert.equal(p.sourceTier, 3);
  assert.equal(p.sourceConfidence, 0.72);
  assert.ok(p.docTypes.includes("MALWARE_REPORT"));
  assert.equal(p.qualityReasons[0].label, "Long-form");
  assert.match(p.qualityReasons[1].label, /TRUSTED_VENDOR ×0\.90 \(tier 3\) × quality 0\.80 = 0\.72/);
  // Re-annotating replaces, not duplicates, the provenance reasons.
  const again = annotateReportProvenance({ ...p, source: { tier: 3, confidenceClass: "TRUSTED_VENDOR" }, title: "x", url: "https://x", text: "", qualityScore: 80, qualityReasons: p.qualityReasons });
  assert.equal(again.qualityReasons.filter((r) => r.label.startsWith("Source confidence")).length, 1);
});
