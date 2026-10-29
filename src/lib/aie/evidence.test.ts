import { test } from "node:test";
import assert from "node:assert/strict";
import { buildEvidence, classifySentence, detectSections, labelSentences, PROCEDURE_RE, splitSentences } from "./evidence.ts";
import type { Evidence, IntelEvidence } from "./types.ts";

const keptIds = (e: IntelEvidence) => e.techniques.map((t) => t.id);
const excludedIds = (e: IntelEvidence) => e.excluded.map((x) => x.techniqueId);

function allEvidence(e: IntelEvidence): Evidence[] {
  return [
    ...e.techniques.flatMap((t) => t.evidence),
    ...e.actors.flatMap((a) => a.evidence),
    ...e.malware.flatMap((m) => m.evidence),
    ...e.targeting.flatMap((t) => t.evidence),
    ...e.relationships.flatMap((r) => r.evidence),
    ...e.chain.steps.flatMap((s) => s.evidence),
    ...e.excluded.map((x) => x.evidence),
  ];
}

test("splitSentences offsets are exact (bullets, newlines, abbreviations)", () => {
  const text =
    " Introduction\n\n The actor used PowerShell. They then ran ntdsutil.exe, e.g. to copy NTDS.dit.\n•\n Block PsExec.\n • Item one • Item two\n- dash bullet here. 1) numbered item";
  const sents = splitSentences(text);
  assert.ok(sents.length >= 7);
  for (const s of sents) {
    assert.equal(text.slice(s.start, s.end), s.text);
    assert.equal(s.text, s.text.trim());
    assert.ok(!/^[•-]/.test(s.text), `bullet stripped: ${s.text}`);
  }
  assert.ok(sents.some((s) => s.text === "They then ran ntdsutil.exe, e.g. to copy NTDS.dit."));
  assert.ok(sents.some((s) => s.text === "Item one"));
  assert.ok(sents.some((s) => s.text === "dash bullet here."));
});

test("detectSections finds title-case and markdown headings, not prose or bullets", () => {
  const text =
    "Threat Actor Lifecycle\nThe actor used valid credentials to log in to the appliance and then moved laterally to vCenter.\n## Mitigations\n• Block PsExec\nDeny log on locally\n";
  const heads = detectSections(text).map((s) => s.heading);
  assert.deepEqual(heads, ["Threat Actor Lifecycle", "Mitigations"]);
});

test("defensive advice does not produce adversary techniques", () => {
  const cases: Array<[string, string]> = [
    ["Block execution of potentially obfuscated scripts.", "T1027"],
    ["Block process creations originating from PSExec and WMI commands.", "T1021.002"],
    ["Enforce local firewall rules to block inbound SMB, RDP, WinRM, PowerShell, & WMI.", "T1059.001"],
  ];
  for (const [sentence, id] of cases) {
    assert.equal(classifySentence(sentence), "defensive", sentence);
    const e = buildEvidence(sentence);
    assert.deepEqual(keptIds(e), [], sentence);
    assert.ok(excludedIds(e).includes(id), `${id} listed as excluded for: ${sentence}`);
  }
  const tamper = "Turning on tamper protection, which is part of built-in protection, prevents attackers from stopping security services.";
  assert.equal(classifySentence(tamper), "defensive");
  assert.ok(!keptIds(buildEvidence(tamper)).includes("T1562.001"));
});

test("techniques mentioned only under a remediation/hardening heading are excluded", () => {
  const text =
    "Remediation and Hardening\nRestrict administrative utilities (e.g. ntdsutil.exe, vssadmin.exe) and alert on volume shadow copy creation.\nMonitor ntdsutil usage on domain controllers.\n";
  const e = buildEvidence(text);
  assert.ok(!keptIds(e).includes("T1003.003"));
  assert.ok(e.excluded.some((x) => x.techniqueId === "T1003.003" && x.label === "defensive"));
  assert.equal(labelSentences(text).find((s) => s.text.startsWith("Monitor"))?.section, "Remediation and Hardening");
});

test("negated statements are excluded", () => {
  const s =
    "Mandiant has identified evidence of this actor operating from several other edge appliances, but could not find definitive evidence of vulnerability exploitation.";
  assert.equal(classifySentence(s), "negated");
  const e = buildEvidence(s);
  assert.ok(!keptIds(e).includes("T1190"));
  assert.ok(e.excluded.some((x) => x.techniqueId === "T1190" && x.label === "negated"));
});

test("detection rule text is excluded, including multi-line rule blocks", () => {
  const text = [
    "rule G_APT_Backdoor_BRICKSTORM_3 {",
    "  meta:",
    '    technique = "T1071.001" // Application Layer Protocol: Web Protocols',
    "  strings:",
    '    $s1 = "wssoft"',
    "  condition:",
    "    all of them",
    "}",
  ].join("\n");
  const e = buildEvidence(text);
  assert.deepEqual(keptIds(e), []);
  assert.ok(excludedIds(e).includes("T1071.001"));
  assert.equal(classifySentence('technique = "T1071.001"'), "defensive");
  assert.equal(classifySentence("| where ProcessCommandLine has_all (\"ntdsutil\", \"create full\")"), "defensive");
});

test("cleared event logs (plural) maps to T1070.001 from an observed sentence", () => {
  const s = "The attackers cleared event logs on the host.";
  assert.equal(classifySentence(s), "observed");
  const t = buildEvidence(s).techniques.find((x) => x.id === "T1070.001");
  assert.ok(t);
  assert.equal(t.label, "inferred"); // keyword-mapped from an observed sentence
  assert.equal(t.mappedBy, "keyword");
});

test("past-tense adversary action beats defensive vocabulary", () => {
  const s = "The attackers disabled Windows Defender real-time monitoring.";
  assert.equal(classifySentence(s), "observed");
  const t = buildEvidence(s).techniques.find((x) => x.id === "T1562.001");
  assert.ok(t, "T1562.001 kept");
  assert.equal(t.label, "inferred");
});

test("explicit technique IDs in observed sentences are observed; unknown IDs use the lookup", () => {
  const text = "The actor used T1059.001 to run scripts. The actor also performed T9999 activity.";
  const e = buildEvidence(text, { lookup: (id) => (id === "T9999" ? { name: "Test Technique", tactic: "Impact" } : null) });
  const ps = e.techniques.find((t) => t.id === "T1059.001");
  assert.equal(ps?.label, "observed");
  assert.equal(ps?.mappedBy, "explicit_id");
  const custom = e.techniques.find((t) => t.id === "T9999");
  assert.equal(custom?.name, "Test Technique");
  assert.equal(custom?.tactic, "Impact");
});

test("actor named only in advice is not an observed actor; generic actor patterns are found", () => {
  const s = "Organizations should follow our guidance outlined in our APT29 whitepaper to hunt for these techniques.";
  const e = buildEvidence(s);
  const apt29 = e.actors.find((a) => a.value === "APT29");
  assert.ok(apt29);
  assert.notEqual(apt29.label, "observed");
  assert.notEqual(apt29.label, "inferred");

  const e2 = buildEvidence("UNC5221 deployed BRICKSTORM backdoor on appliances. Storm-0501 used Rclone to exfiltrate data.");
  const names = e2.actors.map((a) => `${a.value}:${a.label}`);
  assert.ok(names.includes("UNC5221:observed"));
  assert.ok(names.includes("Storm-0501:observed"));
  assert.ok(e2.malware.some((m) => m.value === "BRICKSTORM" && m.label === "observed"));
});

test("relationships only come from same-sentence co-occurrence in observed sentences", () => {
  const text =
    "UNC5221 deployed the BRICKSTORM backdoor on the vCenter server. Later, the operators used Mimikatz to access LSASS. Volt Typhoon is active. Organizations should block Mimikatz used by Volt Typhoon.";
  const e = buildEvidence(text);
  const rels = e.relationships.map((r) => `${r.subject.value}|${r.predicate}|${r.object.value}`);
  assert.ok(rels.includes("UNC5221|uses|BRICKSTORM"));
  assert.ok(rels.includes("Mimikatz|performed|T1003.001"));
  // Volt Typhoon and Mimikatz co-occur only in an advice sentence.
  assert.ok(!rels.some((r) => r.startsWith("Volt Typhoon")));
  // UNC5221 never co-occurs with T1003.001.
  assert.ok(!rels.includes("UNC5221|performed|T1003.001"));
  for (const r of e.relationships) {
    assert.ok(r.confidence >= 0.6 && r.confidence <= 0.85);
    assert.equal(r.evidence.length, 1);
  }
});

test("chain follows source order, not a static tactic order", () => {
  const text =
    "The actor ran encoded PowerShell commands on the server.\nLater, the actor exploited a zero-day vulnerability in the VPN appliance.\nFinally the attackers cleared event logs.";
  const e = buildEvidence(text);
  assert.deepEqual(
    e.chain.steps.map((s) => s.tactic),
    ["Execution", "Initial Access", "Defense Evasion"],
  );
  assert.equal(e.chain.orderBasis, "reported");
  assert.deepEqual(e.chain.steps.map((s) => s.order), [1, 2, 3]);
  const one = buildEvidence("The actor ran PowerShell.");
  assert.equal(one.chain.steps.length, 1);
  assert.equal(one.chain.orderBasis, "unknown");
  const none = buildEvidence("Block PowerShell.");
  assert.equal(none.chain.steps.length, 0);
});

test("targeting status reflects what the source says", () => {
  const atRisk = buildEvidence("Organizations using Ivanti should patch immediately.");
  const ivanti = atRisk.targeting.find((t) => t.kind === "platform" && t.value === "Ivanti");
  assert.equal(ivanti?.status, "at_risk");

  const hit = buildEvidence("The actor compromised a US healthcare provider.");
  const sector = hit.targeting.find((t) => t.kind === "sector" && t.value === "healthcare");
  const geo = hit.targeting.find((t) => t.kind === "geography" && t.value === "United States");
  assert.ok(sector && ["compromised", "targeted"].includes(sector.status));
  assert.ok(geo && ["compromised", "targeted"].includes(geo.status));

  // Actor origin is not a target.
  const origin = buildEvidence("We attribute this activity to suspected China-nexus clusters targeting network appliances.");
  assert.ok(!origin.targeting.some((t) => t.kind === "geography" && t.value === "China"));
});

test("every evidence quote matches its offsets and is at most 400 chars", () => {
  const longSentence = `The actor used ${"very ".repeat(120)}long PowerShell commands and later ran ntdsutil.exe to copy NTDS.dit.`;
  const text = [
    "Threat Actor Lifecycle",
    "UNC5221 deployed BRICKSTORM backdoor on a US legal sector victim. The attackers cleared event logs.",
    longSentence,
    "Mitigations",
    "Block PsExec and enable tamper protection.",
    "There is no evidence the actor used Rclone.",
  ].join("\n");
  const e = buildEvidence(text);
  const all = allEvidence(e);
  assert.ok(all.length > 5);
  for (const ev of all) {
    assert.equal(text.slice(ev.start, ev.end), ev.quote);
    assert.ok(ev.quote.length <= 400);
  }
  const ntds = e.techniques.find((t) => t.id === "T1003.003");
  assert.ok(ntds && ntds.evidence[0].quote.includes("ntdsutil"), "long sentence windowed around the match");
});

test("classification rule lists", () => {
  assert.equal(classifySentence("For example, an attacker could use PsExec to move laterally."), "hypothetical");
  assert.equal(classifySentence("Adversaries may abuse PowerShell commands and scripts for execution."), "reference");
  assert.equal(classifySentence("The malware may be used to tunnel traffic."), "hypothetical");
  assert.equal(classifySentence("Volt Typhoon used PowerShell to enumerate hosts."), "observed");
  assert.equal(classifySentence("We recommend enabling MFA for all accounts."), "defensive");
  assert.equal(classifySentence("The actor did not deploy ransomware."), "negated");
  assert.equal(classifySentence("The actor used PsExec.", "Detection and Hunting"), "defensive");
});

test("procedure regex: net does not match inside Internet", () => {
  const re = new RegExp(PROCEDURE_RE.source, "gi");
  assert.equal("Internet traffic from edge devices and appliances".match(re), null);
  assert.ok("The actor ran net group \"domain admins\" /domain".match(new RegExp(PROCEDURE_RE.source, "gi")));
});

test("a 'Defense Evasion' heading is attacker activity, not defensive content", () => {
  assert.equal(classifySentence("The loader decodes the collector at runtime before execution.", "Defense Evasion"), "observed");
  assert.equal(classifySentence("The loader decodes the collector at runtime before execution.", "Mitigation and protection guidance"), "defensive");
  assert.equal(classifySentence("Disable macros from the internet.", "Defense Evasion"), "defensive", "advice is still advice");
});

test("rows of the report's own ATT&CK mapping table are observed; a side clause does not negate them", () => {
  assert.equal(classifySentence("T1140 Deobfuscate/Decode Files or Information | cook.py decodes and decompresses the collector at runtime.", "Detections"), "observed");
  assert.equal(
    classifySentence("T1552.005 Unsecured Credentials: Cloud Instance Metadata API | Requests AWS and GCP credentials from metadata services; returned credentials were not confirmed.", "Credential Access"),
    "observed",
  );
  assert.equal(classifySentence("T1486 Data Encrypted for Impact | Not observed in this intrusion.", "Impact"), "negated");
  assert.equal(classifySentence("tags: attack.t1059.001", "Detections"), "defensive", "rule syntax stays defensive");
});
