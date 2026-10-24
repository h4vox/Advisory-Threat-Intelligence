import { test } from "node:test";
import assert from "node:assert/strict";
import {
  BAS_CATEGORY_IDS,
  RESEARCH_CATEGORIES,
  RESEARCH_LABELS_VERSION,
  classifyResearch,
  pickResearchQueries,
  researchCoverage,
} from "./research-taxonomy.ts";

const ids = (r: ReturnType<typeof classifyResearch>) => r.labels.map((l) => l.id);

test("the taxonomy is complete and well formed", () => {
  assert.equal(RESEARCH_CATEGORIES.length, 17);
  assert.deepEqual([...BAS_CATEGORY_IDS].sort(), ["detection_content", "detection_telemetry", "emulation"]);
  for (const c of RESEARCH_CATEGORIES) {
    assert.ok(c.types.length >= 3, `${c.id} has research types`);
    assert.ok(c.queries.length >= 3, `${c.id} has discovery queries`);
    assert.ok(c.signals.every((s) => s.re.global), `${c.id} signals are global regexes`);
    assert.ok(!c.queries.some((q) => /[[\]{}]/.test(q)), `${c.id} queries have no placeholders`);
  }
});

const RANSOMWARE_INTRUSION = `
The threat actor gained initial access through a VPN appliance and moved laterally with PsExec and RDP.
They staged data with 7-Zip and exfiltrated it to cloud storage before deploying the encryptor across the domain.
The ransomware deleted shadow copies with vssadmin to inhibit recovery and left a ransom note on each host.
The group operates a data leak site for double extortion. The encryptor encrypts files with ChaCha20.
Lateral movement relied on remote services and WMI; the ransomware binary was pushed by Group Policy.`;

test("a ransomware intrusion is labelled post-compromise impact, not phishing or cloud", () => {
  const r = classifyResearch({ title: "Ransomware deployment through VPN access: lateral movement to mass encryption", text: RANSOMWARE_INTRUSION });
  assert.equal(r.version, RESEARCH_LABELS_VERSION);
  assert.equal(r.primary, "impact");
  assert.ok(!ids(r).includes("phishing"));
  assert.ok(!ids(r).includes("cloud"));
  const impact = r.labels.find((l) => l.id === "impact");
  assert.ok(impact && impact.evidence.includes("recovery inhibition"), JSON.stringify(impact));
});

test("an exploitation report is labelled exploitation, with the CVE as evidence", () => {
  const text = `We observed exploitation of CVE-2026-12345, an authentication bypass in an internet-facing edge device.
The zero-day was exploited in the wild before a patch was available. Successful exploitation leads to remote code execution.
Vulnerable versions are 9.1 through 9.4. Post-exploitation activity included a web shell.`;
  const r = classifyResearch({ title: "Zero-day exploitation of CVE-2026-12345 in edge devices", text });
  assert.equal(r.primary, "exploitation");
  assert.ok(r.labels[0].evidence.includes("CVE"));
});

test("an identity attack report is labelled identity", () => {
  const text = `The actor ran password spraying against Entra ID accounts, then used stolen refresh tokens to bypass MFA.
They added credentials to a service principal and requested Kerberos service tickets (Kerberoasting) on premises.
Privilege escalation to Global Administrator followed. Token theft gave persistent access to the tenant.`;
  const r = classifyResearch({ title: "Password spraying and token theft lead to tenant takeover", text });
  assert.equal(r.primary, "identity");
});

test("greetings, thin pages and marketing get no labels", () => {
  assert.deepEqual(ids(classifyResearch({ title: "Hello", text: "Welcome to our blog." })), []);
  const marketing = classifyResearch({
    title: "Announcing our new AI-powered security platform",
    text: "Our platform helps organizations reduce risk. Book a demo today. Customers love the new dashboard and reporting.",
  });
  assert.deepEqual(ids(marketing), []);
  assert.equal(marketing.primary, null);
});

test("lessons and trends need their defining phrase, not just loose words", () => {
  const loose = `Containment and remediation guidance: reset credentials and remediate affected hosts. Remediation steps follow.`;
  assert.ok(!ids(classifyResearch({ title: "Mitigation guidance", text: loose })).includes("lessons"));
  const review = `This post-incident review covers the root cause, the detection gaps and missed alerts, and the lessons learned.
Containment took two days and eradication a week. The breach investigation found the root cause in an exposed VPN.`;
  assert.ok(ids(classifyResearch({ title: "Post-incident review: lessons learned from the breach", text: review })).includes("lessons"));
  const trend = classifyResearch({
    title: "2025 Zero-Days in Review",
    text: "This retrospective covers the year: exploitation of edge devices rose 30% compared to last year. Trends show more enterprise targeting. Annual figures follow.",
  });
  assert.ok(ids(trend).includes("trends"), JSON.stringify(trend));
});

test("BAS labels never push core labels off the list", () => {
  const text = `${RANSOMWARE_INTRUSION}
Microsoft Defender XDR customers can run the following advanced hunting queries. Threat hunting with KQL:
DeviceProcessEvents
| where FileName =~ "vssadmin.exe"
| where ProcessCommandLine has "delete shadows"
DeviceNetworkEvents
| where RemotePort == 445
| summarize count() by DeviceName
Detection engineering note: the telemetry comes from Sysmon Event ID 1 and the Security log.`;
  const r = classifyResearch({ title: "Ransomware intrusion with hunting queries", text });
  const core = r.labels.filter((l) => !BAS_CATEGORY_IDS.includes(l.id));
  const bas = r.labels.filter((l) => BAS_CATEGORY_IDS.includes(l.id));
  assert.ok(core.length >= 1 && core[0].id === "impact", JSON.stringify(r.labels));
  assert.ok(bas.some((l) => l.id === "detection_content"), "queries in the text are detection content");
  assert.ok(core.length <= 4 && bas.length <= 2);
  assert.equal(r.primary, "impact", "the primary label is a core one");
});

test("detection content needs a rule or query in the text, not just the words", () => {
  const words = "We wrote Sigma rules and YARA rules for this. Detection rules are available to customers. Sigma rules help.";
  assert.ok(!ids(classifyResearch({ title: "Detection rules", text: words })).includes("detection_content"));
});

test("discovery: half the queries go to the thinnest categories, the rest rotate, no duplicates", () => {
  const counts = Object.fromEntries(RESEARCH_CATEGORIES.map((c) => [c.id, 50])) as Record<string, number>;
  counts.c2 = 0;
  counts.identity = 1;
  counts.lessons = 0; // thin by nature: never boosted
  const picks = pickResearchQueries({ round: 3, count: 8, counts });
  assert.equal(picks.length, 8);
  assert.equal(new Set(picks.map((p) => p.query)).size, 8, "no duplicate queries");
  assert.equal(picks[0].category, "c2");
  assert.equal(picks[1].category, "identity");
  assert.ok(picks.slice(0, 4).every((p) => p.category !== "lessons"), "lessons never takes a gap slot");
  assert.ok(picks.every((p) => !BAS_CATEGORY_IDS.includes(p.category)), "BAS is off by default");
});

test("discovery: over successive runs every enabled category and many queries are searched", () => {
  const categories = new Set<string>();
  const queries = new Set<string>();
  for (let round = 0; round < 12; round++) {
    for (const p of pickResearchQueries({ round, count: 6 })) {
      categories.add(p.category);
      queries.add(p.query);
    }
  }
  const core = RESEARCH_CATEGORIES.filter((c) => c.scope === "core").map((c) => c.id);
  assert.deepEqual([...categories].sort(), [...core].sort());
  assert.ok(queries.size >= 40, `${queries.size} distinct queries`);
});

test("discovery: BAS categories can be enabled one by one", () => {
  const seen = new Set<string>();
  for (let round = 0; round < 20; round++) for (const p of pickResearchQueries({ round, count: 6, includeBas: ["emulation"] })) seen.add(p.category);
  assert.ok(seen.has("emulation"));
  assert.ok(!seen.has("detection_content") && !seen.has("detection_telemetry"));
  assert.deepEqual(pickResearchQueries({ round: 0, count: 0 }), []);
});

test("coverage counts labelled reports per category", () => {
  const cov = researchCoverage([
    { research: { labels: [{ id: "malware" }, { id: "c2" }] } },
    { research: { labels: [{ id: "malware" }] } },
    { research: null },
    {},
  ]);
  assert.equal(cov.counts.malware, 2);
  assert.equal(cov.counts.c2, 1);
  assert.equal(cov.counts.cloud, 0);
  assert.equal(cov.labelled, 2);
  assert.equal(cov.total, 4);
});
