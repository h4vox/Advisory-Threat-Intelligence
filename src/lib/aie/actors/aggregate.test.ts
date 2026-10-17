import { test } from "node:test";
import assert from "node:assert/strict";
import {
  actorKpis,
  actorProfile,
  actorRow,
  buildActorIndex,
  filterActors,
  findActor,
  isNewVsAttack,
  resolveActorName,
  slugifyActor,
  sortActorRows,
  suggestActors,
  type ActorSourceReport,
  type EmulationContext,
} from "./aggregate.ts";
import type { IntelAnalysis } from "../types.ts";

const NOW = Date.parse("2026-10-16T00:00:00Z");

function analysis(p: Partial<IntelAnalysis>): IntelAnalysis {
  return {
    method: "heuristic",
    classification: "THREAT_REPORT",
    threatActors: [],
    malware: [],
    vulnerabilities: [],
    ttps: [],
    ioas: [],
    attackChain: [],
    detections: [],
    hunting: [],
    emulation: [],
    ...p,
  };
}

const ev = (quote: string) => ({ quote, start: 0, end: quote.length });

const akira: ActorSourceReport = {
  id: "r_akira",
  title: "SEO-poisoned installer to Akira ransomware",
  excerpt: "An intrusion that ended in Akira deployment.",
  publisher: "The DFIR Report",
  publishedAt: "2026-06-29",
  ingestedAt: "2026-07-01T00:00:00Z",
  status: "acquired",
  discoveryMethod: "seed",
  iocs: [{ kind: "cve", value: "CVE-2024-40766" }],
  analysis: analysis({
    threatActors: ["Akira"],
    malware: ["Bumblebee", "Rclone"],
    evidence: {
      version: 1,
      sections: [],
      techniques: [
        {
          id: "T1189",
          name: "Drive-by Compromise",
          tactic: "Initial Access",
          label: "observed",
          mappedBy: "explicit_id",
          evidence: [ev("Drive-by (T1189)")],
          confidence: 0.9,
        },
        {
          id: "T1021.001",
          name: "RDP",
          tactic: "Lateral Movement",
          label: "observed",
          mappedBy: "explicit_id",
          evidence: [ev("RDP (T1021.001)")],
          confidence: 0.9,
        },
        {
          id: "T1059",
          name: "Command and Scripting Interpreter",
          tactic: "Execution",
          label: "observed",
          mappedBy: "explicit_id",
          evidence: [ev("cmd")],
          confidence: 0.9,
        },
        {
          id: "T1003.001",
          name: "LSASS Memory",
          tactic: "Credential Access",
          label: "defensive",
          mappedBy: "keyword",
          evidence: [ev("Protect LSASS")],
          confidence: 0.5,
        },
      ],
      actors: [{ value: "Akira", label: "observed", evidence: [], confidence: 0.9 }],
      malware: [],
      targeting: [],
      relationships: [],
      chain: { steps: [], orderBasis: "unknown" },
      excluded: [],
    },
  }),
};

const alias: ActorSourceReport = {
  id: "r_alias",
  title: "Cozy Bear phishing wave",
  excerpt: "NOBELIUM sent lures; Storm-9999 was seen alongside.",
  publisher: "Vendor A",
  publishedAt: "2026-09-01",
  status: "acquired",
  analysis: analysis({
    threatActors: ["NOBELIUM", "Storm-9999", "Mimikatz"],
    ttps: ["T1566.001 - Spearphishing Attachment"],
  }),
};

const synced: ActorSourceReport = {
  id: "r_sync",
  title: "APT29 (G0016)",
  excerpt: "MITRE ATT&CK group APT29",
  discoveryMethod: "structured_sync",
  status: "acquired",
  analysis: analysis({ threatActors: ["APT29"] }),
};

test("aliases resolve to canonical ATT&CK group ids", () => {
  assert.equal(resolveActorName("PUNK SPIDER")?.id, "G1024");
  assert.equal(resolveActorName("Cozy Bear")?.id, "G0016");
  assert.equal(resolveActorName("Akira ransomware group")?.id, "G1024");
});

test("unresolved names get stable slugs; software and generic words are not actors", () => {
  assert.equal(resolveActorName("Storm-9999")?.id, "x-storm-9999");
  assert.equal(resolveActorName("Storm-9999")?.attackId, null);
  assert.equal(slugifyActor("  Storm 9999 "), slugifyActor("storm-9999"));
  assert.equal(resolveActorName("Mimikatz"), null);
  assert.equal(resolveActorName("??"), null);
});

test("builds actors from analysis names and title/excerpt text, excluding structured_sync docs", () => {
  const idx = buildActorIndex([akira, alias, synced], NOW);
  assert.equal(idx.libraryReports, 2);
  const apt29 = idx.byId.get("G0016")!;
  assert.deepEqual(
    apt29.reports.map((r) => r.id),
    ["r_alias"],
  );
  const storm = idx.byId.get("x-storm-9999")!;
  assert.equal(storm.inAttack, false);
  assert.equal(storm.name, "Storm-9999");
  assert.equal(storm.reports.length, 1);
  assert.equal(idx.byId.has("x-mimikatz"), false);
  // All ATT&CK groups are present even without reports.
  assert.ok(idx.actors.filter((a) => a.inAttack).length >= 170);
  const k = actorKpis(idx);
  assert.equal(k.observedInLibrary, 3);
  assert.equal(k.notInAttack, 1);
  assert.equal(k.lastActivity, "2026-09-01");
});

test("observed techniques exclude defensive statements and diff against ATT&CK", () => {
  const idx = buildActorIndex([akira], NOW);
  const rec = idx.byId.get("G1024")!;
  assert.deepEqual([...rec.observed.keys()].sort(), ["T1021.001", "T1059", "T1189"]);
  const prof = actorProfile(rec);
  const byId = new Map(prof.techniques.map((t) => [t.id, t]));
  // Akira: T1021.001 attributed in ATT&CK → both; T1189 not → new; T1059 parent of attributed T1059.001 → not new.
  assert.equal(byId.get("T1021.001")?.source, "both");
  assert.equal(byId.get("T1189")?.isNew, true);
  assert.equal(byId.get("T1059")?.isNew, false);
  assert.equal(byId.get("T1486")?.source, "attack");
  assert.equal(byId.get("T1189")?.evidence[0]?.quote, "Drive-by (T1189)");
  assert.equal(prof.row.newTechniques, 1);
  assert.deepEqual(prof.cves, [{ id: "CVE-2024-40766", reports: 1 }]);
  const sw = new Map(prof.software.map((s) => [s.name, s]));
  assert.equal(sw.get("Rclone")?.attributed, true);
  assert.equal(sw.get("Rclone")?.observedReports, 1);
  assert.equal(sw.get("Bumblebee")?.attributed, false);
  assert.equal(prof.emulation.synced, false);
  assert.deepEqual(prof.row.emulation, { synced: false });
});

test("isNewVsAttack honours parent / sub-technique matches", () => {
  const attributed = new Set(["T1059.001", "T1078"]);
  assert.equal(isNewVsAttack("T1059", attributed), false);
  assert.equal(isNewVsAttack("T1078.002", attributed), false);
  assert.equal(isNewVsAttack("T1059.003", attributed), true);
  assert.equal(isNewVsAttack("T1189", attributed), true);
});

test("sorting by activity, reports, techniques and name", () => {
  const idx = buildActorIndex([akira, alias], NOW);
  const rows = idx.actors.map((a) => actorRow(a));
  const recent = sortActorRows(rows, "recent");
  assert.ok(recent.slice(0, 3).every((r) => r.observed));
  assert.equal(recent[0].lastSeen, "2026-09-01");
  const byTech = sortActorRows(rows, "techniques");
  assert.equal(byTech[0].id, "G1024");
  const byName = sortActorRows(rows, "name");
  for (let i = 1; i < byName.length; i++)
    assert.ok(
      byName[i - 1].name.localeCompare(byName[i].name, undefined, { sensitivity: "base" }) <= 0,
    );
  const byReports = sortActorRows(rows, "reports");
  assert.equal(byReports[0].reportCount, 1);
});

test("filtering, lookup and suggestions use names and aliases", () => {
  const idx = buildActorIndex([akira, alias], NOW);
  assert.ok(filterActors(idx, { q: "punk spider" }).some((a) => a.id === "G1024"));
  assert.equal(filterActors(idx, { observedOnly: true }).length, 3);
  assert.equal(findActor(idx, "g1024")?.name, "Akira");
  assert.equal(findActor(idx, "Cozy Bear")?.id, "G0016");
  assert.equal(findActor(idx, "x-storm-9999")?.name, "Storm-9999");
  assert.equal(findActor(idx, "no such actor"), undefined);
  assert.equal(suggestActors(idx, "aki")[0]?.id, "G1024");
});

test("emulation summary counts CTID plans and Atomic coverage when synced", () => {
  const idx = buildActorIndex([akira], NOW);
  const emu: EmulationContext = {
    synced: true,
    atomicTechniques: new Set(["T1189", "T1059.001"]),
    plansByGroup: new Map([
      [
        "G1024",
        [{ reportId: "p1", title: "Akira plan", url: "", planType: "full", techniques: 3 }],
      ],
    ]),
  };
  const row = actorRow(idx.byId.get("G1024")!, emu);
  assert.equal(row.emulation.synced, true);
  if (row.emulation.synced) {
    assert.equal(row.emulation.ctidPlans, 1);
    // T1189, T1059.001 exact; T1059 via a sub-technique test.
    assert.equal(row.emulation.atomicCovered, 3);
  }
});
