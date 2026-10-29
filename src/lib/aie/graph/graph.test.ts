import { test } from "node:test";
import assert from "node:assert/strict";
import { buildIntelGraph, type GraphSourceReport } from "./build.ts";
import { DEFAULT_FILTER, focusView, indexGraph, overviewView, searchNodes, similarEntities } from "./analyze.ts";
import { forceLayout, radialLayout } from "./layout.ts";
import { buildBriefPrompt, parseBrief } from "./brief.ts";
import { resolveEntity } from "../attack-knowledge.ts";

const ev = (q: string) => [{ quote: q, start: 0, end: q.length }];
const fact = (value: string, label: "observed" | "inferred" | "hypothetical" = "observed", confidence = 0.8) => ({ value, label, evidence: ev(value), confidence });
const tech = (id: string, name: string, tactic: string, label: "observed" | "defensive" = "observed") => ({ id, name, tactic, label, mappedBy: "explicit_id" as const, evidence: ev(id), confidence: 0.8 });

function report(id: string, date: string, o: { actors?: string[]; malware?: string[]; techniques?: Array<ReturnType<typeof tech>>; sectors?: string[]; iocs?: Array<{ kind: "domain" | "ipv4" | "cve"; value: string }>; rel?: boolean; extraActors?: Array<ReturnType<typeof fact>> }): GraphSourceReport {
  return {
    id,
    title: `Report ${id}`,
    publisher: "Lab",
    publishedAt: date,
    status: "acquired",
    iocs: o.iocs,
    analysis: {
      method: "heuristic",
      classification: "x",
      threatActors: [],
      malware: [],
      vulnerabilities: [],
      ttps: [],
      ioas: [],
      attackChain: [],
      detections: [],
      hunting: [],
      emulation: [],
      evidence: {
        version: 1,
        sections: [],
        techniques: o.techniques ?? [],
        actors: [...(o.actors ?? []).map((a) => fact(a)), ...(o.extraActors ?? [])],
        malware: (o.malware ?? []).map((m) => fact(m)),
        targeting: (o.sectors ?? []).map((s) => ({ kind: "sector" as const, value: s, status: "targeted" as const, evidence: ev(s), confidence: 0.7 })),
        relationships: o.rel ? [{ subject: { type: "actor" as const, value: o.actors![0] }, predicate: "uses" as const, object: { type: "malware" as const, value: o.malware![0] }, label: "observed" as const, evidence: ev(`${o.actors![0]} deployed ${o.malware![0]}`), confidence: 0.85 }] : [],
        chain: { steps: [], orderBasis: "unknown" },
        excluded: [],
      },
    },
  };
}

const PHISH = tech("T1566", "Phishing", "Initial Access");
const PS = tech("T1059.001", "PowerShell", "Execution");
const RDP = tech("T1021.001", "Remote Desktop Protocol", "Lateral Movement");
const DEF = tech("T1003", "OS Credential Dumping", "Credential Access", "defensive");

const reports: GraphSourceReport[] = [
  report("r1", "2026-09-01", { actors: ["APT29"], malware: ["Cobalt Strike"], techniques: [PHISH, PS, DEF], sectors: ["government"], rel: true, iocs: [{ kind: "domain", value: "evil.example" }, { kind: "cve", value: "CVE-2024-1234" }] }),
  report("r2", "2026-10-01", { actors: ["Cozy Bear"], malware: ["Cobalt Strike"], techniques: [PHISH, RDP], sectors: ["government"] }),
  report("r3", "2026-08-01", { actors: ["Storm-9999", "Mimikatz"], malware: ["Cobalt Strike", "APT29"], techniques: [PHISH, PS, RDP], sectors: ["government"], extraActors: [fact("Maybe Group", "hypothetical")] }),
  { ...report("x", "2026-10-02", { actors: ["APT28"] }), discoveryMethod: "structured_sync" },
];

const apt29 = resolveEntity("APT29", ["group"])[0];
const cs = resolveEntity("Cobalt Strike", ["software"])[0];

test("aliases resolve to one ATT&CK node; reference docs and hypothetical facts are left out", () => {
  const g = buildIntelGraph(reports);
  const actor = g.nodes.find((n) => n.id === `actor:${apt29.id}`)!;
  assert.ok(actor, "APT29 node");
  assert.equal(actor.reportCount, 2, "APT29 + Cozy Bear are one actor");
  assert.ok(actor.aliases?.includes("Cozy Bear"));
  assert.ok(!g.nodes.some((n) => n.label === "Maybe Group"), "hypothetical actor skipped");
  assert.ok(!g.nodes.some((n) => n.attackId === "T1003"), "defensive technique skipped");
  assert.ok(!g.nodes.some((n) => n.attackId === "G0007"), "structured_sync report skipped");
  assert.ok(g.nodes.some((n) => n.id === "actor:x-storm-9999"), "unknown actor gets a slug node");
  assert.ok(!g.nodes.some((n) => n.type === "malware" && n.label === "APT29"), "a known group listed as malware is not malware");
  assert.ok(!g.nodes.some((n) => n.type === "actor" && n.label === "Mimikatz"), "known software listed as an actor is not an actor");
  assert.ok(g.nodes.some((n) => n.id === "vulnerability:CVE-2024-1234"));
  assert.ok(g.nodes.some((n) => n.id === "indicator:domain:evil.example"));
  assert.equal(g.stats.reports, 3);
});

test("stated links keep their quote; co-reported links add up across reports", () => {
  const g = buildIntelGraph(reports);
  const sw = g.nodes.find((n) => n.attackId === cs.id)!;
  const uses = g.edges.find((e) => e.source === `actor:${apt29.id}` && e.target === sw.id && e.predicate === "uses")!;
  assert.equal(uses.basis, "stated");
  assert.equal(uses.weight, 2);
  assert.equal(uses.stated, 1);
  assert.match(uses.quote!.text, /deployed/);
  const phish = g.edges.find((e) => e.source === `actor:${apt29.id}` && e.target === "technique:T1566")!;
  assert.equal(phish.basis, "co-reported");
  assert.equal(phish.weight, 2);
  assert.ok(phish.confidence > 0.48 && phish.confidence < 0.99, `confidence ${phish.confidence} grows with reports`);
  assert.ok(g.edges.some((e) => e.source === `actor:${apt29.id}` && e.target === "sector:government" && e.predicate === "targets"));
  assert.ok(g.edges.some((e) => e.source === "indicator:domain:evil.example" && e.target === sw.id && e.predicate === "indicator_of"));
  assert.deepEqual(g.edges.find((e) => e.id === phish.id)!.reports, ["r2", "r1"], "newest report first");
});

test("focus view rings and overview quota", () => {
  const ix = indexGraph(buildIntelGraph(reports));
  const f = focusView(ix, `actor:${apt29.id}`, DEFAULT_FILTER, { hops: 2 });
  assert.equal(f.ring!.get(`actor:${apt29.id}`), 0);
  assert.equal(f.ring!.get("technique:T1566"), 1);
  assert.equal(f.ring!.get("actor:x-storm-9999"), 2, "the other actor is reached through a shared neighbour");
  const o = overviewView(ix, DEFAULT_FILTER, 50);
  assert.ok(o.nodes.length > 5);
  assert.ok(o.nodes.every((n) => DEFAULT_FILTER.types.includes(n.type)), "indicators are off by default");
  assert.ok(o.edges.every((e) => o.nodes.some((n) => n.id === e.source) && o.nodes.some((n) => n.id === e.target)));
  assert.equal(searchNodes(ix, "cozy")[0]?.id, `actor:${apt29.id}`, "search finds aliases");
});

test("similar entities: actors sharing rare behaviour and tooling", () => {
  const ix = indexGraph(buildIntelGraph(reports));
  const sim = similarEntities(ix, `actor:${apt29.id}`);
  assert.equal(sim[0]?.node.id, "actor:x-storm-9999");
  assert.ok(sim[0].score > 0.3);
  assert.ok(sim[0].shared.some((s) => s.id === "technique:T1566"));
  assert.equal(sim[0].linked, false);
});

test("layouts are deterministic; the focus centre sits at the origin", () => {
  const ix = indexGraph(buildIntelGraph(reports));
  const f = focusView(ix, `actor:${apt29.id}`, DEFAULT_FILTER, { hops: 2 });
  const a = radialLayout(f);
  assert.deepEqual(a.pos.get(`actor:${apt29.id}`), { x: 0, y: 0 });
  assert.equal(a.pos.size, f.nodes.length);
  const o = overviewView(ix, DEFAULT_FILTER, 50);
  const l1 = forceLayout(o, 60);
  const l2 = forceLayout(o, 60);
  assert.deepEqual([...l1.pos.entries()], [...l2.pos.entries()]);
  for (const p of l1.pos.values()) assert.ok(Math.hypot(p.x, p.y) <= 0.96);
});

test("AI brief keeps only points citing known IDs", () => {
  const g = buildIntelGraph(reports);
  const ix = indexGraph(g);
  const node = ix.node.get(`actor:${apt29.id}`)!;
  const facts = {
    node,
    links: (ix.adj.get(node.id) ?? []).map((e) => ({ edge: e, other: ix.node.get(e.source === node.id ? e.target : e.source)!, outgoing: e.source === node.id })),
    similar: similarEntities(ix, node.id),
    reports: node.reports.map((id) => g.reports[id]),
  };
  const prompt = buildBriefPrompt(facts);
  assert.match(prompt, /\[technique:T1566\]/);
  assert.match(prompt, /\[report:r1\]/);
  const b = parseBrief(
    {
      summary: "APT29 phishes governments.",
      points: [
        { text: "Uses phishing", refs: ["technique:T1566", "made:up"] },
        { text: "No refs", refs: [] },
        { text: "Invented", refs: ["actor:G9999"] },
      ],
      hiddenLinks: [{ text: "Overlaps with Storm-9999", refs: ["[actor:x-storm-9999]"] }],
      gaps: ["Only two reports"],
    },
    facts,
    "Test",
  );
  assert.deepEqual(b.points, [{ text: "Uses phishing", refs: ["technique:T1566"] }]);
  assert.equal(b.hiddenLinks[0].refs[0], "actor:x-storm-9999");
  assert.equal(b.dropped, 2);
});
