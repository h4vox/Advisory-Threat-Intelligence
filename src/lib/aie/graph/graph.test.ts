import { test } from "node:test";
import assert from "node:assert/strict";
import { buildIntelGraph, reportEntities, type GraphSourceReport } from "./build.ts";
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

test("3D layout: deterministic, centre at the origin, rings on their shells", async () => {
  const { layout3d } = await import("./layout.ts");
  const ix = indexGraph(buildIntelGraph(reports));
  const f = focusView(ix, `actor:${apt29.id}`, DEFAULT_FILTER, { hops: 2 });
  const a = layout3d(f, 40);
  const b = layout3d(f, 40);
  assert.deepEqual([...a.pos.entries()], [...b.pos.entries()]);
  assert.deepEqual(a.pos.get(`actor:${apt29.id}`), { x: 0, y: 0, z: 0 });
  const r = (id: string) => Math.hypot(a.pos.get(id)!.x, a.pos.get(id)!.y, a.pos.get(id)!.z);
  assert.ok(r("technique:T1566") < r("actor:x-storm-9999"), "first ring inside the second");
  const o = layout3d(overviewView(ix, DEFAULT_FILTER, 50), 40);
  for (const p of o.pos.values()) assert.ok(Math.hypot(p.x, p.y, p.z) <= 1.0001);
});

test("malformed stored reports never break the graph", () => {
  const broken = [
    { id: "b1", title: null, status: "acquired", publishedAt: null, iocs: [{ kind: "cve", value: null }, null, { kind: "domain", value: null }], analysis: { threatActors: [null, "APT29"], malware: null, ttps: [null, "T1566"], vulnerabilities: [null], attackChain: null, evidence: { techniques: [{ id: null, label: "observed" }, null], actors: [{ value: null, label: "observed" }], malware: null, targeting: [{ kind: "sector", value: null, status: "targeted" }], relationships: [null, { subject: null, object: null, label: "observed" }] } } },
    { id: "b2", title: "x", extractedEntities: { attackRefs: [{ kind: "group", id: null, name: null }], techniques: [{ id: null }], cves: [null], threatActors: null, malwareFamilies: [null] }, aiAnalysis: { adversary: { name: null, malware: [null], tools: null, sectors: [null], regions: null }, attackChain: [null, { technique: { id: null } }] } },
    null,
  ] as unknown as GraphSourceReport[];
  const g = buildIntelGraph([...broken, ...reports]);
  assert.ok(g.nodes.some((n) => n.id === `actor:${apt29.id}`));
  assert.ok(g.stats.reports >= 3);
});

test("browser copy: per-type caps, strongest links per entity, stated links kept, ids restored", async () => {
  const { clientGraph } = await import("./build.ts");
  const { withEdgeIds } = await import("./client.ts");
  const g = buildIntelGraph(reports);
  const c = clientGraph(g, { caps: { technique: 2 }, edgesPerNode: 2, edgeReports: 1 });
  assert.equal(c.nodes.filter((n) => n.type === "technique").length, 2);
  assert.equal(c.stats.trimmed?.technique, g.nodes.filter((n) => n.type === "technique").length - 2);
  const ids = new Set(c.nodes.map((n) => n.id));
  assert.ok(c.edges.every((e) => ids.has(e.source) && ids.has(e.target)), "no dangling links");
  assert.ok(c.edges.some((e) => e.basis === "stated"), "stated links are kept");
  assert.ok(c.edges.every((e) => !e.id && e.reports.length <= 1));
  withEdgeIds(c);
  assert.ok(c.edges.every((e) => g.edges.some((x) => x.id === e.id)), "ids match the server's");
  assert.equal(g.edges.every((e) => e.id), true, "the server graph is unchanged");
});

test("reports without evidence facts still contribute their analysis actors, malware and attack-chain techniques", () => {
  const ents = reportEntities({
    id: "r-old",
    title: "Older analysis",
    analysis: {
      method: "heuristic",
      classification: "THREAT_REPORT",
      threatActors: ["Storm-1811"],
      malware: ["QakBot"],
      vulnerabilities: [],
      ttps: [],
      ioas: [],
      attackChain: [{ order: 1, tactic: "Execution", techniques: ["T1059.001 - PowerShell"], summary: "" }],
      detections: [],
      hunting: [],
      emulation: [],
    },
  });
  const types = [...ents.values()].map((m) => `${m.type}:${m.label}`);
  assert.ok(types.some((t) => t.startsWith("actor:")), types.join(", "));
  assert.ok(types.some((t) => /QakBot/i.test(t)), types.join(", "));
  assert.ok(ents.has("technique:T1059.001"));
});

test("indicators the grounded AI analysis verified reach the graph", () => {
  const ents = reportEntities({
    id: "r-ai",
    title: "AI",
    aiAnalysis: { iocs: [{ type: "domain", value: "smashshape.com" }, { type: "cve", value: "CVE-2024-1709" }] } as never,
  });
  assert.ok(ents.has("indicator:domain:smashshape.com"));
  assert.ok(ents.has("vulnerability:CVE-2024-1709"));
});
