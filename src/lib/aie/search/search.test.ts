import { test } from "node:test";
import assert from "node:assert/strict";
import { expansionText, parseQuery, understandQuery } from "./query.ts";
import { matchTechniquePhrase, relatedTechniques, stem } from "./technique-index.ts";
import { collapseDuplicates, diversify, prepareDoc, scoreDocs, type ScoredDoc, type SearchDoc } from "./rank.ts";
import { reportToSearchDoc } from "./report-docs.ts";
import { computeFacets, runSearch } from "./engine.ts";

// ---------------------------------------------------------------------------
// Parser
// ---------------------------------------------------------------------------

test("parses field syntax, quoted values, phrases and exclusions with offsets", () => {
  const raw = 'actor:"Cozy Bear" "golden saml" -phishing type:advisory,dfir since:2025';
  const p = parseQuery(raw);
  const kinds = p.clauses.map((c) => (c.type === "field" ? `${c.field}=${c.value}` : `${c.type}${c.negated ? "-" : ""}=${c.value}`));
  assert.deepEqual(kinds, ["actor=Cozy Bear", "phrase=golden saml", "word-=phishing", "type=advisory,dfir", "since=2025"]);
  for (const c of p.clauses) assert.ok(raw.slice(c.span.start, c.span.end).length > 0);
  assert.equal(raw.slice(p.clauses[0].span.start, p.clauses[0].span.end), 'actor:"Cozy Bear"');
});

test("unknown prefixes (URLs) stay free text; empty field values warn", () => {
  const p = parseQuery("https://example.com/x actor:");
  assert.equal(p.clauses[0].type, "word");
  assert.ok(p.warnings.some((w) => w.includes("actor")));
});

test("date bounds: YYYY, YYYY-MM (end of month), YYYY-MM-DD and invalid values", () => {
  const iq = understandQuery("since:2025 until:2024-02");
  assert.equal(iq.since, "2025-01-01");
  assert.equal(iq.until, "2024-02-29");
  assert.equal(understandQuery("until:2025").until, "2025-12-31");
  assert.equal(understandQuery("since:2025-03-04").since, "2025-03-04");
  const bad = understandQuery("since:yesterday");
  assert.equal(bad.since, undefined);
  assert.ok(bad.warnings.some((w) => w.startsWith("since:")));
});

test("type: friendly names, tier, publisher, has: flags", () => {
  const iq = understandQuery("type:advisory,dfir tier:1,t2 publisher:microsoft has:iocs,emulation -type:kev");
  assert.deepEqual(iq.docTypes, ["THREAT_ADVISORY", "DFIR_REPORT"]);
  assert.deepEqual(iq.excludedDocTypes, ["KEV_ENTRY"]);
  assert.deepEqual(iq.tiers, [1, 2]);
  assert.deepEqual(iq.publishers, ["microsoft"]);
  assert.deepEqual(iq.has, ["iocs", "emulation"]);
  assert.equal(iq.filterOnly, true);
});

// ---------------------------------------------------------------------------
// Alias expansion and entity detection
// ---------------------------------------------------------------------------

test("aliases resolve to canonical actors and expand to every known name", () => {
  const iq = understandQuery("Cozy Bear");
  const e = iq.entities[0];
  assert.equal(e.id, "G0016");
  assert.equal(e.name, "APT29");
  assert.equal(e.source, "implicit");
  for (const alias of ["NOBELIUM", "Midnight Blizzard", "UNC2452"]) assert.ok(e.aliases.includes(alias), alias);
  assert.match(iq.summary, /actor APT29 \(G0016\)/);
  const octo = understandQuery("Octo Tempest");
  assert.equal(octo.entities[0].id, "G1015");
  assert.ok(octo.entities[0].aliases.includes("UNC3944"));
  assert.match(expansionText(octo), /UNC3944/);
});

test("field entities are filters; unresolved values fall back to text", () => {
  const iq = understandQuery('actor:"Midnight Blizzard" since:2025');
  assert.equal(iq.entities[0].source, "field");
  assert.equal(iq.summary, "actor APT29 (G0016) · since 2025");
  const u = understandQuery("actor:UNC5221");
  assert.deepEqual(u.unresolved, [{ field: "actor", value: "UNC5221" }]);
  assert.ok(u.terms.includes("unc5221"));
});

test("ambiguous lowercase words are not taken as entities; capitalised ones are", () => {
  assert.equal(understandQuery("page wiper").entities.length, 0);
  assert.equal(understandQuery("Snake").entities[0]?.name, "Turla");
  assert.equal(understandQuery("malware:snake").entities[0]?.id, "S0022");
});

test("quoted phrases are literal (no alias interpretation)", () => {
  const iq = understandQuery('"Cozy Bear"');
  assert.equal(iq.entities.length, 0);
  assert.deepEqual(iq.phrases, ["Cozy Bear"]);
});

// ---------------------------------------------------------------------------
// Techniques and tactics
// ---------------------------------------------------------------------------

test("technique names, shorthand and token cover map to ATT&CK ids", () => {
  assert.equal(matchTechniquePhrase("lsass dumping")[0]?.technique.id, "T1003.001");
  assert.equal(matchTechniquePhrase("pass the hash")[0]?.technique.id, "T1550.002");
  assert.equal(matchTechniquePhrase("Kerberoasting")[0]?.technique.id, "T1558.003");
  assert.equal(matchTechniquePhrase("rdp")[0]?.technique.id, "T1021.001");
  assert.deepEqual(matchTechniquePhrase("hello world"), []);
  assert.equal(stem("dumping"), stem("dump"));
  assert.equal(stem("hashes"), "hash");
});

test("parent / sub-technique expansion and tactic names", () => {
  assert.ok(relatedTechniques("T1003").includes("T1003.001"));
  assert.deepEqual(relatedTechniques("T1003.001"), ["T1003"]);
  const iq = understandQuery("pass the hash lateral movement tactic:credential-access");
  assert.equal(iq.techniques[0].id, "T1550.002");
  assert.ok(iq.tactics.some((t) => t.name === "Lateral Movement" && t.source === "implicit"));
  assert.ok(iq.tactics.some((t) => t.name === "Credential Access" && t.source === "field"));
  assert.ok(iq.consumedTerms.includes("hash"));
});

test("chips: removing a field clause drops it; removing an implicit chip quotes it", () => {
  const iq = understandQuery("Cozy Bear since:2025");
  const actor = iq.chips.find((c) => c.kind === "actor")!;
  const date = iq.chips.find((c) => c.kind === "date")!;
  assert.equal(actor.implicit, true);
  assert.equal(actor.without, '"Cozy Bear" since:2025');
  assert.equal(date.without, "Cozy Bear");
  assert.equal(understandQuery(actor.without).entities.length, 0);
});

// ---------------------------------------------------------------------------
// Ranking, explainability, facets
// ---------------------------------------------------------------------------

const NOW = Date.parse("2026-10-01T00:00:00Z");

function report(id: string, title: string, text: string, extra: Partial<Parameters<typeof reportToSearchDoc>[0]> = {}) {
  return prepareDoc(reportToSearchDoc({ id, title, extractedText: text, publisher: "Vendor A", publishedAt: "2025-06-01", qualityScore: 0.8, ...extra }));
}

const corpus = [
  report("r_unc", "Hardening against UNC3944", "UNC3944 targets help desks. UNC3944 abuses MFA fatigue and SIM swapping. Reset procedures matter.", { publisher: "Google" }),
  report("r_octo", "Octo Tempest crosses boundaries", "Octo Tempest uses social engineering. Octo Tempest dumped LSASS memory (T1003.001) before ransomware.", { publisher: "Microsoft", iocs: [{ kind: "sha256", value: "a".repeat(64) }] }),
  report("r_volt", "Volt Typhoon living off the land", "Volt Typhoon targets critical infrastructure with living-off-the-land techniques and CVE-2021-40539.", { publisher: "Microsoft" }),
  report("r_adv", "Joint advisory on Volt Typhoon", "This advisory describes Volt Typhoon activity against edge devices.", {
    publisher: "CISA",
    docTypes: ["THREAT_ADVISORY"],
    publishedAt: "2024-02-07",
  }),
];

test("alias-aware ranking finds both reports and explains which alias matched", () => {
  const iq = understandQuery("Octo Tempest");
  const ranked = scoreDocs(corpus, iq, { now: NOW });
  const ids = ranked.map((r) => r.prepared.doc.id);
  assert.deepEqual(ids.slice(0, 2).sort(), ["r_octo", "r_unc"]);
  const unc = ranked.find((r) => r.prepared.doc.id === "r_unc")!;
  assert.deepEqual(unc.why.matchedEntities.map((e) => [e.id, e.via, e.queryForm]), [["G1015", "UNC3944", "Octo Tempest"]]);
  assert.ok(unc.why.breakdown.some((b) => b.key === "entity" && b.value > 0));
  assert.ok(unc.why.breakdown.some((b) => b.key === "mult:confidence"));
  assert.ok(!ids.includes("r_volt"));
});

test("technique-name queries match reports that cite the technique id; exact CVE ids boost", () => {
  const t = scoreDocs(corpus, understandQuery("lsass dumping"), { now: NOW });
  assert.equal(t[0].prepared.doc.id, "r_octo");
  assert.ok(t[0].why.matchedTechniques.some((m) => m.id === "T1003.001" && m.relation === "exact"));
  const c = scoreDocs(corpus, understandQuery("CVE-2021-40539"), { now: NOW });
  assert.equal(c[0].prepared.doc.id, "r_volt");
  assert.deepEqual(c[0].why.matchedIds, ["CVE-2021-40539"]);
});

test("doc-type intent boosts advisories; type: filters; exclusions and has: drop documents", () => {
  const plain = scoreDocs(corpus, understandQuery("Volt Typhoon"), { now: NOW });
  const intent = scoreDocs(corpus, understandQuery("Volt Typhoon advisory"), { now: NOW });
  assert.equal(intent[0].prepared.doc.id, "r_adv");
  assert.ok(intent[0].why.breakdown.some((b) => b.key === "docType"));
  assert.ok(plain.length >= 2);
  assert.deepEqual(scoreDocs(corpus, understandQuery("Volt Typhoon type:advisory"), { now: NOW }).map((r) => r.prepared.doc.id), ["r_adv"]);
  assert.ok(!scoreDocs(corpus, understandQuery("Volt Typhoon -advisory"), { now: NOW }).some((r) => r.prepared.doc.id === "r_adv"));
  assert.deepEqual(scoreDocs(corpus, understandQuery("has:iocs"), { now: NOW }).map((r) => r.prepared.doc.id), ["r_octo"]);
  assert.deepEqual(scoreDocs(corpus, understandQuery("Volt Typhoon until:2024"), { now: NOW }).map((r) => r.prepared.doc.id), ["r_adv"]);
});

test("near-duplicates collapse and publisher diversity reorders without dropping", () => {
  const text = "BRICKSTORM is a backdoor deployed on VMware vCenter appliances by a suspected espionage actor. ".repeat(6);
  const a = report("d1", "BRICKSTORM backdoor", text, { publisher: "Google" });
  const b = report("d2", "BRICKSTORM backdoor (mirror)", `${text} Republished.`, { publisher: "Blog" });
  const ranked = scoreDocs([a, b], understandQuery("BRICKSTORM"), { now: NOW });
  const collapsed = collapseDuplicates(ranked);
  assert.equal(collapsed.length, 1);
  assert.equal(collapsed[0].duplicates.length, 1);

  const mk = (id: string, pub: string, score: number): ScoredDoc => ({ prepared: prepareDoc({ id, kind: "report", title: id, summary: "", body: "", aliases: [], entities: [], techniques: [], tactics: [], cves: [], docTypes: [], publisher: pub } as SearchDoc), score, why: { matchedFields: [], matchedTerms: [], matchedEntities: [], matchedTechniques: [], matchedIds: [], breakdown: [], score } });
  const div = diversify([mk("a1", "A", 10), mk("a2", "A", 9.5), mk("b1", "B", 9)]);
  assert.deepEqual(div.map((d) => d.prepared.doc.id), ["a1", "b1", "a2"]);
  assert.ok(div[2].why.breakdown.some((x) => x.key === "mult:diversity"));
});

test("facets count doc types, publishers, actors and years over the matches", () => {
  const ranked = scoreDocs(corpus, understandQuery("Volt Typhoon"), { now: NOW });
  const f = computeFacets(ranked);
  assert.deepEqual(f.publisher.map((b) => [b.value, b.count]).sort(), [["CISA", 1], ["Microsoft", 1]]);
  assert.ok(f.actor.some((b) => b.value === "Volt Typhoon" && b.count === 2));
  assert.deepEqual(f.year.map((b) => b.value), ["2025", "2024"]);
  assert.ok(f.docType.some((b) => b.value === "THREAT_ADVISORY" && b.label === "Advisory"));
});

test("unified search groups knowledge and reports, with snippets and links", () => {
  const out = runSearch(corpus, understandQuery("Midnight Blizzard"), { now: NOW });
  assert.equal(out.counts.actors, 1);
  const apt29 = out.results.find((r) => r.kind === "group")!;
  assert.equal(apt29.id, "G0016");
  assert.deepEqual(apt29.href, { to: "/actors/$actorId", params: { actorId: "G0016" } });
  const reports = runSearch(corpus, understandQuery("Octo Tempest"), { group: "reports", now: NOW });
  assert.equal(reports.counts.reports, 2);
  const unc = reports.results.find((r) => r.id === "r_unc")!;
  assert.match(unc.snippet ?? "", /UNC3944/);
  assert.ok(unc.highlights.includes("UNC3944"));
  const tech = runSearch(corpus, understandQuery("pass the hash"), { group: "techniques", now: NOW });
  assert.equal(tech.results[0].id, "T1550.002");
  assert.equal(tech.results[0].href.to, "/matrix");
  const facetFiltered = runSearch(corpus, understandQuery("Volt Typhoon"), { group: "reports", filters: { publishers: ["CISA"] }, now: NOW });
  assert.deepEqual(facetFiltered.results.map((r) => r.id), ["r_adv"]);
});
