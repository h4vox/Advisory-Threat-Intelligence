import { test } from "node:test";
import assert from "node:assert/strict";
import { buildSearchPlan, parseDuckDuckGoHtml } from "./web-search.ts";
import { DEFAULT_RESEARCH_DISCOVERY, normalizeResearchDiscovery, splitKeywordPhrases } from "./research-taxonomy.ts";

const DEFAULT_KEYWORDS = 'ransomware, "attack chain", "infection chain", "initial access", "lateral movement", "MITRE ATT&CK", "adversary emulation"';

test("the keyword setting becomes separate phrases, quoted only when they have several words", () => {
  assert.deepEqual(splitKeywordPhrases(DEFAULT_KEYWORDS), [
    "ransomware",
    '"attack chain"',
    '"infection chain"',
    '"initial access"',
    '"lateral movement"',
    '"MITRE ATT&CK"',
    '"adversary emulation"',
  ]);
  assert.deepEqual(splitKeywordPhrases("  ,x, Ransomware\nransomware , “cloud  attack” "), ["Ransomware", '"cloud attack"']);
});

test("a scheduled run searches two keyword phrases (rotating) and the taxonomy, never a nested-quote phrase", () => {
  const a = buildSearchPlan({ keywords: DEFAULT_KEYWORDS, research: DEFAULT_RESEARCH_DISCOVERY, round: 0 });
  const b = buildSearchPlan({ keywords: DEFAULT_KEYWORDS, research: DEFAULT_RESEARCH_DISCOVERY, round: 1 });
  assert.equal(a.filter((p) => p.origin === "keyword").length, 2);
  assert.equal(a.filter((p) => p.origin === "research").length, DEFAULT_RESEARCH_DISCOVERY.queriesPerRun);
  assert.equal(a[0].query, "ransomware threat intelligence technical analysis");
  assert.equal(a[1].query, '"attack chain" threat intelligence technical analysis');
  assert.notDeepEqual(a.slice(0, 2), b.slice(0, 2), "keywords rotate between runs");
  assert.ok(a.every((p) => !p.query.includes('""') && !p.query.includes('"ransomware, ')), "no malformed phrases");
  assert.ok(a.filter((p) => p.origin === "research").every((p) => p.category));
});

test("a targeted hunt searches its own query only; research discovery can be switched off", () => {
  const t = buildSearchPlan({ targetedQuery: "  Volt Typhoon  router  ", keywords: DEFAULT_KEYWORDS, research: DEFAULT_RESEARCH_DISCOVERY, round: 0 });
  assert.equal(t.length, 3);
  assert.ok(t.every((p) => p.origin === "targeted" && p.query.startsWith("Volt Typhoon router ")));
  const off = buildSearchPlan({ keywords: "", research: { ...DEFAULT_RESEARCH_DISCOVERY, enabled: false }, round: 0 });
  assert.deepEqual(off, []);
});

test("stored research settings are made safe", () => {
  assert.deepEqual(normalizeResearchDiscovery(undefined), DEFAULT_RESEARCH_DISCOVERY);
  assert.deepEqual(normalizeResearchDiscovery({ enabled: false, queriesPerRun: 99, bas: ["emulation", "malware", "emulation", "nope"] }), {
    enabled: false,
    queriesPerRun: 12,
    bas: ["emulation"],
  });
  assert.equal(normalizeResearchDiscovery({ queriesPerRun: -3 }).queriesPerRun, 0);
});

const DDG = `
<div class="result results_links results_links_deep web-result">
  <h2 class="result__title">
    <a rel="nofollow" class="result__a" href="//duckduckgo.com/l/?uddg=https%3A%2F%2Funit42.paloaltonetworks.com%2Fnew%2Dloader%2F&amp;rut=abc">New <b>loader</b> delivers &amp; persists</a>
  </h2>
  <a class="result__snippet" href="//duckduckgo.com/l/?uddg=https%3A%2F%2Funit42.paloaltonetworks.com%2Fnew%2Dloader%2F">Unit 42 analyses a <b>loader</b> used in an intrusion chain.</a>
</div>
<div class="result">
  <a rel="nofollow" class="result__a" href="//duckduckgo.com/l/?kh=-1&amp;uddg=https%3A%2F%2Fexample.org%2Freport.pdf">Annual report (PDF)</a>
</div>
<div class="result">
  <a rel="nofollow" class="result__a" href="//duckduckgo.com/y.js?ad_provider=x">Sponsored</a>
  <a rel="nofollow" class="result__a" href="//duckduckgo.com/l/?uddg=https%3A%2F%2Funit42.paloaltonetworks.com%2Fnew%2Dloader%2F">Duplicate</a>
</div>`;

test("DuckDuckGo results keep their titles and snippets; ads and duplicates are dropped", () => {
  const r = parseDuckDuckGoHtml(DDG);
  assert.deepEqual(r, [
    { url: "https://unit42.paloaltonetworks.com/new-loader/", title: "New loader delivers & persists", snippet: "Unit 42 analyses a loader used in an intrusion chain." },
    { url: "https://example.org/report.pdf", title: "Annual report (PDF)", snippet: "" },
  ]);
});

test("unrecognised markup falls back to the bare redirect links", () => {
  const r = parseDuckDuckGoHtml('<a href="/l/?kh=-1&amp;uddg=https%3A%2F%2Fexample.com%2Fa">x</a> <a href="/l/?uddg=javascript%3Aalert(1)">y</a>');
  assert.deepEqual(r, [{ url: "https://example.com/a", title: "", snippet: "" }]);
});
