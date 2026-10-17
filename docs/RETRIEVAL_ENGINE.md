# AIE retrieval engine

How AIE collects threat intelligence, understands it, finds it again and turns it into emulation plans.
Spec references are to *AIE — Adversary Intelligence Web Extraction & Document Ingestion Engine*.

```
Sources (tiered registry)                    Bundled ATT&CK knowledge (v20, offline)
  │  feeds · sitemaps · listings · connectors      │  techniques · groups · software · campaigns + aliases
  ▼                                                ▼
Collection ──► relevance pre-score ──► fetch (conditional) ──► extract (structured) ──► dedup ──► quality gate ──► store
                                                                                                         │
                         entity enrichment (aliases → G/S/C IDs) · fingerprints · versions · mirrors ◄───┘
  ▼
Search & retrieval (/search · ⌘K · library box · AI agent chat)
  ▼
Emulation (/actors · actor profiles · /purple · report Emulation tab)
```

## 1. Sources

The registry (`src/lib/aie/catalog.ts`) holds 41 sources in four tiers: authoritative (ATT&CK STIX, CISA KEV and
advisories, CERTs), emulation (CTID emulation library, Attack Flow, Atomic Red Team, CALDERA), vendor research and
community. Each source declares its connector, the document types it yields, a confidence class and a schedule hint.
Structured connectors live in `src/lib/aie/connectors/` and sync through *Sources → Registry → Sync now*.

## 2. Collection engine (`src/lib/aie/collector/`, wired into `crawler.ts`)

| Capability | What it does | Spec |
|---|---|---|
| Incremental crawling | Conditional GET (`If-None-Match` / `If-Modified-Since`) for feeds, sitemaps, listings and articles, with per-URL fetch state. A 304 or an identical body is skipped. Known articles are re-checked every 14 days or when a listing reports an update. Changed content becomes a new version (previous hashes kept). Near-identical re-fetches (SimHash ≤ 2 bits) are treated as cosmetic. | §45 |
| Multi-hash dedup | Canonical URL (tracking params, AMP, print and mobile renditions collapse), content SHA-256, normalised-text hash, title + publisher hash, 64-bit SimHash (≤ 3 bits). A title + publisher match needs similar content or a publication date within 3 days, so recurring series are not dropped. The better copy (primary publisher over a re-post, higher tier, earlier date) is canonical; the other URL is kept as "also seen at". | §18 |
| Discovery depth | sitemap.xml and sitemap indexes with `lastmod`, feed autodiscovery (`<link rel="alternate">`), listing pagination (`rel=next`, "Older posts", page patterns), robots.txt (RFC 9309, crawl-delay) and a bounded per-source backfill (6, 12 or 24 months). | §15–16 |
| Relevance pre-score | Before any fetch, scores title, summary and URL. Positive: ATT&CK actors, software and campaigns, CVE and technique IDs, actor naming schemes (UNC, DEV/Storm, TA, APT, FIN, cryptonyms), intrusion vocabulary. Negative: webinars, podcasts, awards, hiring, launches, earnings, event recaps, marketing, awareness explainers. Also uses the source's acceptance history and tier. Fail-open: unknown items are fetched; only clear junk (< 0.30) is skipped, with the reason logged. | §16–17 |
| Extraction | Structure-preserving text (headings, lists, tables as rows, code blocks) for crawled pages, pasted HTML and full-content feeds, so evidence keeps its section and IOC appendices stay intact. A "Download the full report" PDF is fetched and attached (size cap, per-job budget, robots). | §19–21 |
| Entity enrichment | Every stored report gets canonical ATT&CK references (`extractedEntities.attackRefs`): G/S/C IDs, the alias the report used, the count and the first offset. | §27, §43 |
| Health, yield, schedules | Per-source counters (fetched, new, unchanged, duplicate, skipped by relevance, rejected, accepted, average quality), automatic backoff (3 failures → 2 h, doubling, up to 7 days), next-due from the schedule hint. *Sources → Health* shows it; *Ingest* shows each job's funnel (discovered → relevant → acquired → unique → qualified → stored). | §44, §53 |

Every fetch goes through the SSRF-guarded fetchers in `security.ts` (DNS validated on every redirect hop).

## 3. ATT&CK knowledge (`src/lib/aie/attack-knowledge.ts`)

A compact offline snapshot of ATT&CK Enterprise (`src/lib/aie/data/attack-knowledge.json`): 706 techniques (tactics,
platforms, data components), 178 groups, 842 software and 57 campaigns, with aliases and "uses" links. It is server-only.
Regenerate it with `npm run build:attack-knowledge`.

- `resolveEntity("Cozy Bear")` returns APT29 (G0016). Matching is exact on normalised names and aliases, never fuzzy.
- `findEntitiesInText(text)` finds groups, campaigns and software in prose. Generic words are never matched, and
  single-word aliases must be capitalised as written. It is indexed by first word: one pass over the text.
- `techniquePrevalence(id)` returns how many groups use a technique.

## 4. Search engine (`src/lib/aie/search/`, `server-search.ts`)

**Query syntax** (field clauses filter; free text ranks):

| Syntax | Meaning |
|---|---|
| `actor:"Volt Typhoon"` · `malware:BRICKSTORM` · `campaign:C0024` | Entity filter (names, aliases or IDs) |
| `technique:T1003.001` · `technique:"lsass dumping"` · `tactic:"lateral movement"` | Technique / tactic filter (parent and sub-techniques count) |
| `cve:CVE-2024-3400` · `type:advisory,dfir` · `tier:1,2` · `publisher:mandiant` | Exact filters |
| `since:2025` · `until:2025-06` · `has:iocs` · `has:emulation` · `has:evidence` | Date window and content flags |
| `"exact phrase"` · `-akira` · `-"press release"` | Required phrase, exclusions |

Free text is understood too. Aliases resolve to the canonical entity: "Octo Tempest" and "UNC3944" both mean
Scattered Spider. Technique names and analyst shorthand map to IDs ("pass the hash" → T1550.002, "rdp" → T1021.001).
Words like "advisory" or "dfir" add a document-type preference. The page shows the interpretation as removable chips.

**Ranking.** BM25F over title, names, summary and body, weighted by term coverage. Added to that: canonical entity
matches (aliases resolved), exact CVE and technique IDs (parent and sub-technique), tactics and document-type intent.
The total is then multiplied by source confidence, tier, quality and a mild recency factor. Near-duplicates are
collapsed and publishers are diversified. Every result carries **Why this result**: matched fields, the alias the
document used, techniques and a score breakdown.

**Where it is used:** `/search` (groups for reports, actors, techniques, software, campaigns, emulation and
vulnerabilities, with facets), the ⌘K palette, the library search box and the AI agent chat. The chat's retrieval
trace records the interpreted query and why each passage was chosen.

## 5. From intelligence to emulation

- **Threat actors** (`/actors`, `src/lib/aie/actors/`): all ATT&CK groups merged with actors observed in library
  reports. Profiles compare ATT&CK-attributed techniques with techniques observed in reports, and flag "new vs
  ATT&CK".
- **Purple paths** (`/purple`, `src/lib/aie/purple/`): actor, report, campaign or technique list → an ordered,
  prioritised path. Each step explains its priority (library frequency and recency, source confidence, ATT&CK
  attribution, emulation availability, platform fit, ATT&CK prevalence). Each step also carries a §33 simulation object
  (prerequisites, telemetry from ATT&CK data components, execution method, expected detection, success criteria,
  cleanup, risk), a §36 hunt hypothesis (query labelled as a template) and an honest detection status. Exports:
  Markdown, JSON, CALDERA-style YAML. **Planning only: AIE never executes procedures.**

## 6. Quality gates

| Command | What it checks | Current |
|---|---|---|
| `npm test` | Unit tests: query parser, ranker, dedup, SimHash, relevance precision, sitemaps, robots, feeds, extraction, purple generator, actor aggregation | all pass except 8 platform share-card tests (pre-existing) |
| `npm run eval -- --raw <dir>` | Extraction and evidence on 5 real vendor reports | 26/26 |
| `npm run eval:retrieval -- --raw <dir>` | 28 labelled queries (aliases, technique names, CVEs, field syntax, negatives) | reports recall@5 1.00 (BM25 0.95, substring 0.05); unified recall@5 0.965 (BM25 0.535); negatives 8/8 |

## 7. Deployment notes

- **MongoDB** (`MONGODB_URI`) is needed for structured sync (ATT&CK, Atomic, CTID, Attack Flow, KEV), the emulation
  index, the autonomous scheduler (cross-instance lock) and durable collector state. Without it, crawls run on demand
  and collector state lives in the local database.
- **Network:** the user deployment needs outbound HTTPS to source sites, `api.github.com` (CALDERA, Unit 42 and CTID
  file listings; set `GITHUB_TOKEN` for higher limits) and `cisa.gov`. The connectors fall back to raw GitHub files
  where possible.
- Collector state (fetch state, health, funnels) is stored on report documents and `collector_*` documents in MongoDB.
