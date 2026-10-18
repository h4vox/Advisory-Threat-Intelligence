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

## 6. Library gate (hiding unrelated reports)

`src/lib/aie/library-gate.ts` (rules, unit-tested) and `src/lib/mongodb/library-gate-repo.server.ts` (storage) keep
the library to threat intelligence. When the Library opens, every report not yet checked under the current rules
version is evaluated once:

| Order | Rule | Example |
|---|---|---|
| 1 | **Protected**: never hidden | ATT&CK techniques, CVEs, 2+ indicators, an attack chain, known actors / malware / campaigns, quality ≥ 70%, structured sources, or an analyst kept it |
| 2 | Page type | homepages, sitemaps, `/blog` / `/tag/…` / `/category/…` listings, privacy / terms / contact pages, search and filter results, government service sites |
| 3 | Topic | the relevance pre-score finds only off-topic signals: webinars, podcasts, awards, hiring, product launches, earnings, events, marketing |
| 4 | Stub | under 120 words (when known) with no indicators |

Hidden reports are **never deleted**. They get `status: "rejected"`, `rejectedBy: "rules"`, the status they had before
and a readable reason, so search, coverage, dashboards and emulation leave them out. The Library shows a summary
("Hid N unrelated reports"), and **Hidden reports only** lists them with their reasons.
- **Restore** a report from its menu, or **Restore N shown** for a whole filtered view. A restored report is pinned
  as kept (`gate.override: "keep"`), so the rules never hide it again.
- **Hide from library** in a report's menu lets an analyst remove anything the rules missed (`rejectedBy: "analyst"`).
- Bump `LIBRARY_GATE_VERSION` after changing the rules, and every report is checked again.

The AI audit ("Audit with AI") writes the same fields. A future AI reviewer can supply the same verdict shape
(`GateVerdict`) in place of the rules.

## 7. Quality gates

| Command | What it checks | Current |
|---|---|---|
| `npm test` | Unit tests: query parser, ranker, dedup, SimHash, relevance precision, sitemaps, robots, feeds, extraction, purple generator, actor aggregation | all pass except 8 platform share-card tests (pre-existing) |
| `npm run eval -- --raw <dir>` | Extraction and evidence on 5 real vendor reports | 26/26 |
| `npm run eval:retrieval -- --raw <dir>` | 28 labelled queries (aliases, technique names, CVEs, field syntax, negatives) | reports recall@5 1.00 (BM25 0.95, substring 0.05); unified recall@5 0.965 (BM25 0.535); negatives 8/8 |

## 8. Deployment notes

- **MongoDB** (`MONGODB_URI`) holds the report library. It is also needed for:
  - structured sync (ATT&CK, Atomic, CTID, Attack Flow, KEV);
  - the emulation index;
  - the autonomous scheduler (cross-instance lock);
  - durable collector state;
  - accounts.

  Without it, the app runs on a built-in local database that starts empty, and the Overview, Library and Settings
  pages say so. In the same case, crawls run only on demand, and collector state lives in the local database.
  - **Connection string.** Earlier versions had a connection string written into the code. That string was removed
    for security, so a deployment that relied on it now needs `MONGODB_URI` set. For `npm run dev`, a `.env` file
    next to `package.json` works.
  - **Networks that refuse SRV DNS lookups.** A `mongodb+srv://` string needs an SRV lookup. When the network refuses
    it, AIE resolves the cluster through public DNS (1.1.1.1, 8.8.8.8, 9.9.9.9) and connects with the equivalent
    seed list (`src/lib/mongodb/srv-fallback.ts`). It accepts only hosts under the cluster's own domain.
  - **Unreachable MongoDB.** When MongoDB can't be reached, the Library shows the error and a plain-language fix
    instead of an empty library.
- **Vercel:**
  - Builds run on Node 22 (`engines.node` in `package.json`; Vite 8 needs Node 20.19+ or 22.12+).
  - Set `MONGODB_URI` for the library.
  - `DATABASE_URL`, if set, must be a Postgres connection string. Migrations run against it during `npm run build`.
    A MongoDB string there is skipped with a warning instead of failing the deploy.
- **Network:** the user deployment needs outbound HTTPS to source sites, `api.github.com` (CALDERA, Unit 42 and CTID
  file listings; set `GITHUB_TOKEN` for higher limits) and `cisa.gov`. The connectors fall back to raw GitHub files
  where possible.
- Collector state (fetch state, health, funnels) is stored on report documents and `collector_*` documents in MongoDB.
