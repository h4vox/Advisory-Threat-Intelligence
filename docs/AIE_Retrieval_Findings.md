# AIE — Retrieval & Intelligence Findings

**Code reviewed:** `master` @ `e8ba24c` (includes `547eabb`) · **Date:** 2026-10-15
**Brief:** `AIE_Retrieval_Intelligence_Data_Requirements.md` (§15 deliverable)

## How this was checked

| Method | What it covers | Limits |
|---|---|---|
| Code trace | Every path from a user question/search to stored reports, every field written by ingest, every truncation point | — |
| Live pipeline run | The app's real `htmlToText → extractHtmlMetadata → scoreQuality → qualifyContent → harvestIocs → analyzeThreatIntelligence → extractStructuredEntities → attack chain` functions, run on 5 real public reports (Microsoft: Volt Typhoon, Octo Tempest; Google/Mandiant: BRICKSTORM, BREEZE COMET, UNC3944 hardening) | No LLM keys, so the AI paths were not run. CISA and The DFIR Report were blocked by the network, so the Microsoft and Google reports above were used in their place |
| Stored data | `docs/library-audit-log.json`: the app's own scan of **678 stored records** (25 Sep 2026), 50-record retained sample | MongoDB is not reachable from the review environment, so search and chat could not be run against the live library |

Labels used below: **VERIFIED** (shown in code or by running it) · **INFERRED** (follows from verified code but not run end-to-end) · **UNVERIFIED** (needs the live DB or LLM).

---

## Readiness decision (summary)

**Not ready to support advisory context.**

- **What works:** ingestion runs, full extracted text is stored (no cap on the heuristic path), and keyword search covers the whole body.
- **What is broken at the root:**
  - No fact carries evidence.
  - No relationships exist between facts.
  - Attack chains are always a fixed template.
  - Defensive advice is extracted as attacker behaviour.
  - The chat "grounding" is four ~220-character excerpts with citations attached whether or not they were used.
- **Fabricated numbers:** several screens show invented or padded numbers as if they were intelligence. This is the "doing stuff that isn't developed" problem, covered in §5.

---

## 1. What AIE currently retrieves

- **Sources configured (VERIFIED):** 19 curated seeds (`catalog.ts`), RSS/Atom feeds, DuckDuckGo HTML scraping, citation/outlink expansion, and a 7-item offline pool (`discovery.ts`).
- **Library composition (VERIFIED, from the stored-record audit of 678 records):**
  - **Junk is still being collected.** 24 records were pruned as product pages, listing pages and the like, which shows the gate lets these through.
  - **ATT&CK reference pages are stored as reports and credited to vendors.** For example, *"Network Service Discovery, Technique T1046 – Enterprise | MITRE ATT&CK"* is stored with publisher *Unit 42*, and *"Proxy, Technique T1090"* also with *Unit 42*. Reference taxonomy is mixed into incident evidence under the wrong publisher (brief §3.3).
  - **Marketing and roundup pages are kept as high-value.** *"Hackers Frequently Target Healthcare and Finance Orgs | Huntress"* is kept. Patch Tuesday roundups are kept with score 1.0 and **80 "IOCs"**, which is the IOC cap (likely CVE IDs).
- **Content completeness:**
  - **Microsoft blog pages keep under 1% of their text (VERIFIED by running it).** URL ingest of a Microsoft Security blog post keeps **190 of 21,043 characters** (Volt Typhoon) and **290 of 36,104** (Octo Tempest), and then rejects the report as too short.
    - Cause: `htmlToText` takes the first `<article>` longer than 400 characters, which on that site is the header card (`extract.ts:~125`).
    - Microsoft is a seeded source (`src_msft`).
  - **Failed PDF extraction stores a placeholder as the report text** (VERIFIED, `crawler.ts:~1196`): the text becomes *"PDF Document Evidence… preserved"*.
  - **Original HTML is not kept** (VERIFIED). `rawHtml` is regenerated "pristine" HTML, and opening a report (`getReport`, `server.ts:~1004-1046`) **rewrites it again and saves the rewrite to MongoDB**. Original bytes are lost; only a hash remains.

## 2. What data is currently preserved

| Brief requirement | Status | Evidence |
|---|---|---|
| Full extracted text | AVAILABLE | Stored uncapped; fetch capped at 1.5 MB |
| Original content | ABSENT | Regenerated HTML only, overwritten on view |
| Publication date | **WRONG on crawler path** | `crawler.ts:1601, 1699` store **today's date** as `publishedAt`. The parsed date is discarded. The URL-ingest path is correct |
| Updated date / event date | ABSENT | — |
| Ingested date | AVAILABLE | `ingestedAt` |
| Content hash / version | PARTIAL | `rawHash` and `textHash` stored; `version` incremented but old versions not kept |
| Source category | PARTIAL | `classification` and `resourceKind`; `SourceRecord.category` not copied to the report |
| Language | ABSENT | — |
| Outbound links / citations | ABSENT | `outlinkCount` and `citedDomains` exist in the type but are never written |
| Page / section boundaries | ABSENT | Text flattened; PDF page numbers dropped |
| Truncation / transformation flags | ABSENT | — |
| Per-fact evidence (quote, offset) | ABSENT | Entities are `string[]` (`types.ts:49-86`) |
| Relationships (actor→procedure→technique…) | ABSENT | Graph edges are discovery links only |
| Observed vs inferred labels | ABSENT | One document-level `method` label, which also mislabels mixed results (§5) |
| Confidence | PARTIAL | Report-level only |
| Victim, sector, geography, platform, objective | ABSENT | Sector data exists only in hard-coded dashboard profiles |
| IOC role, first-seen date, original defanged form | ABSENT | IOCs are `{kind, value}` only, capped at 80 |

## 3. How intelligence currently connects (examples from running the pipeline)

**Attribution errors (VERIFIED):**
- **False actor.** BRICKSTORM (Mandiant) is attributed to **APT29**. The only trigger is *"Organizations should follow our guidance outlined in our APT29 whitepaper"*. The real actors (BRICKSTORM, UNC5221) are not recognised.
- **Actor list is fixed.** Octo Tempest is not detected at all because it is missing from the hard-coded actor list.
- **No actor-to-technique link exists in any run.** Every technique in a document is implicitly attributed to every actor in it.

**Defensive text extracted as attacker behaviour (VERIFIED):**
- T1027 from *"Block execution of potentially obfuscated scripts."* (Volt Typhoon).
- T1021.002 from *"Block process creations originating from PSExec and WMI commands."*
- T1133 and T1059.001 from *"Enforce local firewall rules to block inbound SMB, RDP, WinRM, PowerShell…"* (UNC3944 hardening guide, which is almost entirely defensive yet qualified at 0.8).
- T1003.003 fired only by *ntdsutil* inside a "Remediation and Hardening" section (BREEZE COMET).

**Negation and detection content counted as behaviour (VERIFIED):**
- T1190 fired on *"…could not find definitive evidence of vulnerability exploitation."*
- T1071.001 fired on the text `technique = "T1071.` inside a detection rule.

**Real behaviour missed (VERIFIED):** *"cleared event logs"* does not trigger T1070.001, because the pattern is `\bcleared event log\b` and the trailing "s" breaks it.

**Field mix-ups (VERIFIED):**
- The `mitigations` list contains attacker actions, e.g. *"enable the SSH service so they could connect and install BRICKSTORM"*.
- The `procedures` list contains *"net traffic from edge devices…"*, because the `net` pattern matches inside "Internet".

**Chronology (VERIFIED):** in all 7 runs the attack chain was **exactly the fixed tactic order** (`TACTIC_TECHNIQUE_MAP` in `attack-chain.ts`), and every step summary was template text.
- Example: BREEZE COMET first mentions Execution, then Initial Access, then C2.
- The stored chain still reads Initial Access → Execution → Persistence.

**IOCs (VERIFIED):**
- 0 of 20 defanged IOCs captured in BREEZE COMET (e.g. `hxxps://procon[.]go[.]gov[.]br/…`, `dontpad[.]com`). `harvestIocs` has no domain or URL extraction and no re-fang step.
- Private IPs from sample logs and script comments are stored as IOCs (`10.0.0.255`, `10.0.9.9`).
- Role context such as *"Paste site used for data exfiltration"* is lost.

**Stored data agrees (VERIFIED):** in the stored-record sample, **49 of 50 retained reports have `mitreTechniques = 0`**, while most have attack-chain stages. The technique field is not being filled on the main path. For example, *The DFIR Report – Quantum Ransomware* has 43 IOCs and 9 chain stages but 0 techniques.

## 4. What AIE can answer reliably today

- **"Which stored reports mention X?"** for an exact keyword. Library search runs a case-insensitive regex over the full text (`repository.server.ts:556-594`). VERIFIED in code; UNVERIFIED on live data.
- **"Show me the text of report R."** Full extracted text is retrievable, except for the Microsoft and PDF failures above.
- **Exact CVE or technique-ID lookups in chat.** These hit the first two keyword tiers (`server.ts:3338-3373`). INFERRED.

## 5. What it cannot answer reliably, including features that look built but aren't

**Retrieval itself:**
- **Results are newest-first, not relevance-ordered** (`repository.server.ts:648`). The weighted `$text` index is created but **never queried**.
- **The chat is keyword lookup, not RAG.** It runs at most 4 documents through a regex intent gate with a hard-coded actor list.
  - Each document contributes metadata plus an excerpt of about 220 characters (maximum 450), never the full text or a passage.
  - Tier 3 discards any hit whose match is only in the body.
  - The prompt never asks for citations.
- **The citations shown aren't real citations.** The *"Verified Intelligence Evidence (N Reports)"* panel lists whatever was retrieved, attached server-side, with no check that the answer used them and no locators.
- **Some search clauses can never match.** They search `attackChain.description` and `.techniqueName`, which don't exist in the `AttackStep` type.
- **Long reports:** heuristic analysis sees the full text, but **every AI path sees only the first 4,500–4,800 characters** (`ai-manager.ts:571`, `agy-agent.ts:837`, `attack-chain.ts:360`).
  - In the test reports, 5–9 technique first-mentions each fell past that point.
  - So "AI Verified" scores and AI attack chains for long reports are based on the opening section only.
- **Not reproducible:** the chat logs the message, reply and sources, but not the tier used, the query sent, the candidates or the prompt. Combined with newest-first ordering, the same question gives different answers over time.

**Features presenting fabricated or unimplemented results (VERIFIED):**

| Screen / label | What actually happens |
|---|---|
| Dashboard actor counts | `max(real, nameHash % 6 + 7)` (`dashboard-analytics.ts:316-321`). Every known actor shows at least 7 reports even with none stored |
| Dashboard CVE velocity, regions, tactic bars, heatmap | Floors and fixed lists (`dashboard-analytics.ts:194-617`). The heatmap reads `step.techniqueId`, which doesn't exist, so real data is never counted |
| Dashboard threat flows; "Correlated with N acquired reports" | Fully static cards next to a real report count; no correlation is computed |
| "AI Verified · NN%" badge | For seed, URL and paste ingests, set from `qualityScore ≥ 0.5` or any IOC, with `aiQualityScore` floored at **75** and the reason text *"Verified by Automated AI Quality Gate"*, **with no AI call** (`repository.server.ts:771-786`) |
| Attack chain, "Sigma rules", "Atomic Red Team" | Fixed tactic template; Sigma items are one-line labels, not rules |
| `method: "llm"` on AI chains | Empty LLM fields are silently filled from the heuristic, so mixed origins carry one label |
| Crawler agent techniques | Always stored as `tactic: "Execution"` with `name = id` (`crawler.ts:1680-1686`) |
| Settings: Min IOC Confidence, evidence retention, auto-purge, export format | Saved and read back, **never used by any logic** |
| Marketplace install log | Prints `npm install…`, a sha512 integrity line, "Binary link registered" and "API Key verified" **without doing any of it** |

## 6. Gap list

Priorities follow brief §13.

| # | Gap: current behaviour | Why it matters | Expected behaviour | Pri | How to verify the fix |
|---|---|---|---|---|---|
| G1 | Dashboard, badge and log values are invented or padded (§5) | Analysts act on numbers that aren't real | Show real counts; show empty states; label heuristic results as heuristic | **P0** | With an empty DB, the dashboard shows zeros; no reason text claims AI unless an LLM ran |
| G2 | Crawler stores today's date as the publication date | Breaks every temporal question | Use the extracted date, else `unknown` | **P0** | Ingest the BRICKSTORM URL via the crawler; `publishedAt` = 2025-09-24 |
| G3 | `getReport` overwrites stored HTML; originals never kept | Evidence can't be re-inspected | Store the original (or a compressed copy) once; never rewrite it on read | **P0** | Hash before and after opening a report is unchanged |
| G4 | Microsoft (and similar) pages keep under 1% of their text | Whole seeded source effectively lost | Choose the largest content block, or use a readability parser | **P0** | Volt Typhoon ingest keeps more than 18k characters |
| G5 | No per-fact evidence | Can't answer "why does AIE say this?" | Each actor, technique, IOC and procedure stores `{quote, charStart, charEnd, section}` | **P0** | Every technique in the BRICKSTORM output has a quote that contains its trigger |
| G6 | Techniques fire on mitigation, negation and detection text; mitigations hold attacker actions | False TTPs flow into emulation candidates | Classify each sentence as offensive, defensive, negated or reference before matching; drop or label non-offensive hits | **P0** | The defensive-only triggers listed in §3 no longer produce techniques; UNC3944 guide yields 0 observed TTPs |
| G7 | Attack chain always uses the fixed tactic order | Chronology is invented | Order steps by position in the source text, with `order: reported \| inferred \| unknown`; never reorder to the tactic order | **P0** | BREEZE COMET chain follows first-mention order and is labelled |
| G8 | Actors come from a fixed list, with no link to techniques | Wrong attribution (APT29) | Only link actor and technique when they appear in the same sentence or paragraph, with evidence; otherwise mark the link unknown | **P0** | APT29 is not attributed for BRICKSTORM |
| G9 | Chat grounding is weak and citations are attached regardless | Answers look grounded but aren't | Retrieve passages (chunks of about 1–2k characters), pass them with IDs, require the model to cite IDs, and show only cited passages | **P0** | Ask a question whose answer is deep in a long report; the reply quotes that passage with a locator |
| G10 | AI sees only the first 4.8k characters | Long reports analysed from their opening section | Analyse in chunks, or pass only the most relevant passages | P1 | Late-section technique is found by the AI path |
| G11 | Defanged IOCs, domains and URLs dropped; private IPs stored; no role or date | IOC context lost | Re-fang, keep the original form, add domain and URL types, filter private ranges, capture the role from the nearby sentence | P1 | All 20 BREEZE COMET IOCs are captured with their original form |
| G12 | No victim, sector, geography, platform or objective | No advisory relevance possible | Extract with an evidence quote; separate "targeted" from "at risk" | P1 | Volt Typhoon shows US critical infrastructure with a quote |
| G13 | ATT&CK reference pages stored as vendor reports | Reference mixed with evidence | Tag them `reference` and exclude them from observed-behaviour views | P1 | T1046 page is labelled reference, publisher MITRE |
| G14 | Search ordered by date; `$text` index unused | Relevant results buried | Order by `$text` score (or BM25), then by date | P2 | Saved query set shows the expected doc in the top 3 |
| G15 | Chat logs aren't reproducible | Can't evaluate changes | Log the tier, query, candidates with scores, and prompt hash | P2 | Re-running a logged query reproduces the candidate list |
| G16 | Regex bugs (`event log\b`, `net` without a leading boundary) | Missed and false procedures | Fix the patterns; add unit tests per technique | P1 | Tests pass on the sentences above |

## 7. Recommended change order (smallest high-impact first)

1. **Stop showing invented data (G1)**, about a day of work. Remove the floors, static flows, the "AI verified" text without an AI call, the fake install logs and the unused settings. *Outcome:* every number on screen is real.
2. **Fix dates and evidence integrity (G2, G3)**, a few lines each. *Outcome:* temporal questions and re-inspection become possible.
3. **Fix the HTML extraction for multi-article pages (G4).** *Outcome:* the Microsoft source works.
4. **Sentence-level evidence plus offensive/defensive/negation tagging (G5, G6, G16)** in `analyzeThreatIntelligence`. This needs one new `evidence[]` field per entity, with no data redesign. *Outcome:* every technique has a quote, and mitigation text stops producing TTPs.
5. **Honest chronology (G7)** and **co-occurrence-scoped attribution (G8).** *Outcome:* no invented order or links.
6. **Passage retrieval for chat with enforced citations (G9, G10)**, using the existing `$text` index plus in-document chunking. *Outcome:* answers quote the supporting passage.
7. Then P1 context fields (G11–G13) and the P2 ranking and logging work (G14, G15).

## 8. Evaluation set

**Inputs** (raw HTML, hashes and harness): `scratchpad/eval/` in the review session. `run.sh` reruns it. Ask for it to be committed under `scripts/eval/` so it survives.

| # | Scenario | Resource | Result | Reason |
|---|---|---|---|---|
| 1 | Actor behaviour | BRICKSTORM, Octo Tempest | **FAIL** | Wrong actor (APT29); real actors missed; no behaviour linked to an actor |
| 2 | Technique attribution | Volt Typhoon, BRICKSTORM | **PARTIAL** | Some correct (LSASS, ntdsutil); denials, mitigations and rule text also fire; no actor link |
| 3 | Procedure detail | BRICKSTORM | **PARTIAL** | Real commands found (`Set-MpPreference -DisableRealtimeMonitoring $true`) alongside junk ("net traffic…") |
| 4 | Victim / targeting | All | **FAIL** | No field exists |
| 5 | Technology | BRICKSTORM, BREEZE COMET | **PARTIAL** | Tools found (Impacket, Chisel, AnyDesk); vCenter and ESXi not captured |
| 6 | Chronology | All 7 runs | **FAIL** | Always the fixed tactic order |
| 7 | Campaign corroboration | — | **NOT RUNNABLE** | Needs the live DB; no corroboration logic exists in code (INFERRED FAIL) |
| 8 | IOC context | BREEZE COMET | **FAIL** | 0 of 20 defanged IOCs; private IPs stored; no role |
| 9 | Defensive-content separation | UNC3944 hardening, Volt Typhoon | **FAIL** | TTPs produced from mitigation text only |
| 10 | Insufficient evidence | Microsoft stubs | **PARTIAL** | Short stubs are rejected, but negated statements still count as evidence |
| 11 | Long-resource retrieval | BRICKSTORM (passage at char 26,623) | **PARTIAL** | Heuristic keeps it; AI path cuts at 4.8k; search over the live DB is unverified |
| 12 | Advisory relevance | — | **NOT RUNNABLE** | No customer-context model exists (out of scope per the brief) |

## 9. Readiness decision

- **Safe to build on now:**
  - Source catalogue and feeds.
  - Full-text storage on the heuristic path.
  - Keyword search over the full body.
  - The qualification gate (it rejects stubs and junk reasonably).
- **Must fix first:** G1–G9. Until then, anything downstream (advisory context, emulation candidates) would carry invented chronology, false attributions and defensive text presented as attacker behaviour.
- **Still unverified:**
  - Live search ranking over the 654 retained records.
  - LLM-path output quality.
  - CISA and The DFIR Report extraction (blocked from the review environment).

---

## Appendix: earlier code-review issues re-checked at `e8ba24c`

**Fixed:**
- Type check is now clean (0 errors).
- `generateAgyOAuthUrl` import fixed.

**Partly fixed:**
- `agent-sandbox.ts` is now container-only.
- `agy-agent.ts:232-249` still falls back to the host binary.
- `--dangerously-skip-permissions` is still used in `agy-agent.ts`, `attack-chain.ts` and the new `warm-agent-service.ts`.

**Still present:**
- **Hard-coded MongoDB password**, now also copied into 5 scripts under `scripts/`, one of which runs `deleteMany`. **Rotate it.**
- `tlsAllowInvalidCertificates` is still on.
- No auth on any of the 63 server functions.
- API keys returned unmasked and exported in the diagnostic bundle.
- `testIntegrationConnection` can still send the env OpenAI key to a user-supplied endpoint.
- SSRF: no DNS check, raw `fetch` in the crawler, and `probeSourceFeeds`.
- `bin/aie.mjs` shell injection.
- `allow-scripts` iframes showing crawled HTML.
- Duplicate `0003` migrations.
- Fire-and-forget crawl jobs, and cancel still does nothing.
- Chat sends a Gemini model name to other providers.
- Substring report-ID match.
- Simhash input mismatch.
- `aiQualityScore` floor of 75.
- Unbounded `listReports`.

**New in this diff:**

| Area | Issue |
|---|---|
| PKCE | The verifier is a fixed constant committed in source (`marketplace-registry.ts:125`), so it protects nothing |
| OAuth redirect | The flow redirects to another product's callback (`antigravity.google/oauth-callback`) |
| OAuth codes and tokens | Codes and tokens from unauthenticated callers are stored in plaintext and exposed through `getMarketplaceData` |
| Developer token | A developer's personal Google token is auto-copied from `/home/havox/.gemini/…` into the container (`agent-sandbox.ts:351`), and a 20-character preview is returned unauthenticated (`server.ts:3637-3641`) |
| `warm-agent-service.ts`: shared agent | One agent process and one conversation is shared by every user and every crawl prompt, with permissions skipped. Prompt injection from crawled pages can carry into later chats |
| `warm-agent-service.ts`: deploy | Writes `.agy_conversation_id` to the working directory, which fails when deployed |
| `warm-agent-service.ts`: error path | Resolves the wrong turn and runs two turns at once |

**Checks:** lint has 60 errors (49 empty `catch {}`). Tests: 9 of 195 fail, all in the share-card injector and migration-plan tests. Because of `&&`, the second test suite never runs.

---

## Status after fixes (branch `claude/amazing-wright-jpxhtz`)

Re-checked with `npm run eval` (26/26 checks pass on the five public reports), unit tests (all new suites pass) and code review. Live MongoDB and live LLM providers were **not** reachable from the review environment, so the database search, chat and AI paths are verified by tests and type checks only.

| Gap | Status | What changed |
|---|---|---|
| G1 invented data | **Fixed** | Dashboard counts come only from stored reports, with empty states. "AI Verified" is set only by a model. Fake install logs are gone. Unused settings are marked "Not active yet". `scripts/repair-fabricated-fields.mjs` cleans existing records. |
| G2 wrong publication date | **Fixed** | The feed or page date is stored, or `null`. The repair script can clear crawl-day dates already stored. |
| G3 originals overwritten | **Fixed** | Opening a report never writes back. The original fetched content is stored once (gzip) and never overwritten. |
| G4 Microsoft text loss | **Fixed** | 92.8% / 95.7% of prose kept, up from about 1%. |
| G5 per-fact evidence | **Fixed** | Every technique, actor, malware, target, relationship and IOC carries exact quotes and offsets. A "View Evidence" UI highlights each quote in the full text. |
| G6 defensive/negated text as TTPs | **Fixed** | Sentences are labelled observed / inferred / defensive / negated / hypothetical / reference. Non-adversary statements are listed as "not counted". The UNC3944 hardening guide now yields 0 observed techniques. |
| G7 invented chronology | **Fixed** | Chain steps follow source order (`orderBasis: reported`). With fewer than 2 steps the order is "unknown". |
| G8 co-occurrence attribution | **Fixed** | Relationships are created only from the same observed sentence. APT29 is no longer attributed for BRICKSTORM; UNC5221 is. |
| G9 weak chat grounding | **Fixed (untested live)** | BM25 passage retrieval over the full text, with required `[S#]` citations. Only cited passages are shown, uncited claims are flagged, and the reply states an evidence gap instead of guessing. |
| G10 AI sees first 4.8k chars | **Partly** | Chat retrieval reads the whole document. AI qualification and AI attack-chain synthesis still read only the opening section; the deterministic evidence is attached to their output. |
| G11 IOC context | **Fixed** | Indicators are re-fanged with the original text kept, domain/url/email/sha1 types are added, private IPs are dropped, and roles are recorded only when stated (BREEZE COMET: 33 defanged captured). |
| G12 targeting context | **Partly** | Sector, geography, platform and objective are extracted with status (targeted / compromised / at risk / mentioned) and quotes. Coverage depends on the keyword lists. |
| G13 ATT&CK pages as reports | **Open** | Still not tagged as reference material. |
| G14 relevance ranking | **Fixed (untested live)** | `$text` relevance ranking with best-passage snippets and paging. |
| G15 reproducibility | **Fixed** | Each chat answer stores its query, candidates, passages and prompt hash. `npm run eval` gives a repeatable evaluation set. |
| G16 regex bugs | **Fixed** | Unit tests cover the reported sentences. |

Security items from the code review (sign-in plus allowlist, secret handling, agent sandbox, SSRF, CLI injection, script-free previews, migrations, crawl locking) are fixed in the same branch. See the PR description.

### Still open / next steps
1. **Rotate the MongoDB password.** The old one is in git history.
2. **Re-analyse existing reports** so stored records gain `analysis.evidence`. Records analysed before this change show an "analysed before evidence tracking" notice.
3. **Cross-source corroboration and conflicts:** not built yet (scenario 7).
4. **ATT&CK reference-page tagging (G13)** and **footer leakage:** related-post text can still be read as observed.
5. **AI qualification and synthesis** on chunked or retrieved passages instead of the first 4.8k chars.
6. **Live verification:** run search and chat against the real library with a configured provider.
