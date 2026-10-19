# AIE advisories & detection simulation

How AIE turns library evidence and ATT&CK into an evidence-backed threat advisory,
then validates detection coverage with purple-team simulation runs.

```
Subject (actor · campaign · malware · CVE · selected reports)
  │
  ▼
resolve against library + ATT&CK ──► purple path ──► CISA KEV enrich ──► buildAdvisoryContent (pure)
  │                                                                              │
  │                                                                              ▼
  │                                                              AdvisoryContent (summary, behaviours,
  │                                                              targeting, vulns, IOCs, detections,
  │                                                              recommendations, gaps, sources, path)
  ▼                                                                              │
AdvisoryRecord ◄── analyst overrides (title/severity/summary/notes, survive regen) ◄┘
  │
  ▼
SimulationRun(s) ──► record step outcomes ──► complete ──► deriveFindings ──► detection coverage
```

Every fact in an advisory is traceable to a library report or to ATT&CK
attribution; detection queries are always templates, never presented as
production rules.

## Generating an advisory

A subject is one of five kinds (`AdvisorySubjectKind`): a threat **actor**
(ATT&CK group id or name), a **campaign** (C-id or name), **malware** (ATT&CK
software id or name), a **vulnerability** (one or more CVE ids), or a set of
selected library **reports**.

Generation (`server-advisories.ts → generateContent`):

1. **Resolve the subject.** Actors/campaigns reuse the purple-path seed resolver
   (`resolveSeed`, shared with `server-emulation.ts`); malware resolves ATT&CK
   software for attribution and matches reports by name; a CVE matches reports
   that cite it; selected reports are taken verbatim.
2. **Gather evidence.** The matched library reports (with their analysis and
   IOCs) and the techniques ATT&CK attributes to the subject.
3. **Build the simulation path.** `generatePurplePath` orders candidate
   techniques into an attack path (the advisory's simulation scope).
4. **Enrich.** CVEs found in the evidence are looked up in the CISA KEV index.
5. **Compose.** `buildAdvisoryContent` (pure, in `advisory/build.ts`) produces
   the `AdvisoryContent`: BLUF summary, key points, severity + reasons, observed
   behaviours (with observed/inferred/mapped evidence counts and citations),
   ATT&CK-attributed techniques without library evidence, targeting,
   vulnerabilities, indicators, detection guidance, recommendations (patch /
   ATT&CK mitigation / source guidance), intelligence gaps and sources.

"Regenerate" re-runs this against the current library while preserving the
analyst overrides and the still-valid scope selection.

## Analyst overrides

`AdvisoryRecord.overrides` holds the analyst's edits to `title`, `severity`,
`severityNote`, `summary` and `notes`. They always win over the generated
content (see `advisory/export.ts → effective*`) and survive regeneration, so an
exported advisory reflects what the analyst approved.

## Detection simulation & findings

A `SimulationRun` records, for each technique in the advisory's scope, what the
environment's controls did: `prevented`, `detected`, `logged`, `missed`,
`not_run` or `not_applicable`. On completion:

- `computeRunMetrics` (in `advisory/validation.ts`) gives prevention / detection
  / visibility rates and a per-tactic matrix.
- `deriveFindings` turns every executed-but-not-prevented-or-detected step into a
  finding, with a severity weighing the outcome, the step's priority and its
  risk class, a recommended detection (telemetry + hypothesis + query template)
  and ATT&CK mitigations, plus a trend versus the previous completed run.

## Export

`exportAdvisory` renders an advisory to **Markdown** (a complete, shareable
document) or **JSON** (stable, machine-readable, overrides applied). Both are
pure (`advisory/export.ts`) and carry the TLP and a "queries are templates"
footer.

## Persistence

`advisories-repo.server.ts` stores `AdvisoryRecord`s and their `SimulationRun`
children. With `MONGODB_URI` set it uses dedicated collections
(`aie_advisories`, `aie_simulation_runs`); otherwise it falls back to
PGLite/Postgres JSON-document tables. The store is a thin key/value layer; the
server functions do read-modify-write patches, number allocation
(`ADV-YYYY-NNNN`, run numbers per advisory) and summary derivation.

## Where it lives

| Concern | File |
| --- | --- |
| Domain types | `src/lib/aie/advisory/types.ts` |
| Pure builder | `src/lib/aie/advisory/build.ts` (+ `build.test.ts`) |
| Validation / findings | `src/lib/aie/advisory/validation.ts` (+ `validation.test.ts`) |
| Export (Markdown / JSON) | `src/lib/aie/advisory/export.ts` (+ `export.test.ts`) |
| Persistence | `src/lib/mongodb/advisories-repo.server.ts` |
| Server functions | `src/lib/aie/server-advisories.ts` |
| UI — list + create | `src/routes/advisories.tsx` |
| UI — detail + simulation | `src/routes/advisories_.$advisoryId.tsx` |

All advisory server functions require an authenticated analyst
(`analystMiddleware`); edits are attributed to the request identity.
