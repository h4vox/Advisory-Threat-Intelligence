# Work in progress — resume point

Kept in the repo so work can stop at any time and resume on "continue".

## Done (this branch)
- Crawler **Real time** run mode: full crawls back to back with a 1–30 min pause; `JOB-RT-` jobs.
- Real time is stronger than a manual run: each run resumes a per-source **archive cursor**
  (`docType: "archive_cursor"`) and walks 6 listing pages deeper, skipping pages of known
  articles, restarting at the end of the archive. Settings shows "Next crawl: N min after the
  current run ends" instead of the scheduled time.
- Emulation **& simulation** naming and the simulation part (what defenders should see:
  event IDs, log sources, detections, C2 behaviour) — `docs/EMULATION_SIMULATION.md`.
- Intel Graph mapping completeness: evidence labeller fixes (Defense Evasion headings, ATT&CK
  mapping-table rows), graph builder fixes (dangling else, attack-chain techniques, AI-verified
  indicators, named binaries), background **intel refresh** (rules re-extraction + AI analysis
  at `aiBackfillPerHour`, default 30), coverage shown on the Intel Graph.

## Next (not started)
1. Verify real time on a live install: compare `JOB-RT-` "found"/"ingested" with manual runs
   after a few runs; check `[ARCHIVE]` log lines and that cursors advance.
2. Sources without `paginationPattern` and without a "next page" link get no archive walk:
   add sitemap-based deep walk for them (cursor by sitemap date window).
3. Older backlog: security audit items 3–6, DB migration phase 2, AGY persistent session,
   inference gateway.
