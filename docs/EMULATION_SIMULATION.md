# Emulation & simulation value

AIE's library exists to feed **adversary emulation** (a red or purple team rebuilding an attack step
by step) and **attack simulation** (a BAS platform or exercise replaying the behaviour and checking
that defences see it). The technical-depth check (`src/lib/aie/technical-depth.ts`) answers *"is
this technical threat intelligence?"*. The emulation & simulation value
(`src/lib/aie/emulation-simulation.ts`) answers the next two questions:

- *Could a team emulate or simulate what it describes?* — the procedures, in order, with the files,
  paths, commands, tools and encryption the attacker used.
- *What should defenders see when it runs?* — the event IDs, log sources, detection content (Sigma,
  YARA, KQL, SPL, Suricata) and C2 network behaviour (protocol, URI, user agent, port, DNS) the
  report names, so a simulation can be validated against them.

## Grades

| Grade | What the report gives | Example |
| --- | --- | --- |
| **Attack chain** | A multi-step chain with concrete procedures in order: files, paths, commands, tools, encryption | "PowerShell downloads X.msi … msiexec installs it silently … DeElevate64.exe loads the patched DLL … the loader decrypts the payload with AES-256 and maps it in memory" |
| **Procedures** | Concrete procedures without the full chain | A DLL side-loading walk-through, a command list |
| **Context** | Actor, campaign, malware or indicator context; few procedures | A campaign summary, an IOC list |
| **News / notice** | News, patch notes, vulnerability notices without attacker procedures | "Vendor fixes CVE-… (CVSS 9.9), upgrade to 12.3.2" |

Every grade comes with its reasons, the procedure steps quoted from the report and the telemetry /
detections to validate against, so it can be checked. Telemetry and C2 behaviour raise the score;
a report that is mostly detection content (three or more event IDs, log sources or rules) counts as
at least *Context*.

## Where it is used

- **Crawler**: Settings → crawler → *Min emulation & simulation value* (default *Context or better*). News and
  patch notes are not ingested, even when they name a CVE. CERT / government advisories and tier-1
  sources are exempt, and so is a report in which the AI reviewer found real procedures.
- **Crawler discovery**: every run also searches for attack-chain write-ups (infection chains,
  side-loading, in-memory loaders, ClickFix delivery, new tradecraft), half of them restricted to
  research publishers that write such walk-throughs. Patch / update notices and `security-news`
  URLs rank lower before anything is fetched.
- **Library**: the *Emulation & simulation value* filter, the *Emulation & simulation value* sort and a badge on every report.
  Stored reports are graded once by the library check; news-grade reports are hidden as *low
  emulation & simulation value* (restorable from the Hidden view, never deleted). CERT advisories, structured
  records and anything an analyst restored are not hidden.
- **Report page**: the *Emulation & simulation value* section shows the grade, why, and the **emulation & simulation brief**:
  the report retold in the shared-intel format (category, what it is, infection chain steps, what is
  new, **what to validate**, source, defanged link), built only from sentences in the report. *Copy* puts it on the
  clipboard.

## AI verification

*Analyse with AI* adds an emulation & simulation assessment to the grounded analysis
(`src/lib/aie/report-ai-analysis.ts`): a grade, whether the activity is reproducible from the report,
the procedure steps, novelty claims and the detections a simulation should trigger (each with a quote
that must appear in the report), what an
emulation or simulation team would still need, and an honest note on how much of the chain the report documents.
The grade the AI gives is lowered to what its verified steps support (an attack chain needs at least
four verified steps, procedures at least two), and the page says when that happened. The Library then
uses the AI's verified grade.
