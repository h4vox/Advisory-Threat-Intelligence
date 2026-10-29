# Emulation value

AIE's library exists to feed attack emulation and simulation: reports that walk through how an
attack was carried out, step by step, so a red or purple team can rebuild it. The technical-depth
check (`src/lib/aie/technical-depth.ts`) answers *"is this technical threat intelligence?"*. The
emulation value (`src/lib/aie/emulation-value.ts`) answers the next question: *"could a team replay
what it describes?"*

## Grades

| Grade | What the report gives | Example |
| --- | --- | --- |
| **Attack chain** | A multi-step chain with concrete procedures in order: files, paths, commands, tools, encryption | "PowerShell downloads X.msi … msiexec installs it silently … DeElevate64.exe loads the patched DLL … the loader decrypts the payload with AES-256 and maps it in memory" |
| **Procedures** | Concrete procedures without the full chain | A DLL side-loading walk-through, a command list |
| **Context** | Actor, campaign, malware or indicator context; few procedures | A campaign summary, an IOC list |
| **News / notice** | News, patch notes, vulnerability notices without attacker procedures | "Vendor fixes CVE-… (CVSS 9.9), upgrade to 12.3.2" |

Every grade comes with its reasons and the procedure steps quoted from the report, so it can be
checked.

## Where it is used

- **Crawler**: Settings → crawler → *Min emulation value* (default *Context or better*). News and
  patch notes are not ingested, even when they name a CVE. CERT / government advisories and tier-1
  sources are exempt, and so is a report in which the AI reviewer found real procedures.
- **Crawler discovery**: every run also searches for attack-chain write-ups (infection chains,
  side-loading, in-memory loaders, ClickFix delivery, new tradecraft), half of them restricted to
  research publishers that write such walk-throughs. Patch / update notices and `security-news`
  URLs rank lower before anything is fetched.
- **Library**: the *Emulation value* filter, the *Emulation value* sort and a badge on every report.
  Stored reports are graded once by the library check; news-grade reports are hidden as *low
  emulation value* (restorable from the Hidden view, never deleted). CERT advisories, structured
  records and anything an analyst restored are not hidden.
- **Report page**: the *Emulation value* section shows the grade, why, and the **emulation brief**:
  the report retold in the shared-intel format (category, what it is, infection chain steps, what is
  new, source, defanged link), built only from sentences in the report. *Copy* puts it on the
  clipboard.

## AI verification

*Analyse with AI* adds an emulation assessment to the grounded analysis
(`src/lib/aie/report-ai-analysis.ts`): a grade, whether the activity is reproducible from the report,
the procedure steps and novelty claims (each with a quote that must appear in the report), what an
emulation team would still need, and an honest note on how much of the chain the report documents.
The grade the AI gives is lowered to what its verified steps support (an attack chain needs at least
four verified steps, procedures at least two), and the page says when that happened. The Library then
uses the AI's verified grade.
