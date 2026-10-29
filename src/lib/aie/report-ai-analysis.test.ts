import { test } from "node:test";
import assert from "node:assert/strict";
import { ANALYSIS_TEXT_CHARS, buildAnalysisPrompt, groundReportAnalysis, normaliseForMatch } from "./report-ai-analysis.ts";

const TECH: Record<string, string> = { "T1566.001": "Spearphishing Attachment", T1059: "Command and Scripting Interpreter", T1071: "Application Layer Protocol" };
const opts = { techniqueName: (id: string) => TECH[id], provider: "Test", model: "m", truncated: false, now: new Date("2026-10-26T00:00:00Z") };

const REPORT = `Black Basta affiliates target manufacturers
Published 06 June 2022
The actor, tracked as Storm-1811 and also known as UNC4393, sent phishing emails with a malicious Excel attachment to staff at manufacturing firms in Germany.
The macro launched PowerShell to fetch the QakBot loader from hxxp://update-check[.]example[.]net/a.bin.
QakBot beaconed to 185.220.101[.]4 over HTTPS for command and control.
SHA256: 0f1e2d3c4b5a69788796a5b4c3d2e1f00f1e2d3c4b5a69788796a5b4c3d2e1f0
The group exploited CVE-2024-1709 on exposed ScreenConnect servers.`;

test("normaliseForMatch re-fangs, folds case, quotes and whitespace", () => {
  assert.equal(normaliseForMatch("  Hxxp://Evil[.]com/“a”  \n b"), 'http://evil.com/"a" b');
});

test("buildAnalysisPrompt wraps the report as untrusted data and marks truncation", () => {
  const wrap = (s: string) => `<untrusted_source_content>\n${s}\n</untrusted_source_content>`;
  const { prompt, truncated } = buildAnalysisPrompt({ title: "T", url: "https://x", text: "a".repeat(ANALYSIS_TEXT_CHARS + 10) }, wrap, "NOTICE");
  assert.equal(truncated, true);
  assert.match(prompt, /^NOTICE/);
  assert.match(prompt, /<untrusted_source_content>/);
  assert.ok(prompt.length < ANALYSIS_TEXT_CHARS + 5000);
});

test("indicators: kept only when the report lists them, defanged forms accepted, invented ones dropped", () => {
  const r = groundReportAnalysis(
    {
      iocs: [
        { type: "ipv4", value: "185.220.101[.]4", context: "C2" },
        { type: "url", value: "http://update-check.example.net/a.bin" },
        { type: "sha256", value: "0F1E2D3C4B5A69788796A5B4C3D2E1F00F1E2D3C4B5A69788796A5B4C3D2E1F0" },
        { type: "cve", value: "cve-2024-1709" },
        { type: "ipv4", value: "10.9.9.9" },
        { type: "domain", value: "invented-domain.example.org" },
        { type: "md5", value: "not-a-hash" },
        { type: "ipv4", value: "185.220.101.4" },
      ],
    },
    REPORT,
    opts,
  );
  assert.deepEqual(
    r.iocs.map((i) => `${i.type}:${i.value}`),
    ["ipv4:185.220.101.4", "url:http://update-check.example.net/a.bin", "sha256:0F1E2D3C4B5A69788796A5B4C3D2E1F00F1E2D3C4B5A69788796A5B4C3D2E1F0", "cve:CVE-2024-1709"],
  );
  assert.equal(r.iocs[0].context, "C2");
  assert.equal(r.dropped.iocs, 3);
});

test("attack chain: steps need a verbatim quote and an ATT&CK tactic; unknown technique IDs are left off", () => {
  const r = groundReportAnalysis(
    {
      attackChain: [
        { stage: "Initial Access", techniqueId: "T1566.001", summary: "Phishing with an Excel attachment", quote: "sent phishing emails with a malicious Excel attachment to staff at manufacturing firms in Germany." },
        { stage: "execution", techniqueId: "T9999", summary: "Macro ran PowerShell", quote: "The macro launched PowerShell to fetch the QakBot loader" },
        { stage: "Command and Control", techniqueId: "T1071", summary: "Beaconing", quote: "QakBot beaconed to 185.220.101.4 over HTTPS for command and control." },
        { stage: "Exfiltration", techniqueId: "T1041", summary: "Invented step", quote: "The actor exfiltrated 2 TB of data to a cloud bucket." },
        { stage: "Hacking", summary: "Bad stage", quote: "The group exploited CVE-2024-1709 on exposed ScreenConnect servers." },
      ],
    },
    REPORT,
    opts,
  );
  assert.deepEqual(r.attackChain.map((s) => [s.order, s.stage, s.technique?.id ?? null]), [
    [1, "Initial Access", "T1566.001"],
    [2, "Execution", null],
    [3, "Command and Control", "T1071"],
  ]);
  assert.equal(r.attackChain[0].technique?.name, "Spearphishing Attachment");
  assert.equal(r.dropped.steps, 2);
});

test("adversary profile keeps only names and terms present in the report", () => {
  const r = groundReportAnalysis(
    {
      adversary: {
        name: "Storm-1811",
        aliases: ["UNC4393", "Storm-1811", "FIN99"],
        type: "cybercrime",
        motivation: "financial",
        sectors: ["manufacturing", "healthcare"],
        regions: ["Germany", "Japan"],
        malware: ["QakBot", "Cobalt Strike"],
        tools: ["ScreenConnect"],
        summary: "Storm-1811 deploys QakBot.",
      },
    },
    REPORT,
    opts,
  );
  assert.ok(r.adversary);
  assert.equal(r.adversary.name, "Storm-1811");
  assert.deepEqual(r.adversary.aliases, ["UNC4393"]);
  assert.deepEqual(r.adversary.sectors, ["manufacturing"]);
  assert.deepEqual(r.adversary.regions, ["Germany"]);
  assert.deepEqual(r.adversary.malware, ["QakBot"]);
  assert.equal(r.adversary.type, "cybercrime");
  assert.equal(r.dropped.adversaryTerms, 4);
});

test("an adversary the report never names is not invented", () => {
  const r = groundReportAnalysis({ adversary: { name: "APT28", aliases: [], malware: [], tools: [], sectors: [] } }, REPORT, opts);
  assert.equal(r.adversary, null);
});

test("summary sentences citing identifiers the report lacks are removed", () => {
  const r = groundReportAnalysis(
    { summary: "Affiliates phished manufacturers. They exploited CVE-2024-1709. They also used CVE-2023-9999 and T1486." },
    REPORT,
    opts,
  );
  assert.equal(r.summary, "Affiliates phished manufacturers. They exploited CVE-2024-1709.");
  assert.equal(r.dropped.summarySentences, 1);
});

test("publication date accepted only when the quoted line states that date", () => {
  assert.deepEqual(groundReportAnalysis({ publishedDate: { date: "2022-06-06", quote: "Published 06 June 2022" } }, REPORT, opts).publishedDate, {
    date: "2022-06-06",
    quote: "Published 06 June 2022",
  });
  assert.equal(groundReportAnalysis({ publishedDate: { date: "2022-06-07", quote: "Published 06 June 2022" } }, REPORT, opts).publishedDate, null);
  assert.equal(groundReportAnalysis({ publishedDate: { date: "2023-01-01", quote: "Published 1 January 2023" } }, REPORT, opts).publishedDate, null);
});

test("key findings need a supporting quote", () => {
  const r = groundReportAnalysis(
    {
      keyFindings: [
        { text: "ScreenConnect exploited", quote: "The group exploited CVE-2024-1709 on exposed ScreenConnect servers." },
        { text: "Invented", quote: "The actor used a zero-day in a VPN appliance." },
      ],
    },
    REPORT,
    opts,
  );
  assert.equal(r.keyFindings.length, 1);
  assert.equal(r.dropped.findings, 1);
});

test("review verdicts are normalised; anything unexpected becomes unsure", () => {
  assert.deepEqual(groundReportAnalysis({ review: { verdict: "useful", confidence: 1.4, reasons: ["Intrusion details"] } }, REPORT, opts).review, {
    verdict: "useful",
    confidence: 1,
    reasons: ["Intrusion details"],
  });
  assert.equal(groundReportAnalysis({ review: { verdict: "delete it" } }, REPORT, opts).review.verdict, "unsure");
  assert.equal(groundReportAnalysis({}, REPORT, opts).review.verdict, "unsure");
});

test("a non-object answer is an error, not an empty analysis", () => {
  assert.throws(() => groundReportAnalysis("text", REPORT, opts));
  assert.throws(() => groundReportAnalysis([1], REPORT, opts));
});

test("emulation assessment: quotes are verified and an unsupported 'attack chain' grade is lowered", () => {
  const r = groundReportAnalysis(
    {
      emulationSimulation: {
        grade: "chain",
        reproducible: "yes",
        steps: [
          { text: "Macro launches PowerShell to fetch QakBot", quote: "The macro launched PowerShell to fetch the QakBot loader from hxxp://update-check[.]example[.]net/a.bin." },
          { text: "QakBot beacons over HTTPS", quote: "QakBot beaconed to 185.220.101[.]4 over HTTPS for command and control." },
          { text: "Invented step", quote: "The loader then injected itself into explorer.exe." },
        ],
        novel: [{ text: "New loader", quote: "A completely new loader never seen before." }],
        missing: ["How the Excel lure reached staff in detail"],
        note: "Initial access and C2 are described; execution details are thin.",
      },
    },
    REPORT,
    opts,
  );
  const e = r.emulationSimulation!;
  assert.equal(e.claimedGrade, "chain");
  assert.equal(e.grade, "procedures", "two verified steps support procedures, not a chain");
  assert.equal(e.steps.length, 2);
  assert.equal(e.novel.length, 0, "a novelty claim without a quote from the text is dropped");
  assert.equal(e.reproducible, "partly");
  assert.match(e.gradeNote ?? "", /only 2 procedure steps/);
  assert.deepEqual(e.missing, ["How the Excel lure reached staff in detail"]);
});

test("emulation assessment: a news grade stays news, a missing block is null", () => {
  assert.equal(groundReportAnalysis({ emulationSimulation: { grade: "news", reproducible: "yes", steps: [] } }, REPORT, opts).emulationSimulation?.reproducible, "no");
  assert.equal(groundReportAnalysis({}, REPORT, opts).emulationSimulation, null);
});
