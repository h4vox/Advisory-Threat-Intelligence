/**
 * Advisory builder: turns the library reports relevant to one threat into an evidence-grounded
 * advisory. Pure; ATT&CK lookups are injected (see server-advisory.ts), so it runs in unit tests.
 *
 * Grounding rules (AIE retrieval brief §3–§5):
 *  - Behaviours come from the reports' labelled evidence (observed / inferred) or their technique
 *    lists (mapped); defensive, negated and hypothetical statements are never adversary activity.
 *  - ATT&CK attribution is kept separate from what the library observed.
 *  - Targeting keeps the source's status (compromised / targeted / at risk / mentioned).
 *  - Indicators keep their first-seen date and source; they are historical, not live blocklists.
 *  - Anything the sources do not state becomes a known gap, never a guess.
 */
import { libraryEvidenceFromReport } from "../purple/evidence.ts";
import type { PurplePath } from "../purple/types.ts";
import type { IntelAnalysis, IocHit, SourceTier, TargetingFact } from "../types.ts";
import type {
  AdvisoryBehaviour,
  AdvisoryContent,
  AdvisoryDetection,
  AdvisoryGap,
  AdvisoryIndicator,
  AdvisoryRecommendation,
  AdvisorySeverity,
  AdvisorySource,
  AdvisorySubject,
  AdvisoryTargeting,
  AdvisoryVulnerability,
  KevDetails,
  SourceCitation,
} from "./types.ts";

/** The report fields the builder needs (a ReportListItem satisfies it). */
export type AdvisoryReport = {
  id: string;
  title: string;
  publisher?: string;
  sourceName?: string;
  url?: string;
  canonicalUrl?: string;
  publishedAt: string | null;
  sourceTier?: SourceTier;
  sourceConfidence?: number;
  analysis?: IntelAnalysis | null;
  iocs?: IocHit[];
};

export type AdvisoryBuildInput = {
  subject: AdvisorySubject;
  reports: AdvisoryReport[];
  /** Techniques ATT&CK attributes to the subject (group, campaign or software). */
  attributed: string[];
  path: PurplePath;
  kev: Map<string, KevDetails>;
  kevSynced: boolean;
  emulationSynced: boolean;
  now?: string;
};

export type AdvisoryBuildDeps = {
  getTechnique: (id: string) => { id: string; name: string; tactics: string[]; mitigations?: string[] } | undefined;
  getMitigation: (id: string) => { id: string; name: string; description: string } | undefined;
  mitigationsForTechniques: (ids: string[]) => Array<{ id: string; name: string; description: string; techniques: string[] }>;
  tacticRank: (tactic: string | undefined) => number;
  attackVersion: string | null;
};

const CVE_RE = /^CVE-\d{4}-\d{4,7}$/i;
const STATUS_RANK: Record<TargetingFact["status"], number> = { compromised: 4, targeted: 3, at_risk: 2, mentioned: 1 };
const KIND_ORDER: TargetingFact["kind"][] = ["sector", "geography", "victim_type", "platform", "objective"];
const NOT_INDICATORS = new Set(["cve", "technique"]);
const MAX_CITATIONS = 3;
const MAX_INDICATORS = 300;
const MONTHS = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];

function ms(iso: string | null | undefined): number {
  const t = iso ? Date.parse(iso) : NaN;
  return Number.isFinite(t) ? t : NaN;
}

export function monthYear(iso: string | null | undefined): string | null {
  const t = ms(iso);
  if (!Number.isFinite(t)) return null;
  const d = new Date(t);
  return `${MONTHS[d.getUTCMonth()]} ${d.getUTCFullYear()}`;
}

function plural(n: number, word: string, many = `${word}s`) {
  return `${n} ${n === 1 ? word : many}`;
}

function list(items: string[], max = 4): string {
  const shown = items.slice(0, max);
  const rest = items.length - shown.length;
  if (shown.length <= 1) return shown.join("");
  const head = shown.slice(0, -1).join(", ");
  return rest > 0 ? `${shown.join(", ")} and ${rest} more` : `${head} and ${shown[shown.length - 1]}`;
}

function publisherOf(r: AdvisoryReport): string {
  return r.publisher || r.sourceName || "Unknown publisher";
}

function cite(r: AdvisoryReport, extra: Partial<SourceCitation> = {}): SourceCitation {
  return { reportId: r.id, title: r.title, publisher: publisherOf(r), publishedAt: r.publishedAt ?? null, ...extra };
}

function pushCitation(arr: SourceCitation[], c: SourceCitation) {
  if (arr.some((x) => x.reportId === c.reportId && x.quote === c.quote)) return;
  // Prefer quoted citations: a quote-less one never displaces a quoted one.
  if (arr.length >= MAX_CITATIONS) {
    if (!c.quote) return;
    const i = arr.findIndex((x) => !x.quote);
    if (i === -1) return;
    arr.splice(i, 1);
  }
  arr.push(c);
}

/** Quote → section heading, from the report's labelled evidence. */
function sectionIndex(a: IntelAnalysis | null | undefined): Map<string, string> {
  const m = new Map<string, string>();
  for (const f of a?.evidence?.techniques ?? []) for (const e of f.evidence ?? []) if (e.quote && e.section) m.set(e.quote, e.section);
  return m;
}

// ---------------------------------------------------------------------------
// Sections
// ---------------------------------------------------------------------------

function buildBehaviours(input: AdvisoryBuildInput, deps: AdvisoryBuildDeps, unknownIds: Set<string>): AdvisoryBehaviour[] {
  const inPath = new Set(input.path.steps.map((s) => s.technique.id));
  const attributed = new Set(input.attributed.map((x) => x.toUpperCase()));
  const byId = new Map<string, AdvisoryBehaviour>();
  for (const r of input.reports) {
    const ev = libraryEvidenceFromReport({ id: r.id, title: r.title, publishedAt: r.publishedAt, sourceConfidence: r.sourceConfidence ?? 0.6, analysis: r.analysis });
    const sections = sectionIndex(r.analysis);
    for (const t of ev.techniques) {
      const k = deps.getTechnique(t.id);
      if (!k) {
        unknownIds.add(t.id);
        continue;
      }
      let b = byId.get(t.id);
      if (!b) {
        const mids = k.mitigations?.length ? k.mitigations : (deps.getTechnique(t.id.split(".")[0])?.mitigations ?? []);
        b = {
          techniqueId: k.id,
          name: k.name,
          tactic: k.tactics[0] ?? t.tactic ?? "Unknown",
          observedIn: 0,
          inferredIn: 0,
          mappedIn: 0,
          attributedByAttack: attributed.has(k.id) || attributed.has(k.id.split(".")[0]),
          inPath: inPath.has(k.id),
          citations: [],
          mitigations: mids.map((id) => deps.getMitigation(id)).filter((m): m is NonNullable<typeof m> => Boolean(m)).map((m) => ({ id: m.id, name: m.name })),
        };
        byId.set(t.id, b);
      }
      if (t.label === "observed") b.observedIn += 1;
      else if (t.label === "inferred") b.inferredIn += 1;
      else b.mappedIn += 1;
      const quote = t.quotes[0];
      pushCitation(b.citations, cite(r, { label: t.label, ...(quote ? { quote, ...(sections.get(quote) ? { section: sections.get(quote) } : {}) } : {}) }));
    }
  }
  return [...byId.values()].sort(
    (a, b) => deps.tacticRank(a.tactic) - deps.tacticRank(b.tactic) || b.observedIn - a.observedIn || b.inferredIn - a.inferredIn || a.techniqueId.localeCompare(b.techniqueId, "en", { numeric: true }),
  );
}

function buildTargeting(reports: AdvisoryReport[]): AdvisoryTargeting[] {
  const byKey = new Map<string, AdvisoryTargeting & { _reports: Set<string> }>();
  for (const r of reports) {
    for (const f of r.analysis?.evidence?.targeting ?? []) {
      const value = f.value.trim();
      if (!value) continue;
      const key = `${f.kind}:${value.toLowerCase()}`;
      let t = byKey.get(key);
      if (!t) {
        t = { kind: f.kind, value, status: f.status, reports: 0, citations: [], _reports: new Set() };
        byKey.set(key, t);
      }
      if (STATUS_RANK[f.status] > STATUS_RANK[t.status]) t.status = f.status;
      t._reports.add(r.id);
      const e = f.evidence?.[0];
      pushCitation(t.citations, cite(r, { label: f.status, ...(e?.quote ? { quote: e.quote } : {}), ...(e?.section ? { section: e.section } : {}) }));
    }
  }
  return [...byKey.values()]
    .map(({ _reports, ...t }) => ({ ...t, reports: _reports.size }))
    .sort((a, b) => KIND_ORDER.indexOf(a.kind) - KIND_ORDER.indexOf(b.kind) || STATUS_RANK[b.status] - STATUS_RANK[a.status] || b.reports - a.reports || a.value.localeCompare(b.value));
}

function buildVulnerabilities(input: AdvisoryBuildInput): AdvisoryVulnerability[] {
  const byCve = new Map<string, AdvisoryVulnerability>();
  const touch = (id: string) => {
    const cve = id.trim().toUpperCase();
    let v = byCve.get(cve);
    if (!v) {
      v = { cveId: cve, citations: [], ...(input.kev.get(cve) ? { kev: input.kev.get(cve) } : {}) };
      byCve.set(cve, v);
    }
    return v;
  };
  for (const id of input.subject.cveIds ?? []) if (CVE_RE.test(id)) touch(id);
  for (const r of input.reports) {
    const ids = new Set<string>();
    for (const v of r.analysis?.vulnerabilities ?? []) if (CVE_RE.test(v.trim())) ids.add(v.trim().toUpperCase());
    for (const i of r.iocs ?? []) if (i.kind === "cve" && CVE_RE.test(i.value)) ids.add(i.value.toUpperCase());
    for (const id of ids) {
      const quote = (r.iocs ?? []).find((i) => i.kind === "cve" && i.value.toUpperCase() === id)?.evidence?.quote;
      pushCitation(touch(id).citations, cite(r, quote ? { quote } : {}));
    }
  }
  const ransom = (v: AdvisoryVulnerability) => (v.kev?.ransomwareUse?.toLowerCase() === "known" ? 1 : 0);
  return [...byCve.values()].sort((a, b) => ransom(b) - ransom(a) || Number(Boolean(b.kev)) - Number(Boolean(a.kev)) || b.citations.length - a.citations.length || b.cveId.localeCompare(a.cveId, "en", { numeric: true }));
}

function buildIndicators(reports: AdvisoryReport[]): { indicators: AdvisoryIndicator[]; total: number } {
  const byKey = new Map<string, AdvisoryIndicator & { _reports: Set<string> }>();
  for (const r of reports) {
    for (const i of r.iocs ?? []) {
      if (NOT_INDICATORS.has(i.kind) || !i.value) continue;
      const key = `${i.kind}:${i.value}`;
      let x = byKey.get(key);
      if (!x) {
        x = { kind: i.kind, value: i.value, display: i.original || i.value, ...(i.role ? { role: i.role } : {}), firstSeen: r.publishedAt ?? null, reports: 0, citations: [], _reports: new Set() };
        byKey.set(key, x);
      }
      if (!x.role && i.role) x.role = i.role;
      if (r.publishedAt && (!x.firstSeen || ms(r.publishedAt) < ms(x.firstSeen))) x.firstSeen = r.publishedAt;
      x._reports.add(r.id);
      if (x.citations.length < 2) pushCitation(x.citations, cite(r, i.evidence?.quote ? { quote: i.evidence.quote } : {}));
    }
  }
  const all = [...byKey.values()].map(({ _reports, ...x }) => ({ ...x, reports: _reports.size }));
  all.sort((a, b) => b.reports - a.reports || (ms(b.firstSeen) || 0) - (ms(a.firstSeen) || 0) || a.kind.localeCompare(b.kind) || a.value.localeCompare(b.value));
  return { indicators: all.slice(0, MAX_INDICATORS), total: all.length };
}

function buildDetections(path: PurplePath): AdvisoryDetection[] {
  return path.steps.map((s) => ({
    techniqueId: s.technique.id,
    name: s.technique.name,
    tactic: s.phase,
    telemetry: s.simulation.requiredTelemetry,
    hypothesis: s.hunts[0]?.hypothesis ?? `Hunt for ${s.technique.name} (${s.technique.id}).`,
    queryTemplate: s.hunts[0]?.query.text ?? "",
  }));
}

function normText(s: string) {
  return s.toLowerCase().replace(/\s+/g, " ").trim();
}

function buildRecommendations(input: AdvisoryBuildInput, vulns: AdvisoryVulnerability[], behaviours: AdvisoryBehaviour[], deps: AdvisoryBuildDeps): AdvisoryRecommendation[] {
  const out: AdvisoryRecommendation[] = [];
  for (const v of vulns) {
    if (v.kev?.requiredAction) out.push({ kind: "patch", cveId: v.cveId, action: v.kev.requiredAction, ...(v.kev.dueDate ? { dueDate: v.kev.dueDate } : {}), source: "CISA KEV" });
  }
  const techniqueIds = Array.from(new Set([...input.path.steps.map((s) => s.technique.id), ...behaviours.filter((b) => b.observedIn > 0).map((b) => b.techniqueId)]));
  for (const m of deps.mitigationsForTechniques(techniqueIds).slice(0, 10)) {
    out.push({ kind: "attack_mitigation", id: m.id, name: m.name, description: m.description, techniques: m.techniques });
  }
  const seen = new Set<string>();
  let guidance = 0;
  for (const r of input.reports) {
    for (const x of r.analysis?.evidence?.excluded ?? []) {
      if (x.label !== "defensive" || !x.evidence?.quote) continue;
      const key = normText(x.evidence.quote);
      if (seen.has(key) || key.length < 25) continue;
      seen.add(key);
      out.push({ kind: "source_guidance", text: x.evidence.quote.trim(), citation: cite(r, { label: "defensive", quote: x.evidence.quote, ...(x.evidence.section ? { section: x.evidence.section } : {}) }) });
      if (++guidance >= 12) break;
    }
    if (guidance >= 12) break;
  }
  return out;
}

function buildSources(reports: AdvisoryReport[]): AdvisorySource[] {
  return [...reports]
    .sort((a, b) => (ms(b.publishedAt) || 0) - (ms(a.publishedAt) || 0) || a.title.localeCompare(b.title))
    .map((r) => ({
      reportId: r.id,
      title: r.title,
      publisher: publisherOf(r),
      publishedAt: r.publishedAt ?? null,
      ...(r.sourceTier ? { tier: r.sourceTier } : {}),
      ...(typeof r.sourceConfidence === "number" ? { confidence: r.sourceConfidence } : {}),
      ...(r.canonicalUrl || r.url ? { url: r.canonicalUrl || r.url } : {}),
    }));
}

// ---------------------------------------------------------------------------
// Assessment
// ---------------------------------------------------------------------------

function assessSeverity(
  behaviours: AdvisoryBehaviour[],
  vulns: AdvisoryVulnerability[],
  reports: AdvisoryReport[],
  lastSeen: string | null,
  nowMs: number,
): { severity: AdvisorySeverity; reasons: string[] } {
  const reasons: string[] = [];
  const observed = behaviours.filter((b) => b.observedIn > 0);
  const observedImpact = observed.filter((b) => b.tactic === "Impact");
  const kevRansom = vulns.filter((v) => v.kev?.ransomwareUse?.toLowerCase() === "known");
  const kevAny = vulns.filter((v) => v.kev);
  const ageDays = Number.isFinite(ms(lastSeen)) ? (nowMs - ms(lastSeen)) / 86_400_000 : Infinity;
  const maxConf = Math.max(0, ...reports.map((r) => r.sourceConfidence ?? 0));

  if (kevRansom.length) reasons.push(`Exploited vulnerability with known ransomware use (CISA KEV): ${list(kevRansom.map((v) => v.cveId), 3)}`);
  else if (kevAny.length) reasons.push(`Known exploited vulnerability (CISA KEV): ${list(kevAny.map((v) => v.cveId), 3)}`);
  if (observedImpact.length) reasons.push(`Impact behaviour observed: ${list(observedImpact.map((b) => `${b.name} (${b.techniqueId})`), 2)}`);
  if (observed.length) reasons.push(`${plural(observed.length, "technique")} observed across ${plural(reports.length, "library report")}`);
  if (Number.isFinite(ageDays)) reasons.push(ageDays <= 180 ? `Recent activity: latest source ${monthYear(lastSeen)}` : `Latest source ${monthYear(lastSeen)}`);
  if (!reports.length) reasons.push("No library evidence yet; ATT&CK attribution only");

  let severity: AdvisorySeverity = "low";
  if (kevRansom.length || (observedImpact.length && ageDays <= 90 && maxConf >= 0.85)) severity = "critical";
  else if (kevAny.length || observedImpact.length || (observed.length >= 5 && ageDays <= 180)) severity = "high";
  else if (behaviours.length > 0) severity = "medium";
  return { severity, reasons };
}

function computeGaps(
  input: AdvisoryBuildInput,
  behaviours: AdvisoryBehaviour[],
  targeting: AdvisoryTargeting[],
  vulns: AdvisoryVulnerability[],
  indicatorTotal: number,
  lastSeen: string | null,
  unknownIds: Set<string>,
  nowMs: number,
): AdvisoryGap[] {
  const gaps: AdvisoryGap[] = [];
  const n = input.reports.length;
  if (n === 0) gaps.push({ key: "no-library-evidence", impact: "high", text: "No library report describes this threat yet. Behaviours come from ATT&CK attribution only; ingest or crawl reports to ground the advisory." });
  else if (n === 1) gaps.push({ key: "single-source", impact: "medium", text: "Single source: no second report corroborates these behaviours." });
  if (n > 0 && !behaviours.some((b) => b.tactic === "Initial Access" && b.observedIn > 0)) gaps.push({ key: "initial-access", impact: "medium", text: "The initial access vector is not reported as observed in the sources." });
  if (n > 0 && !targeting.some((t) => t.kind === "sector" && (t.status === "targeted" || t.status === "compromised"))) gaps.push({ key: "sectors", impact: "low", text: "Targeted sectors are not stated in the sources." });
  if (n > 0 && !targeting.some((t) => t.kind === "geography" && (t.status === "targeted" || t.status === "compromised"))) gaps.push({ key: "geography", impact: "low", text: "Targeted geographies are not stated in the sources." });
  if (n > 0 && indicatorTotal === 0) gaps.push({ key: "indicators", impact: "low", text: "The sources publish no indicators of compromise." });
  const ageDays = Number.isFinite(ms(lastSeen)) ? (nowMs - ms(lastSeen)) / 86_400_000 : NaN;
  if (ageDays > 365) gaps.push({ key: "stale", impact: "medium", text: `The most recent source is from ${monthYear(lastSeen)}; the actor's tradecraft may have changed since.` });
  if (vulns.length && !input.kevSynced) gaps.push({ key: "kev", impact: "low", text: "CISA KEV is not synced, so the exploitation status and remediation due dates of these CVEs are not checked." });
  if (!input.emulationSynced) gaps.push({ key: "emulation", impact: "low", text: "Emulation libraries (Atomic Red Team, CTID, CALDERA) are not synced, so simulation steps use custom procedures." });
  if (unknownIds.size) gaps.push({ key: "unknown-techniques", impact: "low", text: `Technique IDs in the sources that are not in the ATT&CK snapshot (revoked or deprecated): ${list([...unknownIds].sort(), 6)}.` });
  gaps.push({ key: "detection-unvalidated", impact: "medium", text: "Detection coverage is unknown until a simulation run records what each step did." });
  return gaps;
}

function subjectLabel(s: AdvisorySubject): string {
  return s.attackId ? `${s.name} (${s.attackId})` : s.name;
}

function defaultTitle(s: AdvisorySubject, reports: AdvisoryReport[]): string {
  switch (s.kind) {
    case "actor":
      return `${s.name}: threat actor advisory`;
    case "campaign":
      return `${s.name}: campaign advisory`;
    case "vulnerability":
      return `${list(s.cveIds?.length ? s.cveIds : [s.name], 3)}: vulnerability advisory`;
    case "malware":
      return `${s.name}: malware and tool advisory`;
    default:
      return reports.length === 1 ? reports[0].title.slice(0, 140) : `Advisory from ${plural(reports.length, "report")}`;
  }
}

function buildSummary(
  input: AdvisoryBuildInput,
  behaviours: AdvisoryBehaviour[],
  attackOnly: number,
  targeting: AdvisoryTargeting[],
  vulns: AdvisoryVulnerability[],
  activity: AdvisoryContent["activity"],
): { summary: string; keyPoints: string[] } {
  const s = input.subject;
  const observed = behaviours.filter((b) => b.observedIn > 0);
  const inferred = behaviours.filter((b) => b.observedIn === 0 && b.inferredIn > 0);
  const parts: string[] = [];
  if (activity.reports > 0) {
    const what = `${plural(observed.length, "technique")} observed${inferred.length ? ` and ${inferred.length} inferred` : ""}`;
    const when = activity.lastSeen ? `latest ${monthYear(activity.lastSeen)}` : "undated";
    parts.push(`${subjectLabel(s)}: ${what} across ${plural(activity.reports, "library report")} (${when}; ${list(activity.publishers, 3)}).`);
  } else {
    parts.push(`${subjectLabel(s)}: no library report describes it yet; ${plural(attackOnly, "technique")} ${attackOnly === 1 ? "is" : "are"} attributed by ATT&CK.`);
  }
  const strong = (t: AdvisoryTargeting) => t.status === "targeted" || t.status === "compromised";
  const sectors = targeting.filter((t) => t.kind === "sector" && strong(t)).map((t) => t.value);
  const geos = targeting.filter((t) => t.kind === "geography" && strong(t)).map((t) => t.value);
  if (sectors.length || geos.length) parts.push(`Targets ${[sectors.length ? list(sectors) : "", geos.length ? `in ${list(geos)}` : ""].filter(Boolean).join(" ")}.`);
  if (vulns.length) {
    const kev = vulns.filter((v) => v.kev).length;
    parts.push(`Cites ${list(vulns.map((v) => v.cveId), 3)}${kev ? ` (${kev} in CISA KEV)` : ""}.`);
  }
  const steps = input.path.steps.length;
  if (steps) {
    const high = input.path.steps.filter((x) => x.simulation.risk.level === "high").length;
    parts.push(`The simulation scope covers ${plural(steps, "step")} across ${plural(input.path.phases.length, "tactic")}${high ? `, ${high} high-risk` : ""}.`);
  }

  const keyPoints: string[] = [];
  const byTactic = new Map<string, AdvisoryBehaviour[]>();
  for (const b of observed) byTactic.set(b.tactic, [...(byTactic.get(b.tactic) ?? []), b]);
  for (const [tactic, items] of [...byTactic.entries()].slice(0, 4)) {
    keyPoints.push(`${tactic}: ${list(items.map((b) => `${b.name.split(": ").pop()} (${b.techniqueId})`), 2)}, observed in ${plural(Math.max(...items.map((b) => b.observedIn)), "report")}.`);
  }
  if (sectors.length) keyPoints.push(`Targeted sectors: ${list(sectors, 5)}.`);
  const ransom = vulns.filter((v) => v.kev?.ransomwareUse?.toLowerCase() === "known");
  if (ransom.length) keyPoints.push(`Known ransomware use of ${list(ransom.map((v) => v.cveId), 3)} (CISA KEV).`);
  return { summary: parts.join(" "), keyPoints };
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

export function buildAdvisoryContent(input: AdvisoryBuildInput, deps: AdvisoryBuildDeps): AdvisoryContent {
  const now = input.now ?? new Date().toISOString();
  const nowMs = ms(now) || Date.now();
  const unknownIds = new Set<string>();
  const behaviours = buildBehaviours(input, deps, unknownIds);
  const known = new Set(behaviours.map((b) => b.techniqueId));
  const attackOnlyBehaviours = Array.from(new Set(input.attributed.map((x) => x.toUpperCase())))
    .filter((id) => !known.has(id))
    .map((id) => deps.getTechnique(id))
    .filter((t): t is NonNullable<typeof t> => Boolean(t))
    .map((t) => ({ techniqueId: t.id, name: t.name, tactic: t.tactics[0] ?? "Unknown" }))
    .sort((a, b) => deps.tacticRank(a.tactic) - deps.tacticRank(b.tactic) || a.techniqueId.localeCompare(b.techniqueId, "en", { numeric: true }));
  const targeting = buildTargeting(input.reports);
  const vulnerabilities = buildVulnerabilities(input);
  const { indicators, total: indicatorTotal } = buildIndicators(input.reports);
  const sources = buildSources(input.reports);
  const dated = sources.map((s) => s.publishedAt).filter((d): d is string => Number.isFinite(ms(d))).sort((a, b) => ms(a) - ms(b));
  const activity = {
    firstSeen: dated[0] ?? null,
    lastSeen: dated[dated.length - 1] ?? null,
    reports: input.reports.length,
    publishers: Array.from(new Set(sources.map((s) => s.publisher))),
  };
  const { severity, reasons } = assessSeverity(behaviours, vulnerabilities, input.reports, activity.lastSeen, nowMs);
  const { summary, keyPoints } = buildSummary(input, behaviours, attackOnlyBehaviours.length, targeting, vulnerabilities, activity);
  return {
    version: 1,
    generatedAt: now,
    attackVersion: deps.attackVersion,
    subject: input.subject,
    title: defaultTitle(input.subject, input.reports),
    severity,
    severityReasons: reasons,
    summary,
    keyPoints,
    activity,
    behaviours,
    attackOnlyBehaviours,
    targeting,
    vulnerabilities,
    indicators,
    indicatorTotal,
    detections: buildDetections(input.path),
    recommendations: buildRecommendations(input, vulnerabilities, behaviours, deps),
    gaps: computeGaps(input, behaviours, targeting, vulnerabilities, indicatorTotal, activity.lastSeen, unknownIds, nowMs),
    sources,
    path: input.path,
    emulationSynced: input.emulationSynced,
    kevSynced: input.kevSynced,
  };
}
