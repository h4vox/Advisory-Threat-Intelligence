/**
 * Advisory server functions: generate an advisory from a subject (actor, campaign, malware, a CVE or
 * selected reports) against the library + ATT&CK, persist it and its simulation runs, and derive the
 * detection findings. Generation reuses the purple-path resolver and the pure advisory builder; the
 * runs drive the validation metrics. Planning / reporting only — nothing here executes a technique.
 */
import { createServerFn } from "@tanstack/react-start";
import { z } from "zod";
import { analystMiddleware } from "./access";
import { getAdvisoriesStore } from "../mongodb/advisories-repo.server";
import { mongoGetKevEntries } from "../mongodb/repository.server";
import { buildAdvisoryContent, type AdvisoryBuildDeps, type AdvisoryReport } from "./advisory/build";
import { effectiveSeverity, effectiveTitle, renderAdvisoryJson, renderAdvisoryMarkdown } from "./advisory/export";
import { computeRunMetrics, deriveFindings, latestRun } from "./advisory/validation";
import type {
  AdvisoryContent,
  AdvisoryFinding,
  AdvisoryInputSpec,
  AdvisoryOptions,
  AdvisoryRecord,
  AdvisorySeverity,
  AdvisoryStatus,
  AdvisorySubject,
  AdvisorySubjectKind,
  AdvisorySummary,
  KevDetails,
  SimulationRun,
  StepOutcome,
  StepResult,
  Tlp,
} from "./advisory/types";
import { loadLibrary, resolveSeed, SeedError, toEvidence } from "./server-emulation";
import {
  ATTACK_VERSION,
  getSoftware,
  getTechnique,
  getMitigation,
  mitigationsForTechniques,
  normalizeEntityName,
  resolveEntity,
  tacticRank,
  TACTIC_ORDER,
  techniquePrevalence,
} from "./attack-knowledge";
import { generatePurplePath } from "./purple/generate";
import type { PurpleSeed } from "./purple/types";
import type { IntelAnalysis, IocHit, ReportListItem, SourceTier } from "./types";

// ATT&CK knowledge, wired into the pure builder's dependency surface. The accessor shapes already
// match AdvisoryBuildDeps, so they pass straight through.
const BUILD_DEPS: AdvisoryBuildDeps = {
  getTechnique,
  getMitigation,
  mitigationsForTechniques,
  tacticRank,
  attackVersion: ATTACK_VERSION,
};

const DEFAULT_OPTIONS: AdvisoryOptions = { platforms: [], excludeHighRisk: false, maxSteps: 12 };
const CVE_RE = /^CVE-\d{4}-\d{4,7}$/i;

function toAdvisoryReport(r: ReportListItem): AdvisoryReport {
  const row = r as ReportListItem & {
    publisher?: string;
    sourceName?: string;
    url?: string;
    canonicalUrl?: string;
    sourceTier?: SourceTier;
    sourceConfidence?: number;
    iocs?: IocHit[];
    analysis?: IntelAnalysis | null;
  };
  return {
    id: r.id,
    title: r.title,
    publisher: row.publisher ?? row.sourceName,
    url: row.url,
    canonicalUrl: row.canonicalUrl,
    publishedAt: r.publishedAt,
    sourceTier: row.sourceTier,
    sourceConfidence: row.sourceConfidence,
    analysis: row.analysis ?? null,
    iocs: row.iocs ?? [],
  };
}

async function kevMap(cveIds: string[]): Promise<Map<string, KevDetails>> {
  const map = new Map<string, KevDetails>();
  const ids = [...new Set(cveIds.map((c) => c.toUpperCase()).filter((c) => CVE_RE.test(c)))];
  if (ids.length === 0) return map;
  try {
    const rows = await mongoGetKevEntries(ids);
    for (const r of rows) {
      map.set(r.cveId.toUpperCase(), {
        vendor: r.vendor,
        product: r.product,
        name: r.name,
        dateAdded: r.dateAdded,
        ...(r.dueDate ? { dueDate: r.dueDate } : {}),
        ...(r.ransomwareUse ? { ransomwareUse: r.ransomwareUse } : {}),
        ...(r.requiredAction ? { requiredAction: r.requiredAction } : {}),
      });
    }
  } catch {
    // KEV index is optional (MongoDB only); an advisory is still valid without it.
  }
  return map;
}

function cvesFrom(reports: AdvisoryReport[], extra: string[] = []): string[] {
  const out = new Set<string>();
  for (const c of extra) if (CVE_RE.test(c)) out.add(c.toUpperCase());
  for (const r of reports) {
    for (const v of r.analysis?.vulnerabilities ?? []) if (CVE_RE.test(v.trim())) out.add(v.trim().toUpperCase());
    for (const i of r.iocs ?? []) if (i.kind === "cve" && CVE_RE.test(i.value)) out.add(i.value.toUpperCase());
  }
  return [...out];
}

/** Resolve a subject to a purple seed, matched library reports and an AdvisorySubject. */
async function resolveAdvisory(
  input: AdvisoryInputSpec,
  library: ReportListItem[],
): Promise<{ seed: PurpleSeed; subject: AdvisorySubject }> {
  const value = (input.value ?? "").trim();

  if (input.kind === "actor" || input.kind === "campaign") {
    const { seed, info } = await resolveSeed(
      { kind: input.kind, value, options: DEFAULT_OPTIONS },
      library,
      [],
    );
    return {
      seed,
      subject: {
        kind: input.kind,
        id: info.id,
        name: info.name,
        aliases: info.aliases ?? [],
        ...(info.attackId ? { attackId: info.attackId } : {}),
        ...(info.attackUrl ? { attackUrl: info.attackUrl } : {}),
        ...(info.description ? { description: info.description } : {}),
      },
    };
  }

  if (input.kind === "malware") {
    const resolved = getSoftware(value) ?? (resolveEntity(value, ["software"])[0] ? getSoftware(resolveEntity(value, ["software"])[0].id) : undefined);
    const names = resolved ? new Set([resolved.name, ...resolved.aliases].map(normalizeEntityName)) : new Set([normalizeEntityName(value)]);
    const matched = library.filter((r) => {
      const inText = `${r.title} ${r.excerpt ?? ""}`.toLowerCase().includes(value.toLowerCase());
      const inMalware = (r.analysis?.malware ?? []).some((m) => names.has(normalizeEntityName(m)));
      return Boolean(value) && (inText || inMalware);
    });
    const attributed = resolved?.techniques ?? [];
    return {
      seed: { kind: "custom", id: resolved?.id ?? (normalizeEntityName(value).replace(/\s+/g, "-") || "malware"), name: resolved?.name ?? value, attributed, custom: attributed, reports: matched.map(toEvidence) },
      subject: {
        kind: "malware",
        id: resolved?.id ?? (normalizeEntityName(value).replace(/\s+/g, "-") || "malware"),
        name: resolved?.name ?? value,
        aliases: resolved?.aliases ?? [],
        ...(resolved ? { attackId: resolved.id, attackUrl: `https://attack.mitre.org/software/${resolved.id}/` } : {}),
      },
    };
  }

  if (input.kind === "vulnerability") {
    const cves = [...new Set([value, ...(input.cveIds ?? [])].map((c) => c.trim().toUpperCase()).filter((c) => CVE_RE.test(c)))];
    const matched = library.filter((r) => {
      const hay = `${r.title} ${r.excerpt ?? ""}`.toUpperCase();
      const inText = cves.some((c) => hay.includes(c));
      const inAnalysis = (r.analysis?.vulnerabilities ?? []).some((v) => cves.includes(v.trim().toUpperCase()));
      const inIocs = ((r as { iocs?: IocHit[] }).iocs ?? []).some((i) => i.kind === "cve" && cves.includes(i.value.toUpperCase()));
      return inText || inAnalysis || inIocs;
    });
    const name = cves.join(", ") || value || "Vulnerability";
    return {
      seed: { kind: "custom", id: cves[0] ?? "cve", name, attributed: [], reports: matched.map(toEvidence) },
      subject: { kind: "vulnerability", id: cves[0] ?? "cve", name, aliases: [], ...(cves.length ? { cveIds: cves } : {}) },
    };
  }

  // reports: an advisory built from an explicit set of library reports.
  const ids = input.reportIds ?? [];
  const matched = library.filter((r) => ids.includes(r.id));
  const name = matched.length === 1 ? matched[0].title : `${matched.length} selected report${matched.length === 1 ? "" : "s"}`;
  return {
    seed: { kind: "custom", id: "reports", name, attributed: [], reports: matched.map(toEvidence) },
    subject: { kind: "reports", id: "reports", name, aliases: [], reportIds: ids },
  };
}

async function generateContent(input: AdvisoryInputSpec, options: AdvisoryOptions, now: string): Promise<AdvisoryContent> {
  const library = await loadLibrary();
  const { seed, subject } = await resolveAdvisory(input, library);
  const matchedIds = new Set(seed.reports.map((e) => e.reportId));
  const reports = library.filter((r) => matchedIds.has(r.id)).map(toAdvisoryReport);
  const path = generatePurplePath(seed, options, { synced: false, options: {} }, { getTechnique, tacticOrder: TACTIC_ORDER, prevalence: techniquePrevalence });
  const cveIds = cvesFrom(reports, subject.cveIds ?? []);
  const kev = await kevMap(cveIds);
  return buildAdvisoryContent(
    { subject, reports, attributed: seed.attributed, path, kev, kevSynced: kev.size > 0, emulationSynced: false, now },
    BUILD_DEPS,
  );
}

// ---------------------------------------------------------------------------
// Numbering & summaries
// ---------------------------------------------------------------------------

function nextAdvisoryNumber(existing: AdvisoryRecord[], now: Date): string {
  const year = now.getUTCFullYear();
  const prefix = `ADV-${year}-`;
  let max = 0;
  for (const a of existing) {
    if (a.number?.startsWith(prefix)) {
      const n = Number(a.number.slice(prefix.length));
      if (Number.isFinite(n) && n > max) max = n;
    }
  }
  return `${prefix}${String(max + 1).padStart(4, "0")}`;
}

function toSummary(record: AdvisoryRecord, runs: SimulationRun[]): AdvisorySummary {
  const latest = latestRun(runs);
  const metrics = latest ? computeRunMetrics(latest, record.content) : null;
  return {
    id: record.id,
    number: record.number,
    title: effectiveTitle(record),
    subject: { kind: record.content.subject.kind, name: record.content.subject.name, ...(record.content.subject.attackId ? { attackId: record.content.subject.attackId } : {}) },
    status: record.status,
    tlp: record.tlp,
    severity: effectiveSeverity(record),
    behaviours: record.content.behaviours.length,
    scopedSteps: record.scope.length,
    sources: record.content.sources.length,
    gaps: record.content.gaps.length,
    createdAt: record.createdAt,
    updatedAt: record.updatedAt,
    createdBy: record.createdBy,
    ...(latest
      ? { latestRun: { number: latest.number, status: latest.status, detectionRate: metrics?.detectionRate ?? null, missed: metrics?.missed ?? 0, executed: metrics?.executed ?? 0, total: metrics?.total ?? 0 } }
      : {}),
  };
}

function who(context: { identity: { username: string | null }; userEmail: string | null }): string {
  return context.identity.username ?? context.userEmail ?? "an analyst";
}

// ---------------------------------------------------------------------------
// Validators
// ---------------------------------------------------------------------------

const ADVISORY_KINDS: [AdvisorySubjectKind, ...AdvisorySubjectKind[]] = ["actor", "campaign", "vulnerability", "malware", "reports"];
const OptionsInput = z.object({
  platforms: z.array(z.enum(["windows", "linux", "macos", "cloud", "saas", "identity", "network"])).max(7).default([]),
  excludeHighRisk: z.boolean().default(false),
  maxSteps: z.number().int().min(1).max(40).default(12),
});
const InputSpec = z.object({
  kind: z.enum(ADVISORY_KINDS),
  value: z.string().trim().max(200).optional(),
  cveIds: z.array(z.string().trim().max(32)).max(50).optional(),
  reportIds: z.array(z.string().trim().max(200)).max(200).optional(),
});
const STATUSES: [AdvisoryStatus, ...AdvisoryStatus[]] = ["draft", "review", "published", "simulating", "closed"];
const TLPS: [Tlp, ...Tlp[]] = ["CLEAR", "GREEN", "AMBER", "AMBER+STRICT", "RED"];
const SEVERITIES: [AdvisorySeverity, ...AdvisorySeverity[]] = ["critical", "high", "medium", "low"];
const OUTCOMES: [StepOutcome, ...StepOutcome[]] = ["prevented", "detected", "logged", "missed", "not_run", "not_applicable"];

// ---------------------------------------------------------------------------
// Server functions
// ---------------------------------------------------------------------------

export const listAdvisories = createServerFn({ method: "GET" })
  .middleware([analystMiddleware])
  .handler(async (): Promise<AdvisorySummary[]> => {
    const store = getAdvisoriesStore();
    const records = await store.allAdvisories();
    const out: AdvisorySummary[] = [];
    for (const r of records) out.push(toSummary(r, await store.runsFor(r.id)));
    return out;
  });

export const getAdvisory = createServerFn({ method: "POST" })
  .middleware([analystMiddleware])
  .validator(z.object({ id: z.string().min(1).max(200) }))
  .handler(async ({ data }): Promise<{ record: AdvisoryRecord; runs: SimulationRun[] } | null> => {
    const store = getAdvisoriesStore();
    const record = await store.getAdvisory(data.id);
    if (!record) return null;
    return { record, runs: await store.runsFor(data.id) };
  });

export const createAdvisory = createServerFn({ method: "POST" })
  .middleware([analystMiddleware])
  .validator(z.object({ input: InputSpec, options: OptionsInput.optional(), tlp: z.enum(TLPS).optional() }))
  .handler(async ({ data, context }): Promise<AdvisoryRecord> => {
    const store = getAdvisoriesStore();
    const nowDate = new Date();
    const now = nowDate.toISOString();
    const options: AdvisoryOptions = data.options ?? DEFAULT_OPTIONS;
    let content: AdvisoryContent;
    try {
      content = await generateContent(data.input, options, now);
    } catch (err) {
      if (err instanceof SeedError) throw new Error(err.message);
      throw err;
    }
    const existing = await store.allAdvisories();
    const by = who(context);
    const record: AdvisoryRecord = {
      id: `adv_${nowDate.getTime().toString(36)}_${Math.random().toString(36).slice(2, 8)}`,
      number: nextAdvisoryNumber(existing, nowDate),
      status: "draft",
      tlp: data.tlp ?? "AMBER",
      createdAt: now,
      updatedAt: now,
      createdBy: by,
      updatedBy: by,
      overrides: {},
      scope: content.path.steps.map((s) => s.technique.id),
      options,
      input: data.input,
      content,
    };
    await store.saveAdvisory(record);
    return record;
  });

export const regenerateAdvisory = createServerFn({ method: "POST" })
  .middleware([analystMiddleware])
  .validator(z.object({ id: z.string().min(1).max(200) }))
  .handler(async ({ data, context }): Promise<AdvisoryRecord> => {
    const store = getAdvisoriesStore();
    const record = await store.getAdvisory(data.id);
    if (!record) throw new Error(`Advisory ${data.id} was not found`);
    const now = new Date().toISOString();
    let content: AdvisoryContent;
    try {
      content = await generateContent(record.input, record.options, now);
    } catch (err) {
      if (err instanceof SeedError) throw new Error(err.message);
      throw err;
    }
    // Keep analyst overrides and only the scope steps that still exist after regeneration.
    const valid = new Set(content.path.steps.map((s) => s.technique.id));
    const scope = record.scope.filter((id) => valid.has(id));
    const updated: AdvisoryRecord = { ...record, content, scope: scope.length ? scope : content.path.steps.map((s) => s.technique.id), updatedAt: now, updatedBy: who(context) };
    await store.saveAdvisory(updated);
    return updated;
  });

export const updateAdvisory = createServerFn({ method: "POST" })
  .middleware([analystMiddleware])
  .validator(
    z.object({
      id: z.string().min(1).max(200),
      status: z.enum(STATUSES).optional(),
      tlp: z.enum(TLPS).optional(),
      scope: z.array(z.string().trim().max(16)).max(60).optional(),
      overrides: z
        .object({
          title: z.string().max(300).optional(),
          severity: z.enum(SEVERITIES).optional(),
          severityNote: z.string().max(1000).optional(),
          summary: z.string().max(5000).optional(),
          notes: z.string().max(10000).optional(),
        })
        .optional(),
    }),
  )
  .handler(async ({ data, context }): Promise<AdvisoryRecord> => {
    const store = getAdvisoriesStore();
    const record = await store.getAdvisory(data.id);
    if (!record) throw new Error(`Advisory ${data.id} was not found`);
    const updated: AdvisoryRecord = {
      ...record,
      ...(data.status ? { status: data.status } : {}),
      ...(data.tlp ? { tlp: data.tlp } : {}),
      ...(data.scope ? { scope: data.scope } : {}),
      ...(data.overrides ? { overrides: { ...record.overrides, ...data.overrides } } : {}),
      updatedAt: new Date().toISOString(),
      updatedBy: who(context),
    };
    await store.saveAdvisory(updated);
    return updated;
  });

export const deleteAdvisory = createServerFn({ method: "POST" })
  .middleware([analystMiddleware])
  .validator(z.object({ id: z.string().min(1).max(200) }))
  .handler(async ({ data }): Promise<{ ok: true; id: string }> => {
    await getAdvisoriesStore().deleteAdvisory(data.id);
    return { ok: true as const, id: data.id };
  });

export const startSimulationRun = createServerFn({ method: "POST" })
  .middleware([analystMiddleware])
  .validator(z.object({ advisoryId: z.string().min(1).max(200), name: z.string().max(200).optional(), environment: z.string().max(200).optional() }))
  .handler(async ({ data, context }): Promise<SimulationRun> => {
    const store = getAdvisoriesStore();
    const advisory = await store.getAdvisory(data.advisoryId);
    if (!advisory) throw new Error(`Advisory ${data.advisoryId} was not found`);
    const runs = await store.runsFor(data.advisoryId);
    const number = runs.reduce((m, r) => Math.max(m, r.number), 0) + 1;
    const scope = advisory.scope.length ? advisory.scope : advisory.content.path.steps.map((s) => s.technique.id);
    const now = new Date().toISOString();
    const run: SimulationRun = {
      id: `run_${Date.now().toString(36)}_${Math.random().toString(36).slice(2, 8)}`,
      advisoryId: data.advisoryId,
      number,
      name: data.name?.trim() || `Run ${number}`,
      ...(data.environment?.trim() ? { environment: data.environment.trim() } : {}),
      status: "in_progress",
      startedAt: now,
      startedBy: who(context),
      scope,
      results: {},
    };
    await store.saveRun(run);
    // Reflect that a simulation is under way.
    if (advisory.status === "draft" || advisory.status === "review" || advisory.status === "published") {
      await store.saveAdvisory({ ...advisory, status: "simulating", updatedAt: now });
    }
    return run;
  });

export const recordStepResult = createServerFn({ method: "POST" })
  .middleware([analystMiddleware])
  .validator(
    z.object({
      runId: z.string().min(1).max(200),
      techniqueId: z.string().trim().min(1).max(16),
      outcome: z.enum(OUTCOMES),
      notes: z.string().max(2000).optional(),
      evidenceRef: z.string().max(500).optional(),
      detectedBy: z.string().max(200).optional(),
    }),
  )
  .handler(async ({ data, context }): Promise<SimulationRun> => {
    const store = getAdvisoriesStore();
    const run = await store.getRun(data.runId);
    if (!run) throw new Error(`Simulation run ${data.runId} was not found`);
    const result: StepResult = {
      techniqueId: data.techniqueId,
      outcome: data.outcome,
      ...(data.notes?.trim() ? { notes: data.notes.trim() } : {}),
      ...(data.evidenceRef?.trim() ? { evidenceRef: data.evidenceRef.trim() } : {}),
      ...(data.detectedBy?.trim() ? { detectedBy: data.detectedBy.trim() } : {}),
      recordedAt: new Date().toISOString(),
      recordedBy: who(context),
    };
    const updated: SimulationRun = { ...run, results: { ...run.results, [data.techniqueId]: result } };
    await store.saveRun(updated);
    return updated;
  });

export const completeSimulationRun = createServerFn({ method: "POST" })
  .middleware([analystMiddleware])
  .validator(z.object({ runId: z.string().min(1).max(200) }))
  .handler(async ({ data }): Promise<{ run: SimulationRun; findings: AdvisoryFinding[] }> => {
    const store = getAdvisoriesStore();
    const run = await store.getRun(data.runId);
    if (!run) throw new Error(`Simulation run ${data.runId} was not found`);
    const now = new Date().toISOString();
    const completed: SimulationRun = { ...run, status: "completed", completedAt: now };
    await store.saveRun(completed);
    const advisory = await store.getAdvisory(run.advisoryId);
    let findings: AdvisoryFinding[] = [];
    if (advisory) {
      const prior = (await store.runsFor(run.advisoryId)).filter((r) => r.status === "completed" && r.number < completed.number).sort((a, b) => b.number - a.number)[0];
      findings = deriveFindings(advisory.content, completed, prior);
      if (advisory.status === "simulating") await store.saveAdvisory({ ...advisory, status: "review", updatedAt: now });
    }
    return { run: completed, findings };
  });

export const deleteSimulationRun = createServerFn({ method: "POST" })
  .middleware([analystMiddleware])
  .validator(z.object({ runId: z.string().min(1).max(200) }))
  .handler(async ({ data }): Promise<{ ok: true; id: string }> => {
    await getAdvisoriesStore().deleteRun(data.runId);
    return { ok: true as const, id: data.runId };
  });

/** Derived findings for a completed run (for the detail view, without re-completing it). */
export const getRunFindings = createServerFn({ method: "POST" })
  .middleware([analystMiddleware])
  .validator(z.object({ advisoryId: z.string().min(1).max(200), runId: z.string().min(1).max(200) }))
  .handler(async ({ data }): Promise<AdvisoryFinding[]> => {
    const store = getAdvisoriesStore();
    const [advisory, run] = await Promise.all([store.getAdvisory(data.advisoryId), store.getRun(data.runId)]);
    if (!advisory || !run) return [];
    const prior = (await store.runsFor(data.advisoryId)).filter((r) => r.status === "completed" && r.number < run.number).sort((a, b) => b.number - a.number)[0];
    return deriveFindings(advisory.content, run, prior);
  });

export const exportAdvisory = createServerFn({ method: "POST" })
  .middleware([analystMiddleware])
  .validator(z.object({ id: z.string().min(1).max(200), format: z.enum(["markdown", "json"]).default("markdown") }))
  .handler(async ({ data }): Promise<{ filename: string; contentType: string; body: string }> => {
    const record = await getAdvisoriesStore().getAdvisory(data.id);
    if (!record) throw new Error(`Advisory ${data.id} was not found`);
    if (data.format === "json") {
      return { filename: `${record.number}.json`, contentType: "application/json", body: renderAdvisoryJson(record) };
    }
    return { filename: `${record.number}.md`, contentType: "text/markdown", body: renderAdvisoryMarkdown(record) };
  });
