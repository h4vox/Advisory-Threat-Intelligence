/**
 * Purple path generator (spec §32–36, MVP 5 §60). Pure: ATT&CK lookups are injected, so this runs
 * in tests and anywhere the bundled knowledge is passed in.
 *
 * Seed (actor / report / campaign / technique list) → candidate techniques → filters (platform,
 * risk) → priority score with reasons → per-tactic selection under maxSteps → kill-chain order →
 * §33 simulation object, §36 hunting hypotheses and §35 detection status per step.
 */
import { prerequisitesFor, cleanupFor, querySkeleton, riskFor, tacticTemplate } from "./templates.ts";
import {
  DETECTION_UNKNOWN,
  PURPLE_DISCLAIMER,
  PURPLE_PLATFORMS,
  type EmulationContext,
  type ExecutionMethod,
  type HuntHypothesis,
  type KbTechnique,
  type LibraryEvidence,
  type ObservationLabel,
  type Priority,
  type PurpleOptions,
  type PurplePath,
  type PurpleSeed,
  type PurpleStep,
  type SimulationObject,
  type SourceRef,
} from "./types.ts";

export type TechniqueLookup = (id: string) => KbTechnique | undefined;

export type GenerateDeps = {
  getTechnique: TechniqueLookup;
  /** Tactic order (ATT&CK); index = rank. */
  tacticOrder: readonly string[];
  /** ISO timestamp for generatedAt and recency (tests pass a fixed one). */
  now?: string;
  /**
   * How many ATT&CK groups use a technique, and that count relative to the most-used technique (0..1).
   * A small signal that ranks widely used techniques first when library evidence is equal or absent.
   */
  prevalence?: (id: string) => { groups: number; share: number };
};

const RECENT_DAYS = 180;
const LABEL_WEIGHT: Record<ObservationLabel, number> = { observed: 1, inferred: 0.7, mapped: 0.5 };
const WEIGHTS = { frequency: 0.25, recency: 0.1, confidence: 0.15, attribution: 0.2, plan: 0.05, emulation: 0.1, platform: 0.1, prevalence: 0.05 };

const MONTHS = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];
export function monthYear(iso: string | null | undefined): string | null {
  if (!iso) return null;
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return null;
  return `${MONTHS[d.getUTCMonth()]} ${d.getUTCFullYear()}`;
}

export function attackPlatformsFor(platforms: PurpleOptions["platforms"]): string[] {
  const chosen = platforms.length ? PURPLE_PLATFORMS.filter((p) => platforms.includes(p.id)) : PURPLE_PLATFORMS;
  return chosen.flatMap((p) => p.attack);
}

function rankOf(order: readonly string[], tactic: string | undefined): number {
  const i = order.findIndex((t) => t.toLowerCase() === (tactic ?? "").toLowerCase());
  return i === -1 ? order.length : i;
}

/** Phase for a technique: the tactic a report observed it under (when ATT&CK lists it), else the earliest ATT&CK tactic. */
function phaseFor(t: KbTechnique, observedTactics: string[], order: readonly string[]): string {
  const valid = observedTactics.filter((x) => t.tactics.some((k) => k.toLowerCase() === x.toLowerCase()));
  if (valid.length) {
    const counts = new Map<string, number>();
    for (const v of valid) counts.set(v, (counts.get(v) ?? 0) + 1);
    const best = [...counts.entries()].sort((a, b) => b[1] - a[1] || rankOf(order, a[0]) - rankOf(order, b[0]))[0][0];
    return t.tactics.find((k) => k.toLowerCase() === best.toLowerCase()) ?? best;
  }
  return [...t.tactics].sort((a, b) => rankOf(order, a) - rankOf(order, b))[0] ?? "Unknown";
}

function slug(s: string): string {
  return s.toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-|-$/g, "").slice(0, 40) || "path";
}

function priorityOf(score: number): Priority {
  return score >= 0.6 ? "high" : score >= 0.35 ? "medium" : "low";
}

function plural(n: number, word: string): string {
  return `${n} ${word}${n === 1 ? "" : "s"}`;
}

type Candidate = {
  t: KbTechnique;
  phase: string;
  sightings: Array<{ report: LibraryEvidence; label: ObservationLabel; quotes: string[]; position?: number }>;
  attributed: boolean;
  custom: boolean;
  inPlan: boolean;
  position?: number;
};

function executionFor(id: string, platforms: string[], emu: EmulationContext): ExecutionMethod {
  if (!emu.synced) return { kind: "custom", summary: "Custom procedure; no emulation library synced", options: [] };
  const all = emu.options[id] ?? [];
  const fit = all.filter((o) => !o.platforms.length || o.platforms.some((p) => platforms.some((q) => q.toLowerCase() === p.toLowerCase())));
  const opts = (fit.length ? fit : all).slice(0, 5);
  if (!opts.length) return { kind: "custom", summary: "Custom procedure; no synced emulation procedure for this technique", options: [] };
  const by = new Map<string, number>();
  for (const o of fit.length ? fit : all) by.set(o.kind, (by.get(o.kind) ?? 0) + 1);
  const label: Record<string, string> = { atomic_test: "Atomic test", caldera_ability: "CALDERA ability", ctid_procedure: "CTID procedure", attack_flow: "Attack flow", custom: "Custom procedure" };
  const summary = [...by.entries()].map(([k, n]) => `${n} ${label[k] ?? k}${n === 1 ? "" : "s"}`).join(", ");
  return { kind: opts[0].kind, summary: `${summary} available (review before use)`, options: opts };
}

/** Builds the full purple path. */
export function generatePurplePath(seed: PurpleSeed, options: PurpleOptions, emu: EmulationContext, deps: GenerateDeps): PurplePath {
  const order = deps.tacticOrder;
  const nowIso = deps.now ?? new Date().toISOString();
  const nowMs = new Date(nowIso).getTime();
  const chosenPlatforms = attackPlatformsFor(options.platforms);
  const platformLabel = options.platforms.length
    ? PURPLE_PLATFORMS.filter((p) => options.platforms.includes(p.id)).map((p) => p.label).join(", ")
    : "any platform";
  const maxSteps = Math.max(1, Math.min(60, Math.floor(options.maxSteps || 12)));
  const reportedOrder = Boolean(seed.reportedOrder) && seed.kind === "report";

  // 1. Candidates.
  const ids = new Set<string>();
  for (const id of seed.attributed) ids.add(id.toUpperCase());
  for (const id of seed.custom ?? []) ids.add(id.toUpperCase());
  const planIds = new Set((seed.emulationPlans ?? []).flatMap((p) => p.techniques.map((x) => x.toUpperCase())));
  if (seed.kind !== "custom") {
    for (const r of seed.reports) for (const t of r.techniques) ids.add(t.id.toUpperCase());
    for (const id of planIds) ids.add(id);
  }

  const attributed = new Set(seed.attributed.map((x) => x.toUpperCase()));
  const custom = new Set((seed.custom ?? []).map((x) => x.toUpperCase()));
  const excluded: PurplePath["excluded"] = [];
  const candidates: Candidate[] = [];

  for (const id of ids) {
    const t = deps.getTechnique(id);
    if (!t) {
      excluded.push({ id, name: id, reason: "Not in the bundled ATT&CK snapshot" });
      continue;
    }
    const sightings: Candidate["sightings"] = [];
    for (const r of seed.reports) {
      const hit = r.techniques.find((x) => x.id.toUpperCase() === id);
      if (hit) sightings.push({ report: r, label: hit.label, quotes: hit.quotes, position: hit.position });
    }
    const phase = phaseFor(t, sightings.map((s) => s.report.techniques.find((x) => x.id.toUpperCase() === id)?.tactic ?? "").filter(Boolean), order);
    const positions = sightings.map((s) => s.position).filter((p): p is number => typeof p === "number");
    candidates.push({
      t,
      phase,
      sightings,
      attributed: attributed.has(id),
      custom: custom.has(id),
      inPlan: planIds.has(id),
      position: positions.length ? Math.min(...positions) : undefined,
    });
  }
  const candidateCount = candidates.length;

  // 2. Filters.
  const kept: Array<Candidate & { fit: string[]; risk: ReturnType<typeof riskFor> }> = [];
  for (const c of candidates) {
    const fit = c.t.platforms.filter((p) => chosenPlatforms.some((q) => q.toLowerCase() === p.toLowerCase()));
    if (options.platforms.length && !fit.length) {
      excluded.push({ id: c.t.id, name: c.t.name, reason: `No ATT&CK platform match for ${platformLabel} (${c.t.platforms.join(", ") || "none listed"})` });
      continue;
    }
    const risk = riskFor(c.t, c.phase);
    if (options.excludeHighRisk && risk.level === "high") {
      excluded.push({ id: c.t.id, name: c.t.name, reason: "High risk; excluded by the high-risk option" });
      continue;
    }
    kept.push({ ...c, fit: options.platforms.length ? fit : c.t.platforms, risk });
  }

  // 3. Score.
  const scored = kept.map((c) => {
    const reasons: string[] = [];
    const freq = c.sightings.reduce((n, s) => n + LABEL_WEIGHT[s.label], 0);
    const freqScore = Math.min(1, freq / 3);
    const dates = c.sightings.map((s) => s.report.publishedAt).filter((d): d is string => Boolean(d)).sort();
    const lastSeen = dates.length ? dates[dates.length - 1] : null;
    const recent = c.sightings.filter((s) => s.report.publishedAt && nowMs - new Date(s.report.publishedAt).getTime() <= RECENT_DAYS * 86_400_000).length;
    const ageDays = lastSeen ? (nowMs - new Date(lastSeen).getTime()) / 86_400_000 : null;
    const recencyScore = ageDays == null ? 0 : ageDays <= RECENT_DAYS ? 1 : ageDays <= 365 ? 0.6 : ageDays <= 730 ? 0.3 : 0.1;
    const conf = c.sightings.length ? Math.max(...c.sightings.map((s) => s.report.sourceConfidence * (s.label === "observed" ? 1 : 0.8))) : 0;

    if (c.sightings.length) {
      const observed = c.sightings.filter((s) => s.label === "observed").length;
      const verb = observed ? "Observed" : c.sightings.some((s) => s.label === "inferred") ? "Inferred" : "Mapped";
      const when = monthYear(lastSeen);
      reasons.push(`${verb} in ${plural(c.sightings.length, "library report")}${when ? ` (latest ${when})` : ""}`);
      const best = Math.max(...c.sightings.map((s) => s.report.sourceConfidence));
      reasons.push(best >= 0.85 ? `high-confidence source (${best.toFixed(2)})` : best >= 0.6 ? `moderate-confidence source (${best.toFixed(2)})` : `low-confidence source (${best.toFixed(2)})`);
    } else if (seed.kind !== "report") {
      reasons.push("Not seen in library reports yet");
    }
    if (c.attributed && seed.attributedBy) reasons.push(`attributed by ATT&CK (${seed.attributedBy.id})`);
    else if ((seed.kind === "actor" || seed.kind === "campaign") && seed.attributedBy) reasons.push("not attributed by ATT&CK");
    if (c.custom) reasons.push("selected by analyst");
    if (c.inPlan) reasons.push("in a synced emulation plan");

    const allOpts = emu.options[c.t.id] ?? [];
    const atomicTests = allOpts.filter((o) => o.kind === "atomic_test").length;
    let emuScore = 0;
    if (!emu.synced) reasons.push("no emulation library synced");
    else if (allOpts.length) {
      emuScore = 1;
      reasons.push(`${plural(allOpts.length, "emulation option")}${atomicTests ? ` (${atomicTests} Atomic)` : ""}`);
    } else reasons.push("no synced emulation procedure");

    const fitShare = c.t.platforms.length ? c.fit.length / c.t.platforms.length : 0;
    const platformScore = options.platforms.length ? 0.6 + 0.4 * fitShare : 0.5;
    if (options.platforms.length) reasons.push(`fits ${c.fit.join(", ")}`);

    const prev = deps.prevalence?.(c.t.id) ?? { groups: 0, share: 0 };
    if (prev.groups >= 10) reasons.push(`used by ${prev.groups} ATT&CK groups`);

    const score =
      WEIGHTS.frequency * freqScore +
      WEIGHTS.recency * recencyScore +
      WEIGHTS.confidence * conf +
      WEIGHTS.attribution * (c.attributed || c.custom ? 1 : 0) +
      WEIGHTS.plan * (c.inPlan ? 1 : 0) +
      WEIGHTS.emulation * emuScore +
      WEIGHTS.platform * platformScore +
      WEIGHTS.prevalence * prev.share;
    if (reasons.length) reasons[0] = reasons[0][0].toUpperCase() + reasons[0].slice(1);
    return {
      ...c,
      score: Math.round(Math.min(1, score) * 100) / 100,
      prevalence: prev.groups,
      reasons,
      stats: {
        reports: c.sightings.length,
        recentReports: recent,
        lastSeen,
        attributed: c.attributed,
        atomicTests,
        libraryOptions: allOpts.length,
        inEmulationPlan: c.inPlan,
        platformFit: c.fit,
      },
    };
  });

  // 4. Select under maxSteps, keeping one step per tactic first so the path stays end to end.
  const byScore = [...scored].sort(
    (a, b) => b.score - a.score || b.prevalence - a.prevalence || rankOf(order, a.phase) - rankOf(order, b.phase) || a.t.id.localeCompare(b.t.id),
  );
  let chosen = byScore;
  if (byScore.length > maxSteps) {
    const pick = new Set<string>();
    const bestPerTactic = new Map<string, (typeof byScore)[number]>();
    for (const c of byScore) if (!bestPerTactic.has(c.phase)) bestPerTactic.set(c.phase, c);
    const tacticLeaders = [...bestPerTactic.values()].sort((a, b) => b.score - a.score);
    for (const c of tacticLeaders.slice(0, maxSteps)) pick.add(c.t.id);
    for (const c of byScore) {
      if (pick.size >= maxSteps) break;
      pick.add(c.t.id);
    }
    chosen = byScore.filter((c) => pick.has(c.t.id));
    for (const c of byScore) if (!pick.has(c.t.id)) excluded.push({ id: c.t.id, name: c.t.name, reason: `Lower priority (${c.score.toFixed(2)}) than the ${maxSteps} steps kept` });
  }

  // 5. Order.
  const ordered = [...chosen].sort((a, b) => {
    if (reportedOrder) {
      const pa = a.position ?? Number.POSITIVE_INFINITY;
      const pb = b.position ?? Number.POSITIVE_INFINITY;
      if (pa !== pb) return pa - pb;
    }
    return rankOf(order, a.phase) - rankOf(order, b.phase) || b.score - a.score || a.t.id.localeCompare(b.t.id);
  });

  // 6. Simulation objects.
  const steps: PurpleStep[] = ordered.map((c, i) => {
    const n = i + 1;
    const simId = `SIM-${String(n).padStart(3, "0")}`;
    const tmpl = tacticTemplate(c.phase);
    const telemetry = c.t.dataSources;
    const quotes = c.sightings.flatMap((s) => s.quotes).slice(0, 3);
    const refs: SourceRef[] = c.sightings.map((s) => ({
      kind: "report",
      reportId: s.report.reportId,
      title: s.report.title,
      publishedAt: s.report.publishedAt,
      label: s.label,
      quotes: s.quotes,
    }));
    if (c.attributed && seed.attributedBy) refs.push({ kind: "attack", id: seed.attributedBy.id, url: seed.attributedBy.url, note: `ATT&CK attributes ${c.t.id} to ${seed.name}` });
    if (c.custom) refs.push({ kind: "analyst", note: "Technique selected by the analyst" });
    if (c.inPlan) for (const p of seed.emulationPlans ?? []) if (p.techniques.some((x) => x.toUpperCase() === c.t.id)) refs.push({ kind: "report", reportId: p.reportId, title: p.title, publishedAt: null, label: "mapped", quotes: [] });

    const simulation: SimulationObject = {
      simulationId: simId,
      scenario: `${seed.name}: ${c.phase.toLowerCase()} via ${c.t.name} (${c.t.id})`,
      objective: `Validate that ${c.t.name} (${c.t.id}), used for ${tmpl.verb}, is recorded and detected on ${c.fit.join(", ") || "the target platform"}.`,
      ttp: { id: c.t.id, name: c.t.name, tactic: c.phase },
      prerequisites: prerequisitesFor(c.phase, c.fit),
      targetPlatforms: c.fit,
      requiredTelemetry: telemetry,
      execution: executionFor(c.t.id, c.fit, emu),
      expectedBehaviour: quotes.length
        ? `Reproduce the behaviour the source describes: "${quotes[0]}"`
        : `Behaviour consistent with ATT&CK ${c.t.id} ${c.t.name} during ${c.phase.toLowerCase()}.`,
      expectedDetection: telemetry.length
        ? `${telemetry.slice(0, 3).join(", ")} record the activity, and an alert or hunt result maps it to ${c.t.id}.`
        : `An alert or hunt result maps the activity to ${c.t.id}. ATT&CK lists no data components for this technique.`,
      successCriteria: [
        telemetry.length ? `Each required data component (${telemetry.length}) is present for the test window` : "Relevant logs are present for the test window",
        `An alert fires and is mapped to ${c.t.id}`,
        "The alert carries host, user and process context",
        "SOC triage reaches the correct conclusion within the agreed time",
      ],
      cleanup: cleanupFor(c.phase),
      risk: c.risk,
      sourceRefs: refs,
    };

    const hunts: HuntHypothesis[] = [
      {
        huntId: `HUNT-${String(n).padStart(3, "0")}`,
        techniqueId: c.t.id,
        hypothesis: `If ${seed.kind === "custom" ? "an adversary" : seed.name} activity is present, ${telemetry.length ? telemetry.slice(0, 2).join(" and ").toLowerCase() : "available logs"} will show ${c.t.name} on ${c.fit.join(", ") || "the estate"}.`,
        telemetry,
        query: { language: "pseudo-sql", isTemplate: true, text: querySkeleton(c.t, telemetry) },
      },
    ];

    return {
      order: n,
      phase: c.phase,
      technique: c.t,
      score: c.score,
      priority: priorityOf(c.score),
      reasons: c.reasons,
      reasonText: c.reasons.join(" · "),
      stats: c.stats,
      simulation,
      hunts,
      detection: { status: "unknown", note: DETECTION_UNKNOWN },
    };
  });

  // Phases: consecutive runs (tactic order normally gives one run per tactic).
  const phases: PurplePath["phases"] = [];
  for (const s of steps) {
    const last = phases[phases.length - 1];
    if (last && last.tactic === s.phase) last.steps++;
    else phases.push({ tactic: s.phase, steps: 1 });
  }

  const libraryReports = new Set(seed.reports.map((r) => r.reportId)).size;
  return {
    version: 1,
    id: `pp-${seed.kind}-${slug(seed.id)}-${nowMs.toString(36)}`,
    generatedAt: nowIso,
    source: { kind: seed.kind, id: seed.id, name: seed.name },
    options: { ...options, maxSteps },
    orderBasis: reportedOrder ? "reported" : "tactic",
    orderNote: reportedOrder
      ? "Sequence reported in the source report"
      : "ATT&CK tactic order; the source gives no verified sequence across these techniques",
    emulationSynced: emu.synced,
    steps,
    phases,
    excluded,
    candidateCount,
    libraryReports,
    disclaimer: PURPLE_DISCLAIMER,
  };
}
