/**
 * The AIE tools the analyst agent can use: read tools over the library, actors, ATT&CK, sources,
 * crawls, advisories and purple-team plans, and action tools (crawls, library visibility,
 * advisories, ingest) that are only proposed and run after the analyst confirms.
 *
 * Every tool goes through the console's own server functions, inside the analyst's request, so it
 * passes the same access checks and can never do more than the analyst could in the UI. Settings
 * are deliberately not reachable. Results are compact text for the model; third-party text is
 * wrapped as untrusted data and every report becomes a numbered evidence item ([S#]).
 *
 * SERVER ONLY.
 */
import { z } from "zod";
import {
  cancelCrawlJob,
  getCrawlerState,
  getDashboard,
  getReport,
  ingestUrl,
  listReports,
  triggerCrawlJob,
} from "../server";
import { searchLibrary } from "../server-search";
import { getActorProfile, listActors } from "../server-actors";
import { createAdvisory, getAdvisory, listAdvisories } from "../server-advisories";
import { buildPurplePath } from "../server-emulation";
import { getResearchCoverage, setReportVisibility } from "../server-library";
import { RESEARCH_CATEGORY_IDS, researchCategory } from "../research-taxonomy";
import { getCollectorOverview } from "../server-collector";
import { getTechnique, mitigationsForTechniques } from "../attack-knowledge";
import { retrieveForChat } from "../search/corpus.server";
import { formatReportId } from "../ids";
import type { ReportListItem } from "../types";
import { EvidenceBook, evidenceLine, type ToolSpec } from "./protocol";

export type ToolContext = { book: EvidenceBook; now: Date };

/** What a read tool returns: text for the model and one line for the analyst. */
export type ToolOutput = { text: string; summary: string };

/** What an action does once the analyst confirms. */
export type ActionOutcome = { ok: boolean; message: string; link?: { label: string; href: string } };

type ReadTool<S extends z.ZodTypeAny> = ToolSpec & { schema: S; run: (args: z.infer<S>, ctx: ToolContext) => Promise<ToolOutput> };
type ActionTool<S extends z.ZodTypeAny> = ToolSpec & {
  action: true;
  schema: S;
  /** The confirmation button text, from the validated arguments. */
  describe: (args: z.infer<S>) => string;
  execute: (args: z.infer<S>) => Promise<ActionOutcome>;
};
export type AgentTool = ReadTool<z.ZodTypeAny> | ActionTool<z.ZodTypeAny>;

/** Typed definitions: each tool's arguments are inferred from its own schema. */
function defineRead<S extends z.ZodTypeAny>(t: ReadTool<S>): AgentTool {
  return t as unknown as AgentTool;
}
function defineAction<S extends z.ZodTypeAny>(t: ActionTool<S>): AgentTool {
  return t as unknown as AgentTool;
}

const isoDate = z
  .string()
  .trim()
  .regex(/^\d{4}-\d{2}-\d{2}/, "use YYYY-MM-DD")
  .transform((s) => s.slice(0, 10));
const clampInt = (min: number, max: number, dflt: number) => z.coerce.number().int().min(min).max(max).catch(dflt).default(dflt);

function day(iso: string | null | undefined): string {
  return iso ? iso.slice(0, 10) : "undated";
}

function shortText(s: string | null | undefined, n: number): string {
  const t = String(s ?? "").replace(/\s+/g, " ").trim();
  return t.length > n ? `${t.slice(0, n - 1)}…` : t;
}

function reportEvidence(ctx: ToolContext, r: ReportListItem, extra = ""): string {
  const e = {
    kind: "report" as const,
    reportId: r.id,
    title: r.title,
    publisher: r.publisher || r.sourceName || "",
    url: r.canonicalUrl || r.url || "",
    publishedAt: r.publishedAt ?? null,
  };
  const id = ctx.book.add(e);
  const actors = r.analysis?.threatActors?.slice(0, 4).join(", ");
  const facts = [
    extra,
    r.classification ? r.classification.toLowerCase().replace(/_/g, " ") : "",
    r.iocCount ? `${r.iocCount} indicators` : "",
    actors ? `actors: ${actors}` : "",
    `ingested ${day(r.ingestedAt)}`,
  ]
    .filter(Boolean)
    .join(" · ");
  return evidenceLine(id, e, facts);
}

// ---------------------------------------------------------------------------
// Read tools
// ---------------------------------------------------------------------------

const searchLibraryTool = defineRead({
  name: "search_library",
  summary: "Full-text and entity search over report passages (actors, malware, CVEs, techniques, behaviour). Returns the best passages with quotes.",
  params: {
    query: { type: "string", description: "what to look for", required: true },
    limit: { type: "integer", description: "passages, 1-8 (default 6)" },
  },
  schema: z.object({ query: z.string().trim().min(1).max(500), limit: clampInt(1, 8, 6) }),
  async run(args, ctx) {
    const res = await retrieveForChat(args.query, { k: args.limit, perDoc: 2 });
    if (!res.passages.length) return { text: `No passage in the library matches "${args.query}".`, summary: `Searched the library for “${shortText(args.query, 60)}”: nothing matched` };
    const byId = new Map(res.candidates.map((c) => [c.id, c]));
    const lines = res.passages.map((p) => {
      const c = byId.get(p.docId);
      const e = {
        kind: "passage" as const,
        reportId: p.docId,
        title: p.title,
        publisher: c?.publisher || c?.sourceName || "",
        url: c?.canonicalUrl || c?.url || "",
        publishedAt: c?.publishedAt ?? null,
        quote: shortText(p.text, 700),
        start: p.start,
        end: p.end,
        score: p.score,
      };
      return evidenceLine(ctx.book.add(e), e);
    });
    const reports = new Set(res.passages.map((p) => p.docId)).size;
    return {
      text: `${res.interpreted.summary ? `Interpreted as: ${res.interpreted.summary}\n` : ""}${lines.join("\n\n")}`,
      summary: `Searched the library for “${shortText(args.query, 60)}”: ${res.passages.length} passages from ${reports} reports`,
    };
  },
});

const listReportsTool = defineRead({
  name: "list_reports",
  summary: "List library reports, newest first, optionally by date range and filters. Use for latest / this week / this month / since questions.",
  params: {
    since: { type: "string", description: "YYYY-MM-DD, inclusive" },
    until: { type: "string", description: "YYYY-MM-DD, inclusive" },
    date_field: { type: "string", description: "which date the range applies to (default published; ingested = added to AIE)", enum: ["published", "ingested"] },
    query: { type: "string", description: "words that must appear in the title, source or summary" },
    actor: { type: "string", description: "threat actor name" },
    malware: { type: "string", description: "malware family" },
    has_iocs: { type: "boolean", description: "only reports with indicators" },
    research: { type: "string", description: "research type of the report", enum: RESEARCH_CATEGORY_IDS },
    limit: { type: "integer", description: "1-25 (default 10)" },
  },
  schema: z.object({
    since: isoDate.optional(),
    until: isoDate.optional(),
    date_field: z.enum(["published", "ingested"]).catch("published").default("published"),
    query: z.string().trim().max(200).optional(),
    actor: z.string().trim().max(120).optional(),
    malware: z.string().trim().max(120).optional(),
    has_iocs: z.boolean().optional(),
    research: z.string().trim().max(40).optional(),
    limit: clampInt(1, 25, 10),
  }),
  async run(args, ctx) {
    // An unknown research type is said, not silently dropped (listing everything would mislead).
    if (args.research && !researchCategory(args.research)) {
      return {
        text: `Unknown research type "${shortText(args.research, 40)}". Use one of: ${RESEARCH_CATEGORY_IDS.join(", ")}.`,
        summary: `Unknown research type "${shortText(args.research, 40)}"`,
      };
    }
    const rows = await listReports({
      data: { q: args.query || undefined, actor: args.actor || undefined, malware: args.malware || undefined, hasIocs: args.has_iocs || undefined, limit: 500, offset: 0 },
    });
    const dateOf = (r: ReportListItem) => (args.date_field === "ingested" ? r.ingestedAt : r.publishedAt || r.ingestedAt) || "";
    const visible = rows.filter(
      (r) => r.status !== "rejected" && r.status !== "duplicate" && (!args.research || (r.research?.labels ?? []).some((l) => l.id === args.research)),
    );
    const inRange = visible
      .filter((r) => {
        const d = dateOf(r).slice(0, 10);
        if (args.since && (!d || d < args.since)) return false;
        if (args.until && (!d || d > args.until)) return false;
        return true;
      })
      .sort((a, b) => dateOf(b).localeCompare(dateOf(a)));
    const range = [args.since && `since ${args.since}`, args.until && `until ${args.until}`].filter(Boolean).join(" ");
    const what = [args.query && `“${shortText(args.query, 40)}”`, args.actor, args.malware, args.research && researchCategory(args.research)?.short]
      .filter(Boolean)
      .join(", ");
    if (!inRange.length) {
      return {
        text: `No report matches (${[what, range, `by ${args.date_field} date`].filter(Boolean).join("; ")}). The library has ${visible.length} matching reports outside that range.`,
        summary: `Listed reports${what ? ` for ${what}` : ""}${range ? ` ${range}` : ""}: none`,
      };
    }
    const shown = inRange.slice(0, args.limit);
    return {
      text: `${inRange.length} reports match (${args.date_field} date${range ? `, ${range}` : ""}); newest ${shown.length}:\n${shown.map((r) => reportEvidence(ctx, r, `${args.date_field} ${day(dateOf(r))}`)).join("\n")}`,
      summary: `Listed ${shown.length} of ${inRange.length} reports${what ? ` for ${what}` : ""}${range ? ` ${range}` : ""}`,
    };
  },
});

const getReportTool = defineRead({
  name: "get_report",
  summary: "Read one report: summary, actors, malware, CVEs, ATT&CK techniques, attack chain and indicators.",
  params: { id: { type: "string", description: "report id (rpt_…) or its RST- display id", required: true } },
  schema: z.object({ id: z.string().trim().min(3).max(200) }),
  async run(args, ctx) {
    const r = await getReport({ data: { id: args.id } });
    if (!r) return { text: `No report with id ${args.id}.`, summary: `Report ${args.id} not found` };
    const e = {
      kind: "passage" as const,
      reportId: r.id,
      title: r.title,
      publisher: r.publisher || r.sourceName || "",
      url: r.canonicalUrl || r.url || "",
      publishedAt: r.publishedAt ?? null,
      quote: shortText(r.extractedText, 1800),
      start: 0,
      end: Math.min(1800, r.extractedText?.length ?? 0),
    };
    const id = ctx.book.add(e);
    const ents = r.extractedEntities;
    const techs = (ents?.techniques ?? []).slice(0, 25).map((t) => `${t.id} ${t.name}`);
    const iocs = (r.iocs ?? []).slice(0, 20).map((i) => `${i.kind}: ${i.original || i.value}`);
    const chain = (r.analysis?.attackChain ?? []).slice(0, 10).map((s) => `${s.order}. ${s.tactic}: ${shortText(s.summary, 160)}`);
    const facts = [
      `Display id ${formatReportId(r.id)} · ${r.classification || "unclassified"} · ${r.wordCount} words · published ${day(r.publishedAt)} · ingested ${day(r.ingestedAt)}${r.translation ? ` · translated from ${r.translation.from}` : ""}`,
      ents?.threatActors?.length || r.analysis?.threatActors?.length ? `Actors: ${(ents?.threatActors?.length ? ents.threatActors : r.analysis?.threatActors ?? []).slice(0, 10).join(", ")}` : "",
      ents?.malwareFamilies?.length ? `Malware: ${ents.malwareFamilies.slice(0, 10).join(", ")}` : "",
      ents?.cves?.length ? `CVEs: ${ents.cves.slice(0, 15).join(", ")}` : "",
      techs.length ? `ATT&CK techniques (${ents?.techniques?.length}): ${techs.join("; ")}` : "",
      chain.length ? `Attack chain:\n${chain.join("\n")}` : "",
      iocs.length ? `Indicators (${r.iocs.length}, first ${iocs.length}): ${iocs.join("; ")}` : "No indicators extracted.",
      r.research?.labels.length ? `Research types: ${r.research.labels.map((l) => researchCategory(l.id)?.short ?? l.id).join(", ")}` : "",
      r.telemetry?.events.length ? `Event IDs named in the report: ${r.telemetry.events.slice(0, 12).map((ev) => `${ev.id} (${ev.log}${ev.meaning ? `: ${ev.meaning}` : ""})`).join("; ")}` : "",
      r.telemetry?.sources.length ? `Log sources named in the report: ${r.telemetry.sources.slice(0, 10).map((x) => x.name).join(", ")}` : "",
      r.telemetry?.content.length ? `Detection content published in the report: ${r.telemetry.content.map((c) => `${c.count} ${c.kind.toUpperCase()}`).join(", ")}` : "",
    ].filter(Boolean);
    return { text: `${evidenceLine(id, e)}\n${facts.join("\n")}`, summary: `Read report ${formatReportId(r.id)} “${shortText(r.title, 60)}”` };
  },
});

const findIndicatorTool = defineRead({
  name: "find_indicator",
  summary: "Find reports that mention an indicator or identifier: IP, domain, URL, hash, CVE id or ATT&CK technique id.",
  params: { value: { type: "string", description: "the indicator, e.g. 109.236.80.191, CVE-2024-3400, T1059.001", required: true } },
  schema: z.object({ value: z.string().trim().min(3).max(300) }),
  async run(args, ctx) {
    const v = args.value.replace(/\[\.\]/g, ".").replace(/^hxxp/i, "http");
    const res = await retrieveForChat(v, { k: 6, perDoc: 1 });
    const lower = v.toLowerCase();
    const hits = res.passages.filter((p) => p.text.toLowerCase().includes(lower));
    if (!hits.length) return { text: `No report passage contains ${v}.`, summary: `Looked up ${shortText(v, 50)}: not in the library` };
    const byId = new Map(res.candidates.map((c) => [c.id, c]));
    const lines = hits.map((p) => {
      const c = byId.get(p.docId);
      const e = {
        kind: "passage" as const,
        reportId: p.docId,
        title: p.title,
        publisher: c?.publisher || c?.sourceName || "",
        url: c?.canonicalUrl || c?.url || "",
        publishedAt: c?.publishedAt ?? null,
        quote: shortText(p.text, 600),
        start: p.start,
        end: p.end,
      };
      return evidenceLine(ctx.book.add(e), e);
    });
    return { text: lines.join("\n\n"), summary: `Looked up ${shortText(v, 50)}: ${new Set(hits.map((h) => h.docId)).size} reports` };
  },
});

const listActorsTool = defineRead({
  name: "list_actors",
  summary: "Threat actors known to AIE (ATT&CK groups and actors seen in reports), with report counts and last activity.",
  params: {
    query: { type: "string", description: "name or alias filter" },
    sort: { type: "string", description: "default recent", enum: ["recent", "reports", "techniques", "name"] },
    observed_only: { type: "boolean", description: "only actors seen in library reports" },
    limit: { type: "integer", description: "1-25 (default 10)" },
  },
  schema: z.object({
    query: z.string().trim().max(120).optional(),
    sort: z.enum(["recent", "reports", "techniques", "name"]).catch("recent").default("recent"),
    observed_only: z.boolean().optional(),
    limit: clampInt(1, 25, 10),
  }),
  async run(args) {
    const res = await listActors({ data: { q: args.query || undefined, observedOnly: args.observed_only, sort: args.sort, limit: args.limit, offset: 0 } });
    if (!res.rows.length) return { text: `No actor matches ${args.query ?? ""}.`, summary: "Listed actors: none" };
    const lines = res.rows.map(
      (a) =>
        `- ${a.name}${a.attackId ? ` (${a.attackId})` : ""} · id ${a.id}${a.aliases.length ? ` · aka ${a.aliases.slice(0, 4).join(", ")}` : ""} · ${a.reportCount} reports · last seen ${day(a.lastSeen)} · ${a.observedTechniques} observed / ${a.attributedTechniques} attributed techniques`,
    );
    return { text: `${res.total} actors match; showing ${res.rows.length}:\n${lines.join("\n")}`, summary: `Listed ${res.rows.length} of ${res.total} threat actors` };
  },
});

const getActorTool = defineRead({
  name: "get_actor",
  summary: "One threat actor's profile: description, techniques (attributed and observed), software, CVEs and the library reports about it.",
  params: { id: { type: "string", description: "actor id or ATT&CK id (G0016) or name", required: true } },
  schema: z.object({ id: z.string().trim().min(2).max(120) }),
  async run(args, ctx) {
    let p = await getActorProfile({ data: { actorId: args.id } });
    if (!p) {
      const found = await listActors({ data: { q: args.id, sort: "reports", limit: 1, offset: 0 } });
      if (found.rows[0]) p = await getActorProfile({ data: { actorId: found.rows[0].id } });
    }
    if (!p) return { text: `No actor matches ${args.id}.`, summary: `Actor ${args.id} not found` };
    const reports = p.reports.slice(0, 8).map((r) => {
      const e = { kind: "report" as const, reportId: r.id, title: r.title, publisher: r.publisher, url: r.url, publishedAt: r.publishedAt };
      return evidenceLine(ctx.book.add(e), e, `matched “${r.matched}”`);
    });
    const techs = p.techniques.slice(0, 30).map((t) => `${t.id} ${t.name} (${t.source}${t.observedReports ? `, ${t.observedReports} reports` : ""})`);
    const text = [
      `${p.row.name}${p.row.attackId ? ` (${p.row.attackId})` : ""}${p.row.aliases.length ? ` · aka ${p.row.aliases.join(", ")}` : ""}`,
      p.description ? `Description (ATT&CK): ${shortText(p.description, 700)}` : "",
      `${p.row.reportCount} library reports · first ${day(p.row.firstSeen)} · last ${day(p.row.lastSeen)}`,
      techs.length ? `Techniques: ${techs.join("; ")}` : "",
      p.software.length ? `Software: ${p.software.slice(0, 15).map((s) => s.name).join(", ")}` : "",
      p.cves.length ? `CVEs: ${p.cves.slice(0, 15).map((c) => c.id).join(", ")}` : "",
      reports.length ? `Reports:\n${reports.join("\n")}` : "No library reports name this actor yet.",
    ].filter(Boolean);
    return { text: text.join("\n"), summary: `Read actor profile ${p.row.name}` };
  },
});

const getTechniqueTool = defineRead({
  name: "get_technique",
  summary: "An ATT&CK technique: name, tactics, platforms, data sources, mitigations, and library reports that mention it.",
  params: { id: { type: "string", description: "technique id, e.g. T1059.001", required: true } },
  schema: z.object({ id: z.string().trim().regex(/^T\d{4}(?:\.\d{3})?$/i, "an ATT&CK technique id like T1059.001") }),
  async run(args, ctx) {
    const id = args.id.toUpperCase();
    const t = getTechnique(id);
    if (!t) return { text: `${id} is not in the bundled ATT&CK knowledge.`, summary: `Technique ${id} not found` };
    const mitigations = mitigationsForTechniques([id]).slice(0, 8).map((m) => `${m.id} ${m.name}`);
    const res = await retrieveForChat(id, { k: 5, perDoc: 1 });
    const byId = new Map(res.candidates.map((c) => [c.id, c]));
    const reports = res.passages
      .filter((p) => p.text.toUpperCase().includes(id) || p.text.toLowerCase().includes(t.name.toLowerCase()))
      .map((p) => {
        const c = byId.get(p.docId);
        const e = { kind: "passage" as const, reportId: p.docId, title: p.title, publisher: c?.publisher || c?.sourceName || "", url: c?.canonicalUrl || c?.url || "", publishedAt: c?.publishedAt ?? null, quote: shortText(p.text, 500), start: p.start, end: p.end };
        return evidenceLine(ctx.book.add(e), e);
      });
    return {
      text: [
        `${t.id} ${t.name} · tactics: ${t.tactics.join(", ")} · platforms: ${t.platforms.join(", ")}`,
        t.dataSources.length ? `Data sources: ${t.dataSources.slice(0, 10).join(", ")}` : "",
        mitigations.length ? `Mitigations: ${mitigations.join("; ")}` : "",
        reports.length ? `Library passages:\n${reports.join("\n\n")}` : "No library passage mentions it.",
      ]
        .filter(Boolean)
        .join("\n"),
      summary: `Read technique ${t.id} ${t.name}`,
    };
  },
});

const libraryOverviewTool = defineRead({
  name: "library_overview",
  summary: "Counts and recent activity: reports, sources, indicators, most-reported actors, ATT&CK tactic distribution, research coverage per research type, latest ingests, crawler status.",
  params: {},
  schema: z.object({}).passthrough(),
  async run(_args, ctx) {
    const [d, coverage] = await Promise.all([getDashboard(), getResearchCoverage().catch(() => null)]);
    const recent = d.recent.slice(0, 6).map((r) => reportEvidence(ctx, r));
    const byCategory = coverage
      ? RESEARCH_CATEGORY_IDS.map((id) => `${researchCategory(id)?.short ?? id} ${coverage.counts[id] ?? 0}`).join(", ")
      : "";
    const text = [
      `${d.reportCount} reports (${d.acquiredCount} in the library) · ${d.sourceCount} sources (${d.enabledSources} enabled) · ${d.iocCount} indicators · average quality ${Math.round(d.avgQuality * 100)}%`,
      `Crawler: ${d.crawlerStatus}${d.lastCrawlAt ? ` · last run ${d.lastCrawlAt}` : ""}${d.nextCrawlAt ? ` · next ${d.nextCrawlAt}` : ""}`,
      d.topThreatActors?.length ? `Most-reported actors: ${d.topThreatActors.slice(0, 8).map((a) => `${a.name} (${a.reportCount})`).join(", ")}` : "",
      d.tacticDistribution?.length ? `Tactics: ${d.tacticDistribution.slice(0, 12).map((t) => `${(t as { tactic?: string; name?: string }).tactic ?? (t as { name?: string }).name} ${(t as { count?: number }).count ?? ""}`).join(", ")}` : "",
      byCategory ? `Research coverage (reports per research type; the crawler searches the thinnest first): ${byCategory}` : "",
      recent.length ? `Latest ingests:\n${recent.join("\n")}` : "",
    ].filter(Boolean);
    return { text: text.join("\n"), summary: "Read the library overview" };
  },
});

const crawlerStatusTool = defineRead({
  name: "crawler_status",
  summary: "The crawler: running job, recent jobs with found / ingested / rejected counts, schedule, failing sources.",
  params: {},
  schema: z.object({}).passthrough(),
  async run() {
    const [s, o] = await Promise.all([getCrawlerState(), getCollectorOverview().catch(() => null)]);
    const job = (j: (typeof s.jobs)[number]) =>
      `- ${j.id} · ${j.status} · ${j.triggerType} · started ${j.startedAt ?? "—"} · found ${j.discoveredCount}, ingested ${j.ingestedCount}, rejected ${j.rejectedCount}, duplicates ${j.duplicateCount}${j.errorSummary ? ` · ${shortText(j.errorSummary, 140)}` : ""}`;
    const failing = (o?.sources ?? []).filter((r) => r.status === "failing" || r.status === "degraded").slice(0, 8);
    const text = [
      s.activeJob ? `Running now: ${job(s.activeJob).slice(2)} · stage ${s.activeJob.currentStage ?? "—"}` : "No crawl is running.",
      `Schedule: ${s.config.enabled ? `every ${s.config.frequencyMinutes} min` : "off"}${s.config.paused ? " (paused)" : ""} · next run ${s.config.nextRunAt ?? "—"}`,
      s.jobs.length ? `Recent jobs:\n${s.jobs.slice(0, 6).map(job).join("\n")}` : "",
      o ? `Sources: ${o.sources.length} tracked, ${o.failing} failing, ${o.dueNow} due now${o.schedulerNote ? ` · ${o.schedulerNote}` : ""}` : "",
      failing.length ? `Failing or degraded:\n${failing.map((r) => `- ${r.name} (${r.status})${r.health?.lastError ? `: ${shortText(r.health.lastError, 120)}` : ""}`).join("\n")}` : "",
    ].filter(Boolean);
    return { text: text.join("\n"), summary: s.activeJob ? "Checked the crawler: a crawl is running" : "Checked the crawler" };
  },
});

const listAdvisoriesTool = defineRead({
  name: "list_advisories",
  summary: "Advisories in AIE with status, TLP, severity and scope.",
  params: { limit: { type: "integer", description: "1-25 (default 10)" } },
  schema: z.object({ limit: clampInt(1, 25, 10) }),
  async run(args) {
    const rows = await listAdvisories();
    if (!rows.length) return { text: "There are no advisories yet.", summary: "Listed advisories: none" };
    const lines = rows
      .slice(0, args.limit)
      .map((a) => `- ${a.number} “${a.title}” · id ${a.id} · ${a.status} · TLP:${a.tlp} · ${a.severity} · ${a.subject.kind} ${a.subject.name} · ${a.scopedSteps} steps · ${a.sources} sources · updated ${day(a.updatedAt)} · /advisories/${a.id}`);
    return { text: `${rows.length} advisories; newest ${lines.length}:\n${lines.join("\n")}`, summary: `Listed ${lines.length} of ${rows.length} advisories` };
  },
});

const getAdvisoryTool = defineRead({
  name: "get_advisory",
  summary: "One advisory: subject, summary, scoped techniques, recommendations and simulation runs.",
  params: { id: { type: "string", description: "advisory id (adv_…)", required: true } },
  schema: z.object({ id: z.string().trim().min(3).max(200) }),
  async run(args) {
    const res = await getAdvisory({ data: { id: args.id } });
    if (!res) return { text: `No advisory with id ${args.id}.`, summary: `Advisory ${args.id} not found` };
    const { record, runs } = res;
    const c = record.content as unknown as Record<string, unknown>;
    const steps = record.content.path.steps.slice(0, 20).map((s) => `${s.order}. ${s.technique.id} ${s.technique.name} (${s.phase}, ${s.priority})`);
    const text = [
      `${record.number} · ${record.status} · TLP:${record.tlp} · created ${day(record.createdAt)} by ${record.createdBy ?? "—"}`,
      typeof c.title === "string" ? `Title: ${c.title}` : "",
      typeof c.summary === "string" ? `Summary: ${shortText(c.summary, 900)}` : "",
      steps.length ? `Scoped steps:\n${steps.join("\n")}` : "",
      runs.length ? `Simulation runs: ${runs.map((r) => `${r.id} ${r.status}`).join(", ")}` : "No simulation runs.",
      `Open: /advisories/${record.id}`,
    ].filter(Boolean);
    return { text: text.join("\n"), summary: `Read advisory ${record.number}` };
  },
});

const planPurplePathTool = defineRead({
  name: "plan_purple_path",
  summary: "Plan (not run) a purple-team emulation path for an actor, campaign or report: ordered techniques with why and simulations.",
  params: {
    kind: { type: "string", description: "what the path is built from", enum: ["actor", "campaign", "report"], required: true },
    value: { type: "string", description: "actor name or id, campaign, or report id", required: true },
    max_steps: { type: "integer", description: "1-20 (default 10)" },
  },
  schema: z.object({ kind: z.enum(["actor", "campaign", "report"]), value: z.string().trim().min(1).max(200), max_steps: clampInt(1, 20, 10) }),
  async run(args) {
    const res = await buildPurplePath({ data: { kind: args.kind, value: args.value, options: { platforms: [], excludeHighRisk: false, maxSteps: args.max_steps } } });
    if ("error" in res) return { text: `Could not plan a path: ${res.error}`, summary: `Purple path for ${args.value}: ${res.error}` };
    const steps = res.path.steps.map((s) => `${s.order}. [${s.phase}] ${s.technique.id} ${s.technique.name} · ${s.priority} · ${shortText(s.reasonText, 180)}`);
    return {
      text: `Purple path for ${res.seed.name} (${res.path.orderBasis} order; ${res.path.candidateCount} candidate techniques, ${res.path.excluded.length} left out):\n${steps.join("\n")}\nBuild and save it in the Purple paths page: /purple`,
      summary: `Planned a ${steps.length}-step purple path for ${res.seed.name}`,
    };
  },
});

// ---------------------------------------------------------------------------
// Action tools (proposed; run only after the analyst confirms)
// ---------------------------------------------------------------------------

const startCrawlTool = defineAction({
  name: "start_crawl",
  action: true,
  summary: "Start a crawl now, optionally focused on a topic (actor, malware, CVE).",
  params: { query: { type: "string", description: "focus of a targeted crawl; omit for a normal crawl of all sources" } },
  schema: z.object({ query: z.string().trim().max(300).optional() }),
  describe: (a) => (a.query ? `Start a crawl focused on “${shortText(a.query, 60)}”` : "Start a crawl of all sources"),
  async execute(a) {
    const res = await triggerCrawlJob({ data: { triggerType: a.query ? "SEARCH" : "AGENT", customQuery: a.query || undefined } });
    if (!res.ok) return { ok: false, message: res.error };
    return { ok: true, message: `Crawl ${res.job.id} started.`, link: { label: "Watch it on Ingest", href: "/ingest" } };
  },
});

const cancelCrawlTool = defineAction({
  name: "cancel_crawl",
  action: true,
  summary: "Cancel a running crawl job.",
  params: { job_id: { type: "string", description: "job id from crawler_status", required: true } },
  schema: z.object({ job_id: z.string().trim().min(3).max(100) }),
  describe: (a) => `Cancel crawl ${a.job_id}`,
  async execute(a) {
    const res = await cancelCrawlJob({ data: { jobId: a.job_id } });
    return res.ok ? { ok: true, message: `Crawl ${a.job_id} cancelled.` } : { ok: false, message: `Crawl ${a.job_id} is not running.` };
  },
});

const hideReportsTool = defineAction({
  name: "hide_reports",
  action: true,
  summary: "Hide reports from the library (reversible: Restore brings them back).",
  params: { ids: { type: "string[]", description: "report ids", required: true } },
  schema: z.object({ ids: z.array(z.string().trim().min(3).max(200)).min(1).max(50) }),
  describe: (a) => `Hide ${a.ids.length} report${a.ids.length === 1 ? "" : "s"} from the library`,
  async execute(a) {
    const res = await setReportVisibility({ data: { ids: a.ids, action: "hide" } });
    return { ok: true, message: `${res.changed} report${res.changed === 1 ? "" : "s"} hidden. They stay in Library → Hidden.`, link: { label: "Open the library", href: "/library" } };
  },
});

const restoreReportsTool = defineAction({
  name: "restore_reports",
  action: true,
  summary: "Restore hidden reports to the library for good.",
  params: { ids: { type: "string[]", description: "report ids", required: true } },
  schema: z.object({ ids: z.array(z.string().trim().min(3).max(200)).min(1).max(50) }),
  describe: (a) => `Restore ${a.ids.length} report${a.ids.length === 1 ? "" : "s"} to the library`,
  async execute(a) {
    const res = await setReportVisibility({ data: { ids: a.ids, action: "restore" } });
    return { ok: true, message: `${res.changed} report${res.changed === 1 ? "" : "s"} restored.`, link: { label: "Open the library", href: "/library" } };
  },
});

const createAdvisoryTool = defineAction({
  name: "create_advisory",
  action: true,
  summary: "Create a draft advisory from the library about an actor, campaign, vulnerability (CVE) or malware.",
  params: {
    kind: { type: "string", description: "subject type", enum: ["actor", "campaign", "vulnerability", "malware"], required: true },
    value: { type: "string", description: "actor name, campaign, CVE id or malware family", required: true },
  },
  schema: z.object({ kind: z.enum(["actor", "campaign", "vulnerability", "malware"]), value: z.string().trim().min(2).max(200) }),
  describe: (a) => `Create a draft advisory on ${a.kind} “${shortText(a.value, 60)}”`,
  async execute(a) {
    const input = a.kind === "vulnerability" ? { kind: a.kind, value: a.value, cveIds: /^CVE-\d{4}-\d{4,7}$/i.test(a.value) ? [a.value.toUpperCase()] : undefined } : { kind: a.kind, value: a.value };
    const rec = await createAdvisory({ data: { input } });
    return { ok: true, message: `Draft advisory ${rec.number} created.`, link: { label: `Open ${rec.number}`, href: `/advisories/${rec.id}` } };
  },
});

const ingestUrlTool = defineAction({
  name: "ingest_url",
  action: true,
  summary: "Fetch one public report URL and add it to the library (it passes the same quality checks as crawled pages).",
  params: { url: { type: "string", description: "https URL of the report", required: true } },
  schema: z.object({ url: z.string().trim().url().max(2048).refine((u) => /^https?:\/\//i.test(u), "http(s) only") }),
  describe: (a) => `Ingest ${shortText(a.url, 80)}`,
  async execute(a) {
    const res = (await ingestUrl({ data: { url: a.url } })) as { ok: boolean; error?: string; reportId?: string; report?: { id: string } };
    if (!res.ok) return { ok: false, message: res.error || "The page was not ingested." };
    const id = res.reportId ?? res.report?.id;
    return { ok: true, message: "Report ingested.", link: id ? { label: "Open the report", href: `/library/${id}` } : { label: "Open the library", href: "/library" } };
  },
});

export const AGENT_TOOLS: AgentTool[] = [
  searchLibraryTool,
  listReportsTool,
  getReportTool,
  findIndicatorTool,
  listActorsTool,
  getActorTool,
  getTechniqueTool,
  libraryOverviewTool,
  crawlerStatusTool,
  listAdvisoriesTool,
  getAdvisoryTool,
  planPurplePathTool,
  startCrawlTool,
  cancelCrawlTool,
  hideReportsTool,
  restoreReportsTool,
  createAdvisoryTool,
  ingestUrlTool,
];

export function findTool(name: string): AgentTool | undefined {
  return AGENT_TOOLS.find((t) => t.name === name);
}

export function isActionTool(t: AgentTool): t is ActionTool<z.ZodTypeAny> {
  return t.action === true;
}
