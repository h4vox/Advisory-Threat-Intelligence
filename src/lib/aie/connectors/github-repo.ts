/**
 * GitHub-repository connectors (spec §15: Git sources preferred over HTML).
 *
 * - CTID Adversary Emulation Library → ADVERSARY_EMULATION_PLAN (one per
 *   adversary folder) and MICRO_EMULATION_PLAN (micro_emulation_plans/src/*).
 * - MITRE Attack Flow corpus (corpus/*.afb) → ATTACK_FLOW with ordered actions.
 * - CALDERA stockpile (data/abilities/**.yml) → CALDERA_ABILITY per technique.
 * - Unit 42 IOC repository → THREAT_REPORT documents with harvested IOCs.
 *
 * Listing prefers the git-trees API; when it is unreachable (rate limit,
 * egress policy) CTID and Attack Flow fall back to the index files the
 * projects publish in-repo (root README tables, docs/example_flows.rst),
 * fetched from raw.githubusercontent.com. Parsers are pure.
 */
import { parse as parseYaml } from "yaml";
import type { EmulationOption, ReportRecord } from "../types.ts";
import { harvestIocs } from "../extract.ts";
import {
  buildStructuredReport,
  mapLimit,
  slugify,
  techniqueIdsIn,
  uniq,
  type ConnectorResult,
  type ConnectorSource,
  type EmulationIndexEntry,
  type TechniqueLookup,
} from "./common.ts";
import { githubBlobUrl, githubRawUrl, githubTreeUrl, type ConnectorFetcher, type GithubTreeEntry } from "./fetch.ts";

export type RepoConfig = { owner: string; repo: string; branch: string; path?: string };

export function repoConfigFrom(cfg: Record<string, string> | undefined, fallback: RepoConfig): RepoConfig {
  return {
    owner: cfg?.owner || fallback.owner,
    repo: cfg?.repo || fallback.repo,
    branch: cfg?.branch || fallback.branch,
    path: cfg?.path ?? fallback.path,
  };
}

const stripMd = (s: string) =>
  s
    .replace(/\[([^\]]*)\]\([^)]*\)/g, "$1")
    .replace(/[*_`]/g, "")
    .replace(/<[^>]+>/g, "")
    .replace(/\s+/g, " ")
    .trim();

// ---------------------------------------------------------------------------
// CTID Adversary Emulation Library
// ---------------------------------------------------------------------------

export type CtidIndexEntry = {
  name: string;
  /** Repository folder without leading/trailing slash, e.g. "fin6" or "micro_emulation_plans/src/webshell". */
  folder: string;
  planType: "full" | "micro";
  summary: string;
  /** Linked intelligence summary path, when the index row links one. */
  summaryPath?: string;
};

/** Parses the library's root README tables (adversary plans + micro plans). */
export function parseCtidReadmeIndex(markdown: string): CtidIndexEntry[] {
  const out: CtidIndexEntry[] = [];
  const seen = new Set<string>();
  for (const line of markdown.split(/\r?\n/)) {
    const m = line.match(/^\|\s*\[([^\]]+)\]\(\.?(\/?[^)\s]+)\)\s*\|(.*)\|\s*$/);
    if (!m) continue;
    const folder = m[2].replace(/^\.?\//, "").replace(/\/+$/, "");
    if (!folder || /^https?:/i.test(m[2]) || folder.includes("..")) continue;
    if (seen.has(folder)) continue;
    seen.add(folder);
    const planType = folder.startsWith("micro_emulation_plans/") || folder.startsWith("src/") ? "micro" : "full";
    const normalized = folder.startsWith("src/") ? `micro_emulation_plans/${folder}` : folder;
    const summaryLink = m[3].match(/\]\(\.?\/?([^)\s]+\.md)\)/);
    out.push({
      name: stripMd(m[1]),
      folder: normalized,
      planType,
      summary: stripMd(m[3]).replace(/\.{3,}$/, "…"),
      summaryPath: summaryLink && !/^https?:/i.test(summaryLink[1]) ? summaryLink[1].replace(/^\/+/, "") : undefined,
    });
  }
  return out;
}

/** Relative markdown links inside `folder` from a README (resolved to repo paths). */
export function linkedRepoFiles(markdown: string, folder: string): string[] {
  const out: string[] = [];
  for (const m of markdown.matchAll(/\]\(([^)\s#]+)(?:#[^)]*)?\)/g)) {
    const href = m[1];
    if (/^[a-z]+:/i.test(href)) continue;
    let path: string;
    if (href.startsWith("/")) path = href.slice(1);
    else {
      const parts = `${folder}/${href}`.split("/");
      const stack: string[] = [];
      for (const p of parts) {
        if (!p || p === ".") continue;
        if (p === "..") stack.pop();
        else stack.push(p);
      }
      path = stack.join("/");
    }
    if (!path.startsWith(`${folder}/`)) continue;
    if (!/\.(md|ya?ml)$/i.test(path)) continue;
    out.push(path);
  }
  return uniq(out);
}

/** Picks the files that describe a plan from a tree listing (README, summaries, flows, YAML). */
export function selectCtidPlanFiles(entries: GithubTreeEntry[], folder: string, max = 8): string[] {
  const inFolder = entries.filter((e) => e.type === "blob" && e.path.startsWith(`${folder}/`));
  const rank = (p: string) => {
    const rel = p.slice(folder.length + 1).toLowerCase();
    if (rel === "readme.md") return 0;
    if (rel.includes("intelligence_summary") && rel.endsWith(".md")) return 1;
    if (rel.includes("operations_flow") && rel.endsWith(".md")) return 2;
    if (rel === "emulation_plan/readme.md") return 3;
    if (/emulation_plan\/.*\.ya?ml$/.test(rel)) return 4;
    if (/emulation_plan\/[^/]+\.md$/.test(rel)) return 5;
    if (/^[^/]+\.md$/.test(rel)) return 6;
    return 99;
  };
  return inFolder
    .map((e) => e.path)
    .filter((p) => rank(p) < 99)
    .sort((a, b) => rank(a) - rank(b) || a.localeCompare(b))
    .slice(0, max);
}

export type CtidPlanContent = { entry: CtidIndexEntry; files: Array<{ path: string; text: string }>; allFiles: string[] };

export function buildCtidPlanDoc(plan: CtidPlanContent, source: ConnectorSource, repo: RepoConfig, opts?: { now?: string; lookup?: TechniqueLookup }) {
  const { entry } = plan;
  const corpus = plan.files.map((f) => f.text).join("\n\n");
  const techniques = techniqueIdsIn(corpus).sort((a, b) => a.localeCompare(b, "en", { numeric: true }));
  const slug = entry.planType === "micro" ? slugify(entry.folder.split("/").pop() ?? entry.name) : slugify(entry.folder);
  const id = entry.planType === "micro" ? `ctid_micro_${slug}` : `ctid_${slug}`;
  const url = githubTreeUrl(repo.owner, repo.repo, repo.branch, entry.folder);
  const docType = entry.planType === "micro" ? "MICRO_EMULATION_PLAN" : "ADVERSARY_EMULATION_PLAN";
  const sections = plan.files.map((f) => `## ${f.path.slice(entry.folder.length + 1) || f.path}\n\n${f.text.trim()}`);
  const text = [
    `${entry.name} — CTID ${entry.planType === "micro" ? "micro emulation plan" : "adversary emulation plan"}.`,
    entry.summary,
    techniques.length ? `Techniques referenced (${techniques.length}): ${techniques.join(", ")}` : "",
    "",
    ...sections,
  ]
    .filter((s) => s !== undefined)
    .join("\n")
    .slice(0, 250_000);
  const doc = buildStructuredReport({
    id,
    source,
    docTypes: [docType, ...(entry.planType === "full" ? (["PURPLE_TEAM_REPORT"] as const) : [])],
    title: entry.planType === "micro" ? `Micro emulation plan: ${entry.name}` : `${entry.name} adversary emulation plan`,
    url,
    text,
    techniques,
    actors: entry.planType === "full" ? [entry.name] : [],
    structured: {
      kind: "emulation_plan",
      adversary: entry.name,
      planType: entry.planType,
      techniques,
      files: plan.allFiles.length ? plan.allFiles : plan.files.map((f) => f.path),
    },
    emulation: [`CTID ${entry.planType} plan: ${entry.name}`],
    contentType: "text/markdown",
    tags: [entry.planType === "full" ? `actor:${entry.name}` : `emulation:${slug}`, "emulation:ctid"],
    lookup: opts?.lookup,
    now: opts?.now,
    publisher: "MITRE Center for Threat-Informed Defense",
    author: "CTID",
  });
  const options: EmulationIndexEntry[] = techniques.map((techniqueId) => ({
    techniqueId,
    kind: "ctid_procedure",
    sourceId: source.id,
    options: [
      {
        techniqueId,
        kind: "ctid_procedure",
        name: `${entry.name} (${entry.planType === "micro" ? "micro plan" : "emulation plan"})`,
        ref: entry.folder,
        platforms: [],
        sourceUrl: url,
      },
    ],
  }));
  return { doc, options };
}

export async function syncCtidLibrary(
  source: ConnectorSource,
  fetcher: ConnectorFetcher,
  opts?: { now?: string; lookup?: TechniqueLookup; maxPlans?: number },
): Promise<ConnectorResult> {
  const repo = repoConfigFrom(source.connectorConfig, {
    owner: "center-for-threat-informed-defense",
    repo: "adversary_emulation_library",
    branch: "master",
  });
  const warnings: string[] = [];
  const readme = await fetcher.text(githubRawUrl(repo.owner, repo.repo, repo.branch, "README.md"), { maxBytes: 2_000_000 });
  const index = parseCtidReadmeIndex(readme).slice(0, opts?.maxPlans ?? 60);
  if (index.length === 0) throw new Error("No emulation plans found in the library README index");

  let tree: GithubTreeEntry[] | null = null;
  try {
    tree = (await fetcher.githubTree(repo.owner, repo.repo, repo.branch)).entries;
  } catch (err) {
    warnings.push(`File listing unavailable (${err instanceof Error ? err.message : String(err)}); used README links instead.`);
  }

  const plans = await mapLimit(index, 4, async (entry): Promise<CtidPlanContent> => {
    const files: Array<{ path: string; text: string }> = [];
    const fetchFile = async (path: string) => {
      if (files.some((f) => f.path === path)) return;
      try {
        files.push({ path, text: await fetcher.text(githubRawUrl(repo.owner, repo.repo, repo.branch, path), { maxBytes: 2_000_000 }) });
      } catch (err) {
        warnings.push(`${path}: ${err instanceof Error ? err.message : String(err)}`);
      }
    };
    let allFiles: string[] = [];
    if (tree) {
      allFiles = tree.filter((e) => e.type === "blob" && e.path.startsWith(`${entry.folder}/`)).map((e) => e.path);
      for (const p of selectCtidPlanFiles(tree, entry.folder)) await fetchFile(p);
    } else {
      await fetchFile(`${entry.folder}/README.md`);
      if (entry.summaryPath) await fetchFile(entry.summaryPath);
      const linked = files[0] ? linkedRepoFiles(files[0].text, entry.folder) : [];
      const preferred = linked
        .filter((p) => /intelligence_summary|operations_flow|emulation_plan\/readme|\.ya?ml$/i.test(p))
        .slice(0, 4);
      for (const p of preferred) await fetchFile(p);
      allFiles = uniq([...files.map((f) => f.path), ...linked]);
    }
    return { entry, files, allFiles };
  });

  const docs: ReportRecord[] = [];
  const emulation: EmulationIndexEntry[] = [];
  let full = 0;
  let micro = 0;
  for (const plan of plans) {
    if (plan.files.length === 0) continue;
    const { doc, options } = buildCtidPlanDoc(plan, source, repo, opts);
    docs.push(doc);
    emulation.push(...options);
    if (plan.entry.planType === "full") full++;
    else micro++;
  }
  return { docs, emulation, stats: { fullPlans: full, microPlans: micro, techniques: uniq(emulation.map((e) => e.techniqueId)).length }, warnings };
}

// ---------------------------------------------------------------------------
// MITRE Attack Flow corpus
// ---------------------------------------------------------------------------

type AfbObject = {
  id: string;
  instance: string;
  properties?: Array<[string, unknown]>;
  anchors?: Record<string, string>;
  latches?: string[];
  source?: string;
  target?: string;
};

export type ParsedAttackFlow = {
  flowName: string;
  description: string;
  scope?: string;
  author?: string;
  created?: string;
  references: Array<{ name: string; url: string }>;
  actions: Array<{ id: string; techniqueId?: string; tacticId?: string; name: string; description?: string }>;
  relationships: Array<{ from: string; to: string }>;
  /** Non-action nodes (tools, malware, assets…) by template id. */
  objects: Array<{ type: string; name: string }>;
};

function propMap(props: Array<[string, unknown]> | undefined): Map<string, unknown> {
  const m = new Map<string, unknown>();
  for (const p of props ?? []) if (Array.isArray(p) && typeof p[0] === "string") m.set(p[0], p[1]);
  return m;
}

const asStr = (v: unknown) => (typeof v === "string" ? v.trim() : "");

/**
 * Parses an Attack Flow Builder (.afb, schema attack_flow_v2) file. Lines
 * connect latches; latches belong to anchors; anchors belong to nodes. Edges
 * between actions are resolved through operator/asset nodes so the result is
 * an action→action graph.
 */
export function parseAttackFlowAfb(input: string | { schema?: string; objects?: AfbObject[] }): ParsedAttackFlow {
  const doc = typeof input === "string" ? JSON.parse(input) : input;
  const objects: AfbObject[] = Array.isArray(doc?.objects) ? doc.objects : [];
  if (objects.length === 0) throw new Error("Attack Flow file has no objects");
  const flowObj = objects.find((o) => o.id === "flow");
  const fp = propMap(flowObj?.properties);

  const anchorToNode = new Map<string, string>();
  const nodes = new Map<string, AfbObject>();
  for (const o of objects) {
    if (o.anchors && o.properties) {
      nodes.set(o.instance, o);
      for (const a of Object.values(o.anchors)) anchorToNode.set(a, o.instance);
    }
  }
  const latchToNode = new Map<string, string>();
  for (const o of objects) {
    if (Array.isArray(o.latches)) {
      const node = anchorToNode.get(o.instance);
      if (node) for (const l of o.latches) latchToNode.set(l, node);
    }
  }
  const out = new Map<string, Set<string>>();
  for (const o of objects) {
    if (o.id !== "dynamic_line" || !o.source || !o.target) continue;
    const from = latchToNode.get(o.source);
    const to = latchToNode.get(o.target);
    if (!from || !to || from === to) continue;
    const set = out.get(from) ?? new Set<string>();
    set.add(to);
    out.set(from, set);
  }

  const actions: ParsedAttackFlow["actions"] = [];
  const objectsOut: ParsedAttackFlow["objects"] = [];
  for (const [instance, node] of nodes) {
    const p = propMap(node.properties);
    if (node.id === "action") {
      const techniqueId = asStr(p.get("technique_id")).toUpperCase() || undefined;
      actions.push({
        id: instance,
        techniqueId: techniqueId && /^T\d{4}(\.\d{3})?$/.test(techniqueId) ? techniqueId : undefined,
        tacticId: asStr(p.get("tactic_id")) || undefined,
        name: asStr(p.get("name")) || techniqueId || "Action",
        description: asStr(p.get("description")) || undefined,
      });
    } else if (!/operator$/i.test(node.id)) {
      const name = asStr(p.get("name")) || asStr(p.get("command_line")) || asStr(p.get("key")) || asStr(p.get("path")) || asStr(p.get("value"));
      if (name) objectsOut.push({ type: node.id, name });
    }
  }
  const actionIds = new Set(actions.map((a) => a.id));
  const relationships: ParsedAttackFlow["relationships"] = [];
  const relSeen = new Set<string>();
  for (const a of actions) {
    // Breadth-first through non-action nodes until the next actions.
    const queue = [...(out.get(a.id) ?? [])];
    const visited = new Set<string>([a.id]);
    while (queue.length) {
      const n = queue.shift()!;
      if (visited.has(n)) continue;
      visited.add(n);
      if (actionIds.has(n)) {
        const key = `${a.id}>${n}`;
        if (!relSeen.has(key)) {
          relSeen.add(key);
          relationships.push({ from: a.id, to: n });
        }
        continue;
      }
      for (const next of out.get(n) ?? []) queue.push(next);
    }
  }

  // Order actions topologically (Kahn) so the stored list follows the flow.
  const indeg = new Map(actions.map((a) => [a.id, 0]));
  for (const r of relationships) indeg.set(r.to, (indeg.get(r.to) ?? 0) + 1);
  const ordered: typeof actions = [];
  const byId = new Map(actions.map((a) => [a.id, a]));
  const ready = actions.filter((a) => (indeg.get(a.id) ?? 0) === 0).map((a) => a.id);
  const adj = new Map<string, string[]>();
  for (const r of relationships) adj.set(r.from, [...(adj.get(r.from) ?? []), r.to]);
  while (ready.length) {
    const id = ready.shift()!;
    ordered.push(byId.get(id)!);
    for (const to of adj.get(id) ?? []) {
      indeg.set(to, (indeg.get(to) ?? 0) - 1);
      if (indeg.get(to) === 0) ready.push(to);
    }
  }
  for (const a of actions) if (!ordered.includes(a)) ordered.push(a); // cycles: keep the rest

  const author = fp.get("author");
  const authorName = Array.isArray(author) ? asStr(propMap(author as Array<[string, unknown]>).get("name")) : asStr(author);
  const refs: ParsedAttackFlow["references"] = [];
  const ext = fp.get("external_references");
  if (Array.isArray(ext)) {
    for (const item of ext) {
      const inner = Array.isArray(item) ? item[1] : null;
      if (!Array.isArray(inner)) continue;
      const rp = propMap(inner as Array<[string, unknown]>);
      const url = asStr(rp.get("url"));
      if (url) refs.push({ name: asStr(rp.get("source_name")) || url, url });
    }
  }

  return {
    flowName: asStr(fp.get("name")) || "Untitled flow",
    description: asStr(fp.get("description")),
    scope: asStr(fp.get("scope")) || undefined,
    author: authorName || undefined,
    created: asStr(fp.get("created")) || undefined,
    references: refs,
    actions: ordered,
    relationships,
    objects: objectsOut,
  };
}

/** Corpus file names (without extension) from docs/example_flows.rst. */
export function parseAttackFlowExampleIndex(rst: string): string[] {
  const out: string[] = [];
  for (const m of rst.matchAll(/\.\.\/corpus\/([^"'<>]+?)\.afb/g)) {
    try {
      out.push(decodeURIComponent(m[1]));
    } catch {
      out.push(m[1]);
    }
  }
  return uniq(out);
}

export function buildAttackFlowDoc(
  flow: ParsedAttackFlow,
  filePath: string,
  source: ConnectorSource,
  repo: RepoConfig,
  opts?: { now?: string; lookup?: TechniqueLookup },
) {
  const techniques = uniq(flow.actions.map((a) => a.techniqueId).filter((t): t is string => !!t));
  const url = githubBlobUrl(repo.owner, repo.repo, repo.branch, filePath);
  const nameOf = new Map(flow.actions.map((a) => [a.id, a.name]));
  const text = [
    `${flow.flowName} — MITRE Attack Flow${flow.scope ? ` (scope: ${flow.scope})` : ""}.`,
    flow.description,
    flow.author ? `Author: ${flow.author}.` : "",
    "",
    `Actions (${flow.actions.length}):`,
    ...flow.actions.map((a, i) => `${i + 1}. ${a.techniqueId ? `${a.techniqueId} ` : ""}${a.name}${a.description ? ` — ${a.description}` : ""}`),
    "",
    flow.relationships.length ? `Flow edges (${flow.relationships.length}):` : "",
    ...flow.relationships.map((r) => `- ${nameOf.get(r.from)} → ${nameOf.get(r.to)}`),
    flow.objects.length ? `\nObjects: ${flow.objects.map((o) => `${o.name} (${o.type.replace(/_/g, " ")})`).join("; ")}` : "",
    flow.references.length ? `\nReferences:\n${flow.references.map((r) => `- ${r.name}: ${r.url}`).join("\n")}` : "",
  ]
    .filter((s) => s !== "")
    .join("\n");
  const malware = flow.objects.filter((o) => o.type === "malware" || o.type === "tool").map((o) => o.name);
  const slug = slugify(filePath.split("/").pop()!.replace(/\.afb$/i, ""));
  const doc = buildStructuredReport({
    id: `af_${slug}`,
    source,
    docTypes: ["ATTACK_FLOW", ...(/\bAA\d{2}-\d{3}/i.test(flow.flowName) ? (["THREAT_ADVISORY"] as const) : [])],
    title: `Attack Flow: ${flow.flowName}`,
    url,
    text,
    publishedAt: flow.created ?? null,
    techniques,
    malware,
    structured: {
      kind: "attack_flow",
      flowName: flow.flowName,
      scope: flow.scope,
      actions: flow.actions.map((a) => ({ id: a.id, techniqueId: a.techniqueId, name: a.name, description: a.description })),
      relationships: flow.relationships,
    },
    emulation: [`Attack Flow: ${flow.flowName}`],
    tags: [`flow:${slug}`, "emulation:attack-flow"],
    lookup: opts?.lookup,
    now: opts?.now,
    publisher: "MITRE Center for Threat-Informed Defense",
    author: flow.author ?? "CTID",
  });
  const options: EmulationIndexEntry[] = techniques.map((techniqueId) => ({
    techniqueId,
    kind: "attack_flow",
    sourceId: source.id,
    options: [
      {
        techniqueId,
        kind: "attack_flow",
        name: flow.flowName,
        ref: filePath,
        platforms: [],
        sourceUrl: url,
      },
    ],
  }));
  return { doc, options };
}

export async function syncAttackFlowCorpus(
  source: ConnectorSource,
  fetcher: ConnectorFetcher,
  opts?: { now?: string; lookup?: TechniqueLookup; maxFlows?: number },
): Promise<ConnectorResult> {
  const repo = repoConfigFrom(source.connectorConfig, {
    owner: "center-for-threat-informed-defense",
    repo: "attack-flow",
    branch: "main",
    path: "corpus/",
  });
  const dir = (repo.path || "corpus/").replace(/^\/+|\/+$/g, "");
  const warnings: string[] = [];
  let files: string[] = [];
  try {
    const { entries } = await fetcher.githubTree(repo.owner, repo.repo, repo.branch);
    files = entries.filter((e) => e.type === "blob" && e.path.startsWith(`${dir}/`) && e.path.endsWith(".afb")).map((e) => e.path);
  } catch (err) {
    warnings.push(`File listing unavailable (${err instanceof Error ? err.message : String(err)}); used docs/example_flows.rst index.`);
    const rst = await fetcher.text(githubRawUrl(repo.owner, repo.repo, repo.branch, "docs/example_flows.rst"), { maxBytes: 3_000_000 });
    files = parseAttackFlowExampleIndex(rst).map((n) => `${dir}/${n}.afb`);
  }
  files = files.sort().slice(0, opts?.maxFlows ?? 120);
  if (files.length === 0) throw new Error("No Attack Flow corpus files found");

  const docs: ReportRecord[] = [];
  const emulation: EmulationIndexEntry[] = [];
  let actions = 0;
  await mapLimit(files, 6, async (path) => {
    try {
      const raw = await fetcher.text(githubRawUrl(repo.owner, repo.repo, repo.branch, path), { maxBytes: 6_000_000 });
      const flow = parseAttackFlowAfb(raw);
      const { doc, options } = buildAttackFlowDoc(flow, path, source, repo, opts);
      docs.push(doc);
      emulation.push(...options);
      actions += flow.actions.length;
    } catch (err) {
      warnings.push(`${path}: ${err instanceof Error ? err.message : String(err)}`);
    }
  });
  docs.sort((a, b) => a.id.localeCompare(b.id));
  return { docs, emulation, stats: { flows: docs.length, actions, techniques: uniq(emulation.map((e) => e.techniqueId)).length }, warnings };
}

// ---------------------------------------------------------------------------
// CALDERA stockpile abilities
// ---------------------------------------------------------------------------

export type CalderaAbility = {
  id: string;
  name: string;
  description?: string;
  tactic?: string;
  techniqueId: string;
  techniqueName?: string;
  platforms: string[];
  executors: string[];
  privilege?: string;
  path: string;
};

/** Parses one stockpile ability YAML file (a list with one or more abilities). */
export function parseCalderaAbilityYaml(text: string, path: string): CalderaAbility[] {
  const doc = parseYaml(text) as unknown;
  const list = Array.isArray(doc) ? doc : doc ? [doc] : [];
  const out: CalderaAbility[] = [];
  for (const raw of list as Array<Record<string, unknown>>) {
    if (!raw || typeof raw !== "object") continue;
    const technique = (raw.technique ?? {}) as Record<string, unknown>;
    const techniqueId = String(technique.attack_id ?? "").toUpperCase();
    if (!/^T\d{4}(\.\d{3})?$/.test(techniqueId)) continue;
    const platformsRaw = raw.platforms && typeof raw.platforms === "object" ? (raw.platforms as Record<string, unknown>) : {};
    const platforms = Object.keys(platformsRaw);
    const executors = uniq(
      platforms.flatMap((p) => {
        const ex = platformsRaw[p];
        return ex && typeof ex === "object" ? Object.keys(ex as Record<string, unknown>).flatMap((k) => k.split(",").map((s) => s.trim())) : [];
      }),
    );
    out.push({
      id: String(raw.id ?? path),
      name: String(raw.name ?? techniqueId),
      description: typeof raw.description === "string" ? raw.description.trim() : undefined,
      tactic: typeof raw.tactic === "string" ? raw.tactic : undefined,
      techniqueId,
      techniqueName: typeof technique.name === "string" ? technique.name : undefined,
      platforms,
      executors,
      privilege: typeof raw.privilege === "string" ? raw.privilege : undefined,
      path,
    });
  }
  return out;
}

export function buildCalderaResult(abilities: CalderaAbility[], source: ConnectorSource, repo: RepoConfig, opts?: { now?: string; lookup?: TechniqueLookup }): ConnectorResult {
  const byTech = new Map<string, CalderaAbility[]>();
  for (const a of abilities) byTech.set(a.techniqueId, [...(byTech.get(a.techniqueId) ?? []), a]);
  const docs: ReportRecord[] = [];
  const emulation: EmulationIndexEntry[] = [];
  for (const [techniqueId, list] of [...byTech].sort((a, b) => a[0].localeCompare(b[0], "en", { numeric: true }))) {
    const name = opts?.lookup?.(techniqueId)?.name ?? list[0].techniqueName ?? techniqueId;
    const options: EmulationOption[] = list.map((a) => ({
      techniqueId,
      kind: "caldera_ability",
      name: a.name,
      ref: a.id,
      platforms: a.platforms,
      executor: a.executors.join(", ") || undefined,
      sourceUrl: githubBlobUrl(repo.owner, repo.repo, repo.branch, a.path),
      elevationRequired: a.privilege ? /elevated|root|admin/i.test(a.privilege) : undefined,
    }));
    emulation.push({ techniqueId, kind: "caldera_ability", sourceId: source.id, options });
    docs.push(
      buildStructuredReport({
        id: `cal_${techniqueId}`,
        source,
        docTypes: ["CALDERA_ABILITY"],
        title: `CALDERA abilities: ${techniqueId} ${name}`,
        url: githubBlobUrl(repo.owner, repo.repo, repo.branch, list[0].path),
        text: [
          `MITRE CALDERA stockpile abilities for ${techniqueId} ${name} (${list.length}).`,
          "",
          ...list.map((a, i) => `${i + 1}. ${a.name} [${a.platforms.join(", ")}; ${a.executors.join(", ")}]${a.description ? ` — ${a.description}` : ""}`),
        ].join("\n"),
        techniques: [techniqueId],
        emulation: list.map((a) => `CALDERA: ${a.name}`),
        contentType: "application/yaml",
        tags: [`technique:${techniqueId}`, "emulation:caldera"],
        lookup: opts?.lookup,
        now: opts?.now,
        publisher: "MITRE CALDERA",
        author: "MITRE",
      }),
    );
  }
  return { docs, emulation, stats: { abilities: abilities.length, techniques: byTech.size }, warnings: [] };
}

export async function syncCalderaStockpile(
  source: ConnectorSource,
  fetcher: ConnectorFetcher,
  opts?: { now?: string; lookup?: TechniqueLookup; maxFiles?: number },
): Promise<ConnectorResult> {
  const repo = repoConfigFrom(source.connectorConfig, { owner: "mitre", repo: "stockpile", branch: "master", path: "data/abilities/" });
  const dir = (repo.path || "data/abilities/").replace(/^\/+|\/+$/g, "");
  const { entries, truncated } = await fetcher.githubTree(repo.owner, repo.repo, repo.branch);
  const files = entries
    .filter((e) => e.type === "blob" && e.path.startsWith(`${dir}/`) && /\.ya?ml$/i.test(e.path))
    .map((e) => e.path)
    .sort()
    .slice(0, opts?.maxFiles ?? 600);
  const warnings: string[] = truncated ? ["Repository listing was truncated by GitHub; some abilities may be missing."] : [];
  const abilities: CalderaAbility[] = [];
  await mapLimit(files, 8, async (path) => {
    try {
      const text = await fetcher.text(githubRawUrl(repo.owner, repo.repo, repo.branch, path), { maxBytes: 500_000 });
      abilities.push(...parseCalderaAbilityYaml(text, path));
    } catch (err) {
      warnings.push(`${path}: ${err instanceof Error ? err.message : String(err)}`);
    }
  });
  const result = buildCalderaResult(abilities, source, repo, opts);
  return { ...result, stats: { ...result.stats, files: files.length }, warnings: [...warnings, ...result.warnings] };
}

// ---------------------------------------------------------------------------
// Unit 42 IOC repository
// ---------------------------------------------------------------------------

/** Picks IOC files (newest-looking paths first) from a tree listing. */
export function selectUnit42IocFiles(entries: GithubTreeEntry[], max = 60): string[] {
  return entries
    .filter((e) => e.type === "blob" && /\.(txt|csv|md|json)$/i.test(e.path) && !/^readme\.md$/i.test(e.path) && !e.path.startsWith("."))
    .filter((e) => (e.size ?? 0) <= 2_000_000)
    .map((e) => e.path)
    .sort((a, b) => b.localeCompare(a))
    .slice(0, max);
}

export function buildUnit42IocDoc(path: string, text: string, source: ConnectorSource, repo: RepoConfig, opts?: { now?: string; lookup?: TechniqueLookup }) {
  const base = path.split("/").pop()!.replace(/\.[a-z]+$/i, "");
  const dateMatch = path.match(/(20\d{2})[-_]?(\d{2})[-_]?(\d{2})/);
  const title = base.replace(/[-_]+/g, " ").replace(/\s+/g, " ").trim();
  const iocs = harvestIocs(text.slice(0, 400_000), { sourceDomain: "github.com" });
  const techniques = techniqueIdsIn(text);
  const cves = uniq(iocs.filter((i) => i.kind === "cve").map((i) => i.value.toUpperCase()));
  const doc = buildStructuredReport({
    id: `u42_${slugify(path, 90)}`,
    source,
    docTypes: ["THREAT_REPORT"],
    title: `Unit 42 IOCs: ${title}`,
    url: githubBlobUrl(repo.owner, repo.repo, repo.branch, path),
    text: text.slice(0, 200_000),
    publishedAt: dateMatch ? `${dateMatch[1]}-${dateMatch[2]}-${dateMatch[3]}` : null,
    techniques,
    cves,
    contentType: "text/plain",
    tags: ["source:unit42", "ioc-list"],
    lookup: opts?.lookup,
    now: opts?.now,
    publisher: "Palo Alto Networks Unit 42",
    author: "Unit 42",
  });
  doc.iocs = iocs;
  return doc;
}

export async function syncUnit42Iocs(
  source: ConnectorSource,
  fetcher: ConnectorFetcher,
  opts?: { now?: string; lookup?: TechniqueLookup; maxFiles?: number },
): Promise<ConnectorResult> {
  const repo = repoConfigFrom(source.connectorConfig, {
    owner: "PaloAltoNetworks",
    repo: "Unit42-Threat-Intelligence-Article-Information",
    branch: "main",
  });
  const { entries } = await fetcher.githubTree(repo.owner, repo.repo, repo.branch);
  const files = selectUnit42IocFiles(entries, opts?.maxFiles ?? 60);
  const warnings: string[] = [];
  const docs: ReportRecord[] = [];
  await mapLimit(files, 6, async (path) => {
    try {
      const text = await fetcher.text(githubRawUrl(repo.owner, repo.repo, repo.branch, path), { maxBytes: 2_000_000 });
      const doc = buildUnit42IocDoc(path, text, source, repo, opts);
      if (doc.iocs.length > 0) docs.push(doc);
    } catch (err) {
      warnings.push(`${path}: ${err instanceof Error ? err.message : String(err)}`);
    }
  });
  return { docs, emulation: [], stats: { files: files.length, documents: docs.length, iocs: docs.reduce((n, d) => n + d.iocs.length, 0) }, warnings };
}
