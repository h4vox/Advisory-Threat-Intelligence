/**
 * Atomic Red Team atomics/Indexes/index.yaml → per-technique emulation options
 * and one ATOMIC_TEST document per technique (structured.kind "atomic_test").
 *
 * index.yaml shape: { <tactic>: { <Txxxx[.yyy]>: { technique: {...STIX attack-pattern}, atomic_tests: [...] } } }
 * A technique can appear under several tactics; tests are merged by GUID/name.
 */
import { parse as parseYaml } from "yaml";
import type { EmulationOption, ReportRecord } from "../types.ts";
import {
  buildStructuredReport,
  cleanAttackText,
  uniq,
  type ConnectorResult,
  type ConnectorSource,
  type EmulationIndexEntry,
  type TechniqueLookup,
} from "./common.ts";

export type AtomicTest = {
  name: string;
  guid?: string;
  platforms: string[];
  executor: string;
  elevationRequired?: boolean;
  description?: string;
};

export type AtomicTechnique = {
  techniqueId: string;
  techniqueName: string;
  tactics: string[];
  tests: AtomicTest[];
};

type RawAtomicTest = {
  name?: unknown;
  auto_generated_guid?: unknown;
  description?: unknown;
  supported_platforms?: unknown;
  executor?: { name?: unknown; elevation_required?: unknown } | null;
};

type RawTechniqueEntry = {
  technique?: { name?: unknown; external_references?: Array<{ source_name?: string; external_id?: string }> } | null;
  atomic_tests?: RawAtomicTest[] | null;
};

const str = (v: unknown): string => (typeof v === "string" ? v : v == null ? "" : String(v));

/** Parses the YAML index text (or an already-parsed object) into techniques with ≥1 atomic test. */
export function parseAtomicIndex(input: string | Record<string, unknown>): AtomicTechnique[] {
  const doc = (typeof input === "string" ? parseYaml(input, { maxAliasCount: -1 }) : input) as Record<string, unknown> | null;
  if (!doc || typeof doc !== "object") throw new Error("Atomic index is empty or not a mapping");
  const byId = new Map<string, AtomicTechnique>();
  for (const [tactic, techniques] of Object.entries(doc)) {
    if (!techniques || typeof techniques !== "object") continue;
    for (const [techniqueId, rawEntry] of Object.entries(techniques as Record<string, RawTechniqueEntry>)) {
      if (!/^T\d{4}(\.\d{3})?$/.test(techniqueId)) continue;
      const tests = Array.isArray(rawEntry?.atomic_tests) ? rawEntry.atomic_tests : [];
      if (tests.length === 0) continue;
      const existing = byId.get(techniqueId) ?? {
        techniqueId,
        techniqueName: str(rawEntry?.technique?.name) || techniqueId,
        tactics: [],
        tests: [],
      };
      if (!existing.tactics.includes(tactic)) existing.tactics.push(tactic);
      const seen = new Set(existing.tests.map((t) => t.guid || t.name));
      for (const t of tests) {
        const name = str(t?.name).trim();
        if (!name) continue;
        const guid = str(t.auto_generated_guid) || undefined;
        const key = guid || name;
        if (seen.has(key)) continue;
        seen.add(key);
        const platforms = Array.isArray(t.supported_platforms) ? t.supported_platforms.map(str).filter(Boolean) : [];
        const elevation = t.executor?.elevation_required;
        existing.tests.push({
          name,
          guid,
          platforms,
          executor: str(t.executor?.name) || "manual",
          elevationRequired: typeof elevation === "boolean" ? elevation : undefined,
          description: cleanAttackText(str(t.description)).slice(0, 400) || undefined,
        });
      }
      byId.set(techniqueId, existing);
    }
  }
  return Array.from(byId.values()).sort((a, b) => a.techniqueId.localeCompare(b.techniqueId, "en", { numeric: true }));
}

const ART_BASE = "https://github.com/redcanaryco/atomic-red-team/blob/master/atomics";

export function atomicTechniqueUrl(techniqueId: string): string {
  return `${ART_BASE}/${techniqueId}/${techniqueId}.md`;
}

/** EmulationOption[] for one technique's atomic tests. */
export function atomicEmulationOptions(t: AtomicTechnique): EmulationOption[] {
  return t.tests.map((test, i) => ({
    techniqueId: t.techniqueId,
    kind: "atomic_test" as const,
    name: test.name,
    ref: test.guid ? `${t.techniqueId}#${test.guid}` : `${t.techniqueId}-${i + 1}`,
    platforms: test.platforms,
    executor: test.executor,
    sourceUrl: atomicTechniqueUrl(t.techniqueId),
    elevationRequired: test.elevationRequired,
  }));
}

/** Builds ATOMIC_TEST documents and the atomic emulation index. */
export function buildAtomicResult(
  techniques: AtomicTechnique[],
  source: ConnectorSource,
  opts?: { now?: string; lookup?: TechniqueLookup },
): ConnectorResult {
  const docs: ReportRecord[] = [];
  const emulation: EmulationIndexEntry[] = [];
  let testCount = 0;
  for (const t of techniques) {
    testCount += t.tests.length;
    const platforms = uniq(t.tests.flatMap((x) => x.platforms)).sort();
    const executors = uniq(t.tests.map((x) => x.executor)).sort();
    const name = opts?.lookup?.(t.techniqueId)?.name ?? t.techniqueName;
    const text = [
      `Atomic Red Team tests for ${t.techniqueId} ${name}.`,
      `${t.tests.length} test${t.tests.length === 1 ? "" : "s"} · platforms: ${platforms.join(", ") || "n/a"} · executors: ${executors.join(", ")}.`,
      "",
      ...t.tests.map(
        (x, i) =>
          `${i + 1}. ${x.name} [${x.platforms.join(", ")}; ${x.executor}${x.elevationRequired ? "; elevation required" : ""}]${x.description ? `\n   ${x.description}` : ""}`,
      ),
    ].join("\n");
    docs.push(
      buildStructuredReport({
        id: `art_${t.techniqueId}`,
        source,
        docTypes: ["ATOMIC_TEST"],
        title: `Atomic tests: ${t.techniqueId} ${name}`,
        url: atomicTechniqueUrl(t.techniqueId),
        text,
        techniques: [t.techniqueId],
        structured: { kind: "atomic_test", techniqueId: t.techniqueId, tests: t.tests },
        emulation: t.tests.map((x) => `Atomic: ${x.name}`),
        contentType: "application/yaml",
        tags: [`technique:${t.techniqueId}`, "emulation:atomic-red-team"],
        lookup: opts?.lookup,
        now: opts?.now,
        publisher: "Red Canary",
        author: "Atomic Red Team contributors",
      }),
    );
    emulation.push({ techniqueId: t.techniqueId, kind: "atomic_test", sourceId: source.id, options: atomicEmulationOptions(t) });
  }
  return {
    docs,
    emulation,
    stats: { techniques: techniques.length, tests: testCount },
    warnings: [],
  };
}
