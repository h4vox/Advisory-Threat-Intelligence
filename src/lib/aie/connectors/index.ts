/**
 * Structured connector dispatch: registry source → ConnectorResult.
 * The parser is chosen by `connectorConfig.parser`; network access goes
 * through the injected fetcher so the whole path is testable offline.
 */
import { parseAttackStixBundle, type StixBundle } from "./attack-stix.ts";
import { buildAtomicResult, parseAtomicIndex } from "./atomic-red-team.ts";
import { parseKevFeed } from "./cisa-kev.ts";
import { githubRawUrl, type ConnectorFetcher } from "./fetch.ts";
import { repoConfigFrom, syncAttackFlowCorpus, syncCalderaStockpile, syncCtidLibrary, syncUnit42Iocs } from "./github-repo.ts";
import type { ConnectorResult, ConnectorSource, TechniqueLookup } from "./common.ts";

export type { ConnectorResult, ConnectorSource, EmulationIndexEntry, KevEntry, AttackTechniqueIndexEntry, TechniqueLookup } from "./common.ts";
export { buildAttackTechniqueIndex, techniqueLookupFrom } from "./attack-stix.ts";

export const STRUCTURED_PARSERS = [
  "attack_stix",
  "cisa_kev",
  "atomic_red_team",
  "ctid_emulation",
  "attack_flow",
  "caldera_stockpile",
  "unit42_iocs",
] as const;
export type StructuredParser = (typeof STRUCTURED_PARSERS)[number];

export function parserOf(source: ConnectorSource): StructuredParser | null {
  const p = source.connectorConfig?.parser;
  return (STRUCTURED_PARSERS as readonly string[]).includes(p ?? "") ? (p as StructuredParser) : null;
}

const MB = 1_000_000;

function capBytes(source: ConnectorSource, fallbackMB: number, hardMaxMB = 80): number {
  const n = Number(source.connectorConfig?.maxMB);
  const mb = Number.isFinite(n) && n > 0 ? n : fallbackMB;
  return Math.min(mb, hardMaxMB) * MB;
}

export async function runStructuredConnector(
  source: ConnectorSource,
  deps: { fetcher: ConnectorFetcher; lookup?: TechniqueLookup; now?: string },
): Promise<ConnectorResult> {
  const parser = parserOf(source);
  const opts = { now: deps.now, lookup: deps.lookup };
  switch (parser) {
    case "attack_stix": {
      const url = source.connectorConfig?.url;
      if (!url) throw new Error("ATT&CK connector has no bundle URL");
      const body = await deps.fetcher.text(url, { maxBytes: capBytes(source, 80), timeoutMs: 180_000, accept: "application/json" });
      let bundle: StixBundle;
      try {
        bundle = JSON.parse(body) as StixBundle;
      } catch {
        throw new Error("ATT&CK bundle is not valid JSON");
      }
      return parseAttackStixBundle(bundle, source, opts);
    }
    case "cisa_kev": {
      const url = source.connectorConfig?.url;
      if (!url) throw new Error("KEV connector has no feed URL");
      const warnings: string[] = [];
      const fetchKev = (u: string) => deps.fetcher.text(u, { maxBytes: capBytes(source, 20), timeoutMs: 60_000, accept: "application/json" });
      let body: string;
      try {
        body = await fetchKev(url);
      } catch (err) {
        // CISA mirrors the catalogue in its own GitHub repository (cisagov/kev-data).
        const mirror = source.connectorConfig?.mirrorUrl;
        if (!mirror) throw err;
        warnings.push(`Primary feed unavailable (${err instanceof Error ? err.message : String(err)}); used CISA's GitHub mirror.`);
        body = await fetchKev(mirror);
      }
      const catalog = parseKevFeed(body);
      return {
        docs: [],
        emulation: [],
        kev: catalog.entries,
        stats: {
          entries: catalog.entries.length,
          ransomwareLinked: catalog.entries.filter((e) => /^known$/i.test(e.ransomwareUse ?? "")).length,
        },
        warnings,
      };
    }
    case "atomic_red_team": {
      const repo = repoConfigFrom(source.connectorConfig, {
        owner: "redcanaryco",
        repo: "atomic-red-team",
        branch: "master",
        path: "atomics/Indexes/index.yaml",
      });
      const body = await deps.fetcher.text(githubRawUrl(repo.owner, repo.repo, repo.branch, repo.path || "atomics/Indexes/index.yaml"), {
        maxBytes: capBytes(source, 20),
        timeoutMs: 90_000,
        accept: "application/yaml, text/plain",
      });
      return buildAtomicResult(parseAtomicIndex(body), source, opts);
    }
    case "ctid_emulation":
      return syncCtidLibrary(source, deps.fetcher, opts);
    case "attack_flow":
      return syncAttackFlowCorpus(source, deps.fetcher, opts);
    case "caldera_stockpile":
      return syncCalderaStockpile(source, deps.fetcher, opts);
    case "unit42_iocs":
      return syncUnit42Iocs(source, deps.fetcher, opts);
    default:
      throw new Error(`Source ${source.name} has no structured connector`);
  }
}
