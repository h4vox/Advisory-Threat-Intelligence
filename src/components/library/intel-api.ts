import * as aieServer from "@/lib/aie/server";
import type { DocType, EmulationOption, SourceTier } from "@/lib/aie/types";

/**
 * Feature-checked access to the intelligence-coverage server functions.
 * They may not be deployed yet; callers get `null` ("not synced yet") instead
 * of an error, so the UI can show an honest empty state.
 */

type ServerFn<I, O> = (opts: { data: I }) => Promise<O>;
type NoArgFn<O> = () => Promise<O>;

const server = aieServer as unknown as Record<string, unknown>;

export const hasEmulationOptionsApi = typeof server.getEmulationOptions === "function";
export const hasIntelCoverageApi = typeof server.getIntelCoverage === "function";

export type EmulationOptionsMap = Record<string, EmulationOption[]>;

/** {[techniqueId]: options}, or null when the endpoint is unavailable. */
export async function fetchEmulationOptions(techniqueIds: string[]): Promise<EmulationOptionsMap | null> {
  if (!hasEmulationOptionsApi || techniqueIds.length === 0) return hasEmulationOptionsApi ? {} : null;
  const fn = server.getEmulationOptions as ServerFn<{ techniqueIds: string[] }, unknown>;
  const res = await fn({ data: { techniqueIds } });
  if (!res || typeof res !== "object") return {};
  const out: EmulationOptionsMap = {};
  for (const [k, v] of Object.entries(res as Record<string, unknown>)) {
    if (Array.isArray(v)) out[k.toUpperCase()] = v as EmulationOption[];
  }
  return out;
}

export type IntelCoverage = {
  byDocType: Partial<Record<DocType, number>>;
  byTier: Partial<Record<SourceTier, number>>;
  total: number | null;
  atomicTechniques: number | null;
};

function numRecord(v: unknown): Record<string, number> {
  const out: Record<string, number> = {};
  if (v && typeof v === "object") {
    for (const [k, n] of Object.entries(v as Record<string, unknown>)) if (typeof n === "number") out[k] = n;
  }
  return out;
}

function firstNumber(o: Record<string, unknown>, keys: string[]): number | null {
  for (const k of keys) if (typeof o[k] === "number") return o[k] as number;
  return null;
}

/** Library-wide counts by document type / tier, or null when the endpoint is unavailable. */
export async function fetchIntelCoverage(): Promise<IntelCoverage | null> {
  if (!hasIntelCoverageApi) return null;
  const fn = server.getIntelCoverage as NoArgFn<unknown>;
  const res = (await fn()) as Record<string, unknown> | null;
  if (!res || typeof res !== "object") return null;
  const byDocType = numRecord(res.byDocType ?? res.docTypes ?? res.documentTypes);
  const byTierRaw = numRecord(res.byTier ?? res.tiers ?? res.sourceTiers);
  const byTier: Partial<Record<SourceTier, number>> = {};
  for (const [k, n] of Object.entries(byTierRaw)) {
    const t = Number(String(k).replace(/\D/g, ""));
    if (t >= 1 && t <= 4) byTier[t as SourceTier] = n;
  }
  return {
    byDocType: byDocType as Partial<Record<DocType, number>>,
    byTier,
    total: firstNumber(res, ["total", "totalReports", "reports"]),
    atomicTechniques: firstNumber(res, ["atomicTechniques", "atomicCoveredTechniques", "techniquesWithAtomics"]),
  };
}
