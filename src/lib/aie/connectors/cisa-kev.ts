/**
 * CISA Known Exploited Vulnerabilities JSON feed → KEV index entries.
 *
 * KEV entries are kept as a lookup index (docType "kev" in Mongo), not as
 * library reports: ~1,500 one-paragraph rows would drown narrative reports.
 * Reports link to KEV through their CVE ids (see mongoGetKevEntries).
 */
import type { KevEntry } from "./common.ts";

type RawKev = {
  cveID?: string;
  vendorProject?: string;
  product?: string;
  vulnerabilityName?: string;
  dateAdded?: string;
  shortDescription?: string;
  requiredAction?: string;
  dueDate?: string;
  knownRansomwareCampaignUse?: string;
  notes?: string;
  cwes?: string[];
};

export type KevCatalog = { catalogVersion?: string; dateReleased?: string; count?: number; entries: KevEntry[] };

const CVE_RE = /^CVE-\d{4}-\d{4,}$/;

export function parseKevFeed(input: string | { vulnerabilities?: RawKev[]; catalogVersion?: string; dateReleased?: string; count?: number }): KevCatalog {
  const doc = typeof input === "string" ? JSON.parse(input) : input;
  if (!doc || !Array.isArray(doc.vulnerabilities)) throw new Error("KEV feed has no vulnerabilities array");
  const entries: KevEntry[] = [];
  const seen = new Set<string>();
  for (const v of doc.vulnerabilities as RawKev[]) {
    const cveId = (v.cveID ?? "").trim().toUpperCase();
    if (!CVE_RE.test(cveId) || seen.has(cveId)) continue;
    seen.add(cveId);
    entries.push({
      cveId,
      vendor: v.vendorProject?.trim() ?? "",
      product: v.product?.trim() ?? "",
      name: v.vulnerabilityName?.trim() ?? cveId,
      dateAdded: v.dateAdded ?? "",
      dueDate: v.dueDate || undefined,
      ransomwareUse: v.knownRansomwareCampaignUse || undefined,
      requiredAction: v.requiredAction || undefined,
      shortDescription: v.shortDescription || undefined,
      notes: v.notes || undefined,
      cwes: Array.isArray(v.cwes) && v.cwes.length ? v.cwes : undefined,
    });
  }
  return { catalogVersion: doc.catalogVersion, dateReleased: doc.dateReleased, count: doc.count, entries };
}

/** Structured payload for a KEV entry (StructuredIntel kind "kev"). */
export function kevStructured(e: KevEntry) {
  return {
    kind: "kev" as const,
    cveId: e.cveId,
    vendor: e.vendor,
    product: e.product,
    dateAdded: e.dateAdded,
    dueDate: e.dueDate,
    ransomwareUse: e.ransomwareUse,
    requiredAction: e.requiredAction,
  };
}
