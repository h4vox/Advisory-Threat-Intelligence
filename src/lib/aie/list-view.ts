/**
 * The Library list sent to the browser, without what list screens never show: the quoted passages
 * and text offsets behind each fact (`Evidence`), the analysis' excluded statements and section
 * index, and the raw text of each indicator. Labels, names, values, tactics, order and counts stay,
 * so cards, facets and the matrix work unchanged. The report page loads the full report.
 *
 * Server code (purple paths, actor profiles) keeps reading the full list. Pure; unit-tested.
 */

type Json = unknown;

function isEvidenceList(v: Json): boolean {
  return Array.isArray(v) && v.every((e) => e && typeof e === "object" && typeof (e as { quote?: unknown }).quote === "string");
}

/** Copies a value, emptying Evidence arrays (`evidence: [{ quote, start, end }]`). */
function stripEvidence(v: Json): Json {
  if (Array.isArray(v)) return v.map(stripEvidence);
  if (v && typeof v === "object") {
    const out: Record<string, Json> = {};
    for (const [k, x] of Object.entries(v as Record<string, Json>)) {
      out[k] = k === "evidence" && isEvidenceList(x) ? [] : stripEvidence(x);
    }
    return out;
  }
  return v;
}

export function slimForList<T extends object>(item: T): T {
  const out: T = { ...item };
  const src = item as { analysis?: unknown; iocs?: unknown };
  const analysis = src.analysis as { evidence?: Record<string, Json> } | null | undefined;
  if (analysis && typeof analysis === "object") {
    const next = stripEvidence(analysis) as { evidence?: Record<string, Json> };
    if (next.evidence && typeof next.evidence === "object") next.evidence = { ...next.evidence, excluded: [], sections: [] };
    (out as { analysis?: unknown }).analysis = next;
  }
  const emulation = (item as { emulation?: { steps?: unknown } }).emulation;
  // The list shows the grade and its reasons; the quoted steps are for the report page.
  if (emulation && typeof emulation === "object") (out as { emulation?: unknown }).emulation = { ...emulation, steps: [] };
  if (Array.isArray(src.iocs)) {
    (out as { iocs?: unknown }).iocs = (src.iocs as Array<Record<string, Json>>).map((i) => {
      const { evidence: _evidence, original: _original, ...rest } = i ?? {};
      return rest;
    });
  }
  return out;
}
