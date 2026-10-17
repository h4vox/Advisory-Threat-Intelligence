import type { SearchResult } from "@/lib/aie/search/types";

/**
 * Why an ATT&CK card appears when the query named something else: it is only structurally linked
 * ("Used by APT29" on a tool card for "Cozy Bear"). Null when the card matched directly.
 */
export function linkNote(r: SearchResult): string | null {
  const uses = r.why.matchedEntities.filter((e) => e.rel === "uses");
  if (uses.length === 0 || r.why.matchedEntities.some((e) => e.rel === "self")) return null;
  const names = uses
    .slice(0, 2)
    .map((e) => e.name)
    .join(", ");
  const more = uses.length > 2 ? ` +${uses.length - 2}` : "";
  if (r.kind === "software") return `Used by ${names}${more}`;
  if (r.kind === "group") return `Uses ${names}${more}`;
  return `Linked to ${names}${more}`;
}

/** Direct matches (the entity the query named, or a technique card for a named technique) before linked ones. */
export function isDirectMatch(r: SearchResult): boolean {
  if (r.why.matchedEntities.some((e) => e.rel === "self")) return true;
  if (r.kind === "technique" && r.why.matchedTechniques.length > 0) return true;
  return r.kind === "vulnerability" && r.why.matchedIds.length > 0;
}
