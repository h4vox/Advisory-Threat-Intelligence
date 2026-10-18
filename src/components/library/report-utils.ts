import { EyeOff, Undo2 } from "lucide-react";
import type { IntelAnalysis, ExtractedEntities, ReportListItem, ResourceKind } from "@/lib/aie/types";
import type { Tone } from "@/components/ui/primitives";
import type { ReportRowActions } from "./report-table";

/** Singular, sentence-case label for a report's resource kind (used as the "Type" column). */
export const KIND_LABEL: Record<ResourceKind, string> = {
  FULL_ATTACK_CHAIN: "Attack chain",
  CAMPAIGN_INTEL: "Campaign intel",
  PROCEDURE_DEEPDIVE: "Procedure deep-dive",
  MALWARE_ANALYSIS: "Malware analysis",
  DETECTION_GUIDANCE: "Detection guidance",
  VULNERABILITY_ADVISORY: "Vulnerability advisory",
  THREAT_ACTOR_DOSSIER: "Actor dossier",
};

export function kindLabel(kind?: ResourceKind | null, classification?: string | null): string {
  if (kind && KIND_LABEL[kind]) return KIND_LABEL[kind];
  if (classification) {
    const c = classification.replace(/_/g, " ").trim().toLowerCase();
    return c.charAt(0).toUpperCase() + c.slice(1);
  }
  return "Unclassified";
}

/** "Mar 11, 2024" (UTC), or null when the value is missing / unparseable. */
export function formatDate(val: unknown): string | null {
  if (!val) return null;
  const d = val instanceof Date ? val : new Date(String(val));
  if (Number.isNaN(d.getTime())) return null;
  return d.toLocaleDateString("en-US", { year: "numeric", month: "short", day: "numeric", timeZone: "UTC" });
}

export function dateValue(val: unknown): number {
  if (!val) return 0;
  const t = new Date(String(val)).getTime();
  return Number.isNaN(t) ? 0 : t;
}

/** Distinct ATT&CK technique count from analysis + extracted entities. */
export function techniqueCount(r: {
  analysis?: IntelAnalysis | null;
  extractedEntities?: ExtractedEntities;
}): number {
  const set = new Set<string>();
  const add = (v?: string | null) => {
    if (!v) return;
    const m = v.match(/T\d{4}(?:\.\d{3})?/i);
    set.add((m ? m[0] : v).toUpperCase());
  };
  r.analysis?.ttps?.forEach(add);
  r.analysis?.attackChain?.forEach((s) => s.techniques?.forEach(add));
  r.extractedEntities?.techniques?.forEach((t) => add(t.id || t.name));
  return set.size;
}

export type AiReview = { label: string; tone: Tone; rank: number; detail?: string };

/** One honest AI review state, derived only from stored fields. */
export function aiReview(r: { aiVerified?: boolean; aiQualityScore?: number; status?: string }): AiReview {
  const score = typeof r.aiQualityScore === "number" && r.aiQualityScore > 0 ? `${r.aiQualityScore}/100` : undefined;
  if (r.status === "rejected") return { label: "Hidden", tone: "neutral", rank: 0, detail: score };
  if (r.aiVerified) return { label: "AI verified", tone: "success", rank: 3, detail: score };
  if (score) return { label: "Not verified", tone: "warning", rank: 1, detail: score };
  return { label: "Not evaluated", tone: "neutral", rank: 2 };
}

export function qualityTone(score: number): Tone {
  if (score >= 0.8) return "success";
  if (score >= 0.6) return "info";
  if (score >= 0.4) return "warning";
  return "danger";
}

export function downloadHtml(html: string, title: string) {
  const blob = new Blob([html], { type: "text/html;charset=utf-8" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  const slug = (title || "threat_report")
    .toLowerCase()
    .replace(/[^a-z0-9_-]/g, "_")
    .slice(0, 50);
  a.download = `${slug}_intel_report.html`;
  a.click();
  URL.revokeObjectURL(url);
}

/** Open the document in a new window and trigger the print dialog. Returns false when pop-ups are blocked. */
export function printHtml(html: string): boolean {
  const w = window.open("", "_blank");
  if (!w) return false;
  w.document.write(html);
  w.document.close();
  w.focus();
  setTimeout(() => w.print(), 400);
  return true;
}

export type ReportSortKey = "title" | "publisher" | "published" | "type" | "quality" | "iocs" | "techniques" | "ai";
export type ReportSort = { key: ReportSortKey; desc: boolean } | null;

/** Comparator for the table's column sort (applied to the whole filtered list, before paging). */
export function compareReports(key: ReportSortKey): (a: ReportListItem, b: ReportListItem) => number {
  switch (key) {
    case "title":
      return (a, b) => a.title.localeCompare(b.title);
    case "publisher":
      return (a, b) => (a.publisher || a.sourceName || "").localeCompare(b.publisher || b.sourceName || "");
    case "published":
      return (a, b) => dateValue(a.publishedAt) - dateValue(b.publishedAt);
    case "type":
      return (a, b) => kindLabel(a.resourceKind, a.classification).localeCompare(kindLabel(b.resourceKind, b.classification));
    case "quality":
      return (a, b) => a.qualityScore - b.qualityScore;
    case "iocs":
      return (a, b) => (a.iocCount || 0) - (b.iocCount || 0);
    case "techniques":
      return (a, b) => techniqueCount(a) - techniqueCount(b);
    case "ai":
      return (a, b) => aiReview(a).rank - aiReview(b).rank || (a.aiQualityScore || 0) - (b.aiQualityScore || 0);
  }
}


/** "Hide from library" / "Restore to library" for a report's action menu. */
export function visibilityMenuItem(r: ReportListItem, actions: ReportRowActions) {
  return r.status === "rejected"
    ? { label: "Restore to library", icon: Undo2, onSelect: () => actions.restore?.(r), disabled: !actions.restore }
    : { label: "Hide from library", icon: EyeOff, onSelect: () => actions.hide?.(r), disabled: !actions.hide };
}
