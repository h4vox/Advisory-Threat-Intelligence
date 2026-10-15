/** Small list helpers shared by the Ingest and Sources pages. */

export function paginateList<T>(list: T[], page: number, pageSize: number | "all"): T[] {
  if (pageSize === "all") return list;
  const start = (page - 1) * pageSize;
  return list.slice(start, start + pageSize);
}

const MONTHS = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];

/** "3 Jan 2026" style (UTC, deterministic for SSR) short date; falls back to an em dash. */
export function shortDate(val?: string | null): string {
  if (!val) return "—";
  const d = new Date(val);
  if (Number.isNaN(d.getTime())) return "—";
  return `${d.getUTCDate()} ${MONTHS[d.getUTCMonth()]} ${d.getUTCFullYear()}`;
}

export function humanize(s?: string | null): string {
  if (!s) return "";
  const t = s.replace(/_/g, " ").toLowerCase();
  return t.charAt(0).toUpperCase() + t.slice(1);
}
