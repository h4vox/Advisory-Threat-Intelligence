export function toIsoString(val: unknown): string | null {
  if (!val) return null;
  if (val instanceof Date) return val.toISOString();
  return String(val);
}

export function formatDateTime(val: unknown, fallback = "—"): string {
  if (!val) return fallback;
  if (val instanceof Date) return val.toISOString().replace("T", " ").slice(0, 16);
  const s = String(val);
  return s.replace("T", " ").slice(0, 16);
}
