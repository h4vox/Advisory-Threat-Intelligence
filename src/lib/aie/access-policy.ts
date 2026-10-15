/** Pure access-list decision (no framework imports, so it is unit-testable). */

function parseList(raw: string | undefined): string[] {
  return (raw ?? "")
    .split(",")
    .map((s) => s.trim().toLowerCase().replace(/^@/, ""))
    .filter(Boolean);
}

/** Pure allowlist decision, exported for tests. */
export function isEmailAllowed(
  email: string | null | undefined,
  env: { emails?: string; domains?: string; production: boolean },
): boolean {
  const emails = parseList(env.emails);
  const domains = parseList(env.domains);
  if (emails.length === 0 && domains.length === 0) return !env.production;
  const normalized = (email ?? "").trim().toLowerCase();
  if (!normalized.includes("@")) return false;
  if (emails.includes(normalized)) return true;
  const domain = normalized.slice(normalized.lastIndexOf("@") + 1);
  return domains.includes(domain);
}
