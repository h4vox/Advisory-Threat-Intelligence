/**
 * Security headers on every response of the production server (security audit item 6).
 * Runs as Nitro global middleware (vite.config.ts `serverDir: "./server"`).
 *
 * Content-Security-Policy is not set yet: the page needs inline scripts (theme, hydration),
 * Google Fonts and the platform script, so a strict policy needs its own pass.
 */
interface SecurityHeadersEvent {
  req: { headers: Headers };
}

const HEADERS: Record<string, string> = {
  "X-Frame-Options": "DENY",
  "X-Content-Type-Options": "nosniff",
  "Referrer-Policy": "strict-origin-when-cross-origin",
  "Permissions-Policy": "camera=(), microphone=(), geolocation=(), payment=()",
  "Cross-Origin-Opener-Policy": "same-origin",
};

function withHeaders(res: Response, https: boolean): Response {
  const apply = (h: Headers) => {
    for (const [k, v] of Object.entries(HEADERS)) if (!h.has(k)) h.set(k, v);
    if (https && !h.has("Strict-Transport-Security")) h.set("Strict-Transport-Security", "max-age=63072000; includeSubDomains");
  };
  try {
    apply(res.headers);
    return res;
  } catch {
    // Immutable headers (e.g. a fetched response): copy into a new response.
    const copy = new Response(res.body, res);
    apply(copy.headers);
    return copy;
  }
}

export default async function securityHeaders(event: SecurityHeadersEvent, next: () => unknown | Promise<unknown>): Promise<unknown> {
  const result = await next();
  if (!(result instanceof Response)) return result;
  const https = event.req.headers.get("x-forwarded-proto")?.split(",")[0]?.trim().toLowerCase() === "https";
  return withHeaders(result, https);
}
