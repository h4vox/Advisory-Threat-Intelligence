import { createFileRoute } from "@tanstack/react-router";

/**
 * Sign-in form target. A plain HTML form post, so signing in works before the page's scripts have
 * loaded (and without JavaScript). Sets the session cookie and returns to the page asked for;
 * on failure returns to the sign-in page with the reason.
 */

/** Same-origin path only: never an open redirect. */
function safePath(v: FormDataEntryValue | null): string {
  const r = typeof v === "string" ? v : "";
  return r.startsWith("/") && !r.startsWith("//") && !r.startsWith("/\\") && !r.startsWith("/login") && !r.startsWith("/api/") ? r : "/";
}

function back(to: string, headers: Record<string, string> = {}): Response {
  return new Response(null, { status: 303, headers: { Location: to, "Cache-Control": "no-store", ...headers } });
}

function failure(reason: string, redirect: string): Response {
  const q = new URLSearchParams({ error: reason });
  if (redirect !== "/") q.set("redirect", redirect);
  return back(`/login?${q}`);
}

export const Route = createFileRoute("/api/login")({
  server: {
    handlers: {
      POST: async ({ request }) => {
        // A form on another site must not sign this browser in (login CSRF).
        const site = request.headers.get("sec-fetch-site");
        if (site && site !== "same-origin" && site !== "none") return new Response("Forbidden: cross-site request blocked", { status: 403 });

        const form = await request.formData().catch(() => null);
        const redirect = safePath(form?.get("redirect") ?? null);
        const username = String(form?.get("username") ?? "").slice(0, 200);
        const password = String(form?.get("password") ?? "").slice(0, 1000);

        const { SignInLimiter, checkCredentials } = await import("@/lib/aie/auth/env-auth");
        const { authConfig, clientAddress, requestIsHttps, sessionCookieHeader } = await import("@/lib/aie/auth/session.server");
        const cfg = authConfig();
        if (!cfg) return failure("unconfigured", redirect);

        const g = globalThis as typeof globalThis & { __aieSignInLimiter__?: InstanceType<typeof SignInLimiter> };
        const limiter = (g.__aieSignInLimiter__ ??= new SignInLimiter());
        const key = clientAddress(request);
        if (limiter.retryAfter(key) > 0) return failure("limited", redirect);
        if (!username || !password || !checkCredentials({ username, password }, { username: cfg.username, password: cfg.password })) {
          limiter.fail(key);
          return failure("invalid", redirect);
        }
        limiter.succeed(key);
        return back(redirect, { "Set-Cookie": sessionCookieHeader(cfg, requestIsHttps(request)) });
      },
    },
  },
});
