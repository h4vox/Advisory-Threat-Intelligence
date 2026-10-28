import { createFileRoute } from "@tanstack/react-router";

/** Sign-out: clears the session cookie and returns to the sign-in page. */
export const Route = createFileRoute("/api/logout")({
  server: {
    handlers: {
      POST: async ({ request }) => {
        const site = request.headers.get("sec-fetch-site");
        if (site && site !== "same-origin" && site !== "none") return new Response("Forbidden: cross-site request blocked", { status: 403 });
        const { clearedCookieHeader, requestIsHttps } = await import("@/lib/aie/auth/session.server");
        return new Response(null, { status: 303, headers: { Location: "/login", "Set-Cookie": clearedCookieHeader(requestIsHttps(request)), "Cache-Control": "no-store" } });
      },
    },
  },
});
