import { createMiddleware } from "@tanstack/react-start";
import { authMiddleware } from "@/lib/auth/middleware";
import { isEmailAllowed } from "./access-policy";

/**
 * Analyst access gate for every AIE server function.
 *
 * Sign-in alone is not enough: any Google/X account can sign in, and this app
 * holds provider API keys and spends AI budget. On top of `authMiddleware`
 * (verified session → `context.userId`) the caller's email must match
 * `AIE_ALLOWED_EMAILS` or `AIE_ALLOWED_DOMAINS` (comma-separated).
 *
 * With neither variable set, access is allowed in development only; a
 * production server refuses everyone until the allowlist is configured
 * (fail closed).
 */

export class ForbiddenError extends Error {
  readonly status = 403;
  constructor(message = "Forbidden") {
    super(message);
    this.name = "ForbiddenError";
  }
}

export const analystMiddleware = createMiddleware({ type: "function" })
  .middleware([authMiddleware])
  .server(async ({ next, context }) => {
    const { getSessionUser, DEV_USER_ID } = await import("@/lib/auth/verify.server");
    const production = process.env.NODE_ENV === "production";
    let email: string | null = null;
    if (context.userId !== DEV_USER_ID) {
      const user = await getSessionUser((context as { bearerToken?: string }).bearerToken);
      email = user?.email ?? null;
    }
    const allowed =
      context.userId === DEV_USER_ID
        ? !production
        : isEmailAllowed(email, {
            emails: process.env.AIE_ALLOWED_EMAILS,
            domains: process.env.AIE_ALLOWED_DOMAINS,
            production,
          });
    if (!allowed) {
      throw new ForbiddenError(
        production && !process.env.AIE_ALLOWED_EMAILS && !process.env.AIE_ALLOWED_DOMAINS
          ? "Access is not configured: set AIE_ALLOWED_EMAILS or AIE_ALLOWED_DOMAINS."
          : "Your account is not on this workspace's access list.",
      );
    }
    return next({ context: { userId: context.userId, userEmail: email } });
  });
